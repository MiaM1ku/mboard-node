package node

import (
	"context"
	"io"
	"log"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type MaskWriter struct {
	Out   io.Writer
	Token string
}

func (w MaskWriter) Write(p []byte) (int, error) {
	safe := strings.ReplaceAll(string(p), w.Token, "[REDACTED]")
	_, err := io.WriteString(w.Out, safe)
	return len(p), err
}
func Backoff(failures int, base, cap time.Duration) time.Duration {
	if base > cap {
		return cap
	}
	d := base
	for i := 1; i < failures; i++ {
		if d > cap/2 {
			return cap
		}
		d *= 2
	}
	if d > cap {
		return cap
	}
	return d
}
func loop(ctx context.Context, interval time.Duration, name string, logger *log.Logger, fn func(context.Context) error) {
	failures := 0
	for {
		if ctx.Err() != nil {
			return
		}
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := interval
		if err != nil {
			failures++
			delay = Backoff(failures, time.Second, 5*time.Minute)
			delay += time.Duration(rand.Int64N(int64(delay/4) + 1))
			logger.Printf("%s: %v; retry in %s", name, err, delay.Round(time.Second))
		} else {
			failures = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func Run(ctx context.Context, c Config, out io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	lock, err := Lock(c.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	client, err := NewClient(c)
	if err != nil {
		return err
	}
	logger := log.New(MaskWriter{Out: out, Token: c.Token}, "mboard-node ", log.LstdFlags|log.LUTC)
	timeout, _ := time.ParseDuration(c.RequestTimeout)
	core := &ProcessCore{Binary: c.CoreBinary, Timeout: timeout, StartupGrace: time.Second, StopGrace: 10 * time.Second}
	manager, err := NewManager(c, core)
	if manager == nil {
		return err
	}
	if err != nil {
		logger.Printf("local config state: %v", err)
	}
	interval, _ := time.ParseDuration(c.Interval)
	started := time.Now()
	var wg sync.WaitGroup
	start := func(name string, frequency time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() { defer wg.Done(); loop(ctx, frequency, name, logger, fn) }()
	}
	start("heartbeat", interval, func(ctx context.Context) error {
		_, err := client.Heartbeat(ctx, Heartbeat{Version: Version, UptimeSeconds: int64(time.Since(started).Seconds()), ConfigRevision: manager.Revision()})
		return err
	})
	start("config", interval, func(ctx context.Context) error {
		// Recover a crashed core from validated disk config even during panel outage.
		coreErr := manager.Ensure(ctx)
		remote, err := client.Config(ctx)
		if err != nil {
			if coreErr != nil {
				return coreErr
			}
			return err
		}
		before := manager.Revision()
		err = manager.Apply(ctx, remote)
		if err == nil && before != manager.Revision() {
			logger.Printf("applied config revision %d", manager.Revision())
		}
		return err
	})
	spool := Spool{Dir: filepath.Join(c.DataDir, "spool")}
	start("traffic", time.Second, func(ctx context.Context) error { return spool.Flush(ctx, client) })
	logger.Print("agent started; machine token [REDACTED]")
	<-ctx.Done()
	wg.Wait()
	return core.Stop()
}
