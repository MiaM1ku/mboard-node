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
	spool := Spool{Dir: filepath.Join(c.DataDir, "spool")}
	// A batch the panel refuses outright is moved to spool/rejected so the rest
	// of the queue keeps flowing; surface it once instead of retrying forever.
	spool.OnReject = func(batchID string, err error) {
		logger.Printf("traffic: retired batch %s: %v", batchID, err)
	}
	telemetryInterval, _ := time.ParseDuration(c.TelemetryInterval)
	if telemetryInterval == 0 {
		telemetryInterval = 5 * time.Second
	}
	telemetryTimeout, _ := time.ParseDuration(c.TelemetryTimeout)
	if telemetryTimeout == 0 {
		telemetryTimeout = 5 * time.Second
	}
	collector := &Collector{Path: filepath.Join(c.DataDir, "collector.json"), Spool: spool, Reader: GRPCStats{}, Timeout: telemetryTimeout, SpoolLimit: c.TelemetrySpoolMaxBytes}
	manager.BeforeRestart = collector.Poll
	manager.BeforeRollback = collector.Final
	// The connection log is an observation layer on top of 0.2.2: it reads the
	// core's stderr, never touches the journal, spool or counters, and can be
	// switched off so the start path is byte-for-byte the previous release.
	var connLog *ConnLog
	if c.ConnectionLogEnabled() {
		connLog = NewConnLog()
		connLog.Labels = manager.Labels
		connLog.Log = logger.Printf
		core.OnLine = connLog.OnLine
	}
	interval, _ := time.ParseDuration(c.Interval)
	started := time.Now()
	var wg sync.WaitGroup
	start := func(name string, frequency time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() { defer wg.Done(); loop(ctx, frequency, name, logger, fn) }()
	}
	start("heartbeat", interval, func(ctx context.Context) error {
		revision, coreReady, telemetryReady := manager.Status(collector)
		_, err := client.Heartbeat(ctx, Heartbeat{Version: Version, UptimeSeconds: int64(time.Since(started).Seconds()), ConfigRevision: revision, CoreReady: &coreReady, TelemetryReady: &telemetryReady})
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
	start("collector", telemetryInterval, func(ctx context.Context) error { return manager.Collect(ctx, collector) })
	start("traffic", time.Second, func(ctx context.Context) error { return spool.Flush(ctx, client) })
	if connLog != nil {
		// One minute of aggregation keeps POSTs cheap while the panel still sees
		// hour buckets appear promptly.
		start("connections", time.Minute, func(ctx context.Context) error { return connLog.Flush(ctx, client) })
	}
	logger.Print("agent started; machine token [REDACTED]")
	<-ctx.Done()
	wg.Wait()
	finalCtx, cancel := context.WithTimeout(context.Background(), telemetryTimeout+5*time.Second)
	defer cancel()
	if err := manager.FinalCollect(finalCtx, collector); err != nil {
		logger.Printf("shutdown traffic drain: %v", err)
	}
	stopErr := core.Stop()
	if connLog != nil {
		// The core is stopped first, so nothing arrives from the pipe while the
		// final flush runs; a short deadline keeps shutdown inside the unit's
		// shutdown budget.
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := connLog.Flush(flushCtx, client); err != nil {
			logger.Printf("shutdown connection flush: %v", err)
		}
		flushCancel()
	}
	return stopErr
}
