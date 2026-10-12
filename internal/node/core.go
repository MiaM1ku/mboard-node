package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

type Core interface {
	Check(context.Context, string) error
	Restart(context.Context, string) error
	Running() bool
	Stop() error
}
type ProcessCore struct {
	Binary                           string
	Timeout, StartupGrace, StopGrace time.Duration
	cmd                              *exec.Cmd
	done                             chan struct{}
}

func (p *ProcessCore) Check(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Binary, "check", "-c", path)
	if err := cmd.Run(); err != nil {
		return errors.New("sing-box check failed (verify config, core version and TLS files)")
	}
	return nil
}
func (p *ProcessCore) Running() bool {
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *ProcessCore) Restart(ctx context.Context, path string) error {
	if err := p.Stop(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(p.Binary, "run", "-c", path)
	// No shell, no remote arguments and no unfiltered core output in agent logs.
	if err := cmd.Start(); err != nil {
		return errors.New("start sing-box failed")
	}
	p.cmd = cmd
	p.done = make(chan struct{})
	done := p.done
	go func() { _ = cmd.Wait(); close(done) }()
	timer := time.NewTimer(p.StartupGrace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		p.Stop()
		return ctx.Err()
	case <-done:
		return errors.New("sing-box exited during startup")
	case <-timer.C:
		return nil
	}
}
func (p *ProcessCore) Stop() error {
	if p.cmd == nil {
		return nil
	}
	if !p.Running() {
		p.cmd = nil
		return nil
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return errors.New("signal sing-box failed")
	}
	timer := time.NewTimer(p.StopGrace)
	defer timer.Stop()
	select {
	case <-p.done:
	case <-timer.C:
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return errors.New("kill sing-box failed")
		}
		<-p.done
	}
	p.cmd = nil
	return nil
}

type State struct {
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}
type Manager struct {
	Path, StatePath string
	Core            Core
	state           State
	revision        atomic.Int64
	applied         bool
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func NewManager(c Config, core Core) (*Manager, error) {
	m := &Manager{Path: c.ConfigPath, StatePath: filepath.Join(c.DataDir, "state.json"), Core: core}
	raw, err := os.ReadFile(m.StatePath)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(raw, &m.state); err != nil || m.state.Revision < 0 || m.state.Revision > MaxSafeInteger || len(m.state.SHA256) != 64 {
		return m, errors.New("invalid revision state; refetching panel config")
	}
	cfg, err := os.ReadFile(m.Path)
	if err != nil || digest(cfg) != m.state.SHA256 {
		return m, errors.New("revision state/config mismatch; refetching panel config")
	}
	m.applied = true
	m.revision.Store(m.state.Revision)
	return m, nil
}
func (m *Manager) Revision() int64 { return m.revision.Load() }
func (m *Manager) Ensure(ctx context.Context) error {
	if m.Core.Running() {
		return nil
	}
	if !m.applied {
		return nil
	}
	if err := m.Core.Check(ctx, m.Path); err != nil {
		return err
	}
	return m.Core.Restart(ctx, m.Path)
}
func (m *Manager) Apply(ctx context.Context, r RemoteConfig) error {
	if r.Revision < 0 || r.Revision > MaxSafeInteger {
		return errors.New("invalid config revision")
	}
	var obj map[string]any
	decoder := json.NewDecoder(bytes.NewReader(r.Config))
	decoder.UseNumber()
	if err := decoder.Decode(&obj); err != nil || obj == nil {
		return errors.New("config must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("config must contain exactly one JSON object")
	}
	raw, err := json.Marshal(obj)
	if err != nil || len(raw) > MaxBody {
		return errors.New("invalid or oversized config")
	}
	hash := digest(raw)
	if m.applied && r.Revision < m.state.Revision {
		return errors.New("panel configuration revision moved backwards")
	}
	if m.applied && r.Revision == m.state.Revision {
		if hash != m.state.SHA256 {
			return errors.New("panel changed config without a new revision")
		}
		return m.Ensure(ctx)
	}
	old, err := os.ReadFile(m.Path)
	oldExists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	temp, err := stageFile(m.Path, raw)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if err = m.Core.Check(ctx, temp); err != nil {
		return err
	}
	// Validation finishes before replacing the previous config or stopping core.
	if err = os.Rename(temp, m.Path); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var restoreErr error
		if oldExists {
			restoreErr = atomicWrite(m.Path, old)
		} else {
			restoreErr = os.Remove(m.Path)
			if os.IsNotExist(restoreErr) {
				restoreErr = nil
			}
			if restoreErr == nil {
				restoreErr = syncDir(filepath.Dir(m.Path))
			}
		}
		if restoreErr != nil {
			return fmt.Errorf("apply failed and rollback write failed: %w", cause)
		}
		recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if oldExists {
			if e := m.Core.Check(recovery, m.Path); e == nil {
				restoreErr = m.Core.Restart(recovery, m.Path)
			} else {
				restoreErr = e
			}
		} else {
			restoreErr = m.Core.Stop()
		}
		if restoreErr != nil {
			return fmt.Errorf("apply failed; previous config restored but core recovery failed: %w", cause)
		}
		return fmt.Errorf("apply failed; previous config restored: %w", cause)
	}
	if err = syncDir(filepath.Dir(m.Path)); err != nil {
		return rollback(err)
	}
	if err = m.Core.Restart(ctx, m.Path); err != nil {
		return rollback(err)
	}
	next := State{Revision: r.Revision, SHA256: hash}
	stateRaw, _ := json.Marshal(next)
	if err = atomicWrite(m.StatePath, stateRaw); err != nil {
		// If rename succeeded but dir fsync failed, restore old revision metadata too.
		var metadataErr error
		if m.applied {
			oldState, _ := json.Marshal(m.state)
			metadataErr = atomicWrite(m.StatePath, oldState)
		} else {
			metadataErr = os.Remove(m.StatePath)
			if os.IsNotExist(metadataErr) {
				metadataErr = nil
			}
		}
		recovered := rollback(err)
		if metadataErr != nil {
			return fmt.Errorf("revision metadata recovery failed; %w", recovered)
		}
		return recovered
	}
	m.state = next
	m.applied = true
	m.revision.Store(next.Revision)
	return nil
}
