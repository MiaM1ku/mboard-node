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
	"sync"
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
	counterGeneration                string
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
func (p *ProcessCore) CounterGeneration() string { return p.counterGeneration }
func (p *ProcessCore) Restart(ctx context.Context, path string) error {
	id, err := NewBatchID()
	if err != nil {
		return err
	}
	if err := p.Stop(); err != nil {
		return err
	}
	p.counterGeneration = id
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(p.Binary, "run", "-c", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
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
	Revision      int64          `json:"revision"`
	SHA256        string         `json:"sha256"`
	TrafficLabels []TrafficLabel `json:"traffic_labels,omitempty"`
}
type Manager struct {
	Path, StatePath string
	Core            Core
	state           State
	revision        atomic.Int64
	applied         bool
	mu              sync.Mutex
	generation      string
	spec            TelemetrySpec
	activeSHA       string
	BeforeRestart   func(context.Context, TelemetrySpec, string) error
	BeforeRollback  func(context.Context, TelemetrySpec, string) error
	writeState      func(string, []byte) error
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
	m.spec, err = telemetrySpec(cfg, m.state.TrafficLabels)
	if err != nil {
		return m, err
	}
	m.applied = true
	m.revision.Store(m.state.Revision)
	return m, nil
}
func (m *Manager) Revision() int64 { return m.revision.Load() }
func (m *Manager) Ensure(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensure(ctx)
}
func (m *Manager) CoreReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied && m.Core.Running() && m.activeSHA == m.state.SHA256
}
func (m *Manager) Status(c *Collector) (int64, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ready := m.applied && m.Core.Running() && m.activeSHA == m.state.SHA256
	generation := c.readyGeneration.Load()
	return m.revision.Load(), ready, ready && c.Ready.Load() && generation != nil && *generation == m.generation
}
func (m *Manager) Collect(ctx context.Context, c *Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := c.Recover(); err != nil {
		c.Ready.Store(false)
		return err
	}
	if !m.applied || !m.Core.Running() {
		c.Ready.Store(false)
		return errors.New("managed core unavailable")
	}
	return c.Poll(ctx, m.spec, m.generation)
}
func (m *Manager) FinalCollect(ctx context.Context, c *Collector) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied || !m.Core.Running() {
		return errors.New("managed core unavailable")
	}
	return c.Final(ctx, m.spec, m.generation)
}
func (m *Manager) restart(ctx context.Context, path string) error {
	id, err := NewBatchID()
	if err != nil {
		return err
	}
	err = m.Core.Restart(ctx, path)
	if source, ok := m.Core.(interface{ CounterGeneration() string }); ok {
		m.generation = source.CounterGeneration()
	} else if err == nil || !m.Core.Running() {
		m.generation = id
	}
	return err
}
func (m *Manager) drain(ctx context.Context) error {
	if m.BeforeRestart != nil && m.Core.Running() && m.spec.Address != "" {
		return m.BeforeRestart(ctx, m.spec, m.generation)
	}
	return nil
}
func (m *Manager) ensure(ctx context.Context) error {
	if m.Core.Running() {
		return nil
	}
	if !m.applied {
		return nil
	}
	if err := m.Core.Check(ctx, m.Path); err != nil {
		return err
	}
	err := m.restart(ctx, m.Path)
	if err == nil {
		m.activeSHA = m.state.SHA256
	}
	return err
}
func (m *Manager) Apply(ctx context.Context, r RemoteConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	spec, err := telemetrySpec(raw, r.TrafficLabels)
	if err != nil {
		return err
	}
	hash := digest(raw)
	if m.applied && r.Revision < m.state.Revision {
		return errors.New("panel configuration revision moved backwards")
	}
	if m.applied && r.Revision == m.state.Revision {
		oldLabels, _ := json.Marshal(m.spec.Labels)
		newLabels, _ := json.Marshal(spec.Labels)
		if hash != m.state.SHA256 || !bytes.Equal(oldLabels, newLabels) {
			return errors.New("panel changed config or accounting mapping without a new revision")
		}
		return m.ensure(ctx)
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
	if err = m.drain(ctx); err != nil {
		return fmt.Errorf("cannot drain traffic before config restart: %w", err)
	}
	if err = os.Rename(temp, m.Path); err != nil {
		return err
	}
	oldSpec, oldActiveSHA := m.spec, m.activeSHA
	candidateStarted := false
	rollback := func(cause error) error {
		if candidateStarted && m.BeforeRollback != nil && m.Core.Running() && spec.Address != "" {
			drainCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			drainErr := m.BeforeRollback(drainCtx, spec, m.generation)
			cancel()
			if drainErr != nil {
				return fmt.Errorf("rollback deferred because candidate traffic cannot be checkpointed: %w", drainErr)
			}
		}
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
				restoreErr = m.restart(recovery, m.Path)
			} else {
				restoreErr = e
			}
		} else {
			restoreErr = m.Core.Stop()
		}
		if restoreErr != nil {
			return fmt.Errorf("apply failed; previous config restored but core recovery failed: %w", cause)
		}
		m.spec, m.activeSHA = oldSpec, oldActiveSHA
		return fmt.Errorf("apply failed; previous config restored: %w", cause)
	}
	if err = syncDir(filepath.Dir(m.Path)); err != nil {
		return rollback(err)
	}
	if err = m.restart(ctx, m.Path); err != nil {
		return rollback(err)
	}
	candidateStarted = true
	m.spec, m.activeSHA = spec, hash
	next := State{Revision: r.Revision, SHA256: hash, TrafficLabels: r.TrafficLabels}
	stateRaw, _ := json.Marshal(next)
	writeState := m.writeState
	if writeState == nil {
		writeState = atomicWrite
	}
	if err = writeState(m.StatePath, stateRaw); err != nil {
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
	m.spec = spec
	m.applied = true
	m.revision.Store(next.Revision)
	return nil
}
