package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeCore struct {
	checks, restarts, stops int
	running                 bool
	failRestart             bool
}

func (c *fakeCore) Check(ctx context.Context, path string) error {
	c.checks++
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.Contains(string(raw), "invalid") {
		return errors.New("invalid config")
	}
	return nil
}
func (c *fakeCore) Restart(ctx context.Context, path string) error {
	c.restarts++
	raw, _ := os.ReadFile(path)
	if c.failRestart && strings.Contains(string(raw), "startup-fail") {
		return errors.New("cannot bind port")
	}
	c.running = true
	return nil
}
func (c *fakeCore) Running() bool { return c.running }
func (c *fakeCore) Stop() error   { c.stops++; c.running = false; return nil }
func remote(rev int64, raw string) RemoteConfig {
	return RemoteConfig{Revision: rev, Config: json.RawMessage(raw)}
}

func TestRevisionValidationNoopAndEmptyInbounds(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{}
	m, err := NewManager(cfg, core)
	if err != nil {
		t.Fatal(err)
	}
	initial := remote(1, `{"inbounds":[{"type":"vless"}]}`)
	if err = m.Apply(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(cfg.ConfigPath)
	if err = m.Apply(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	if core.restarts != 1 || core.checks != 1 {
		t.Fatalf("noop touched core: %+v", core)
	}
	for _, bad := range []RemoteConfig{remote(2, `{"invalid":true}`), remote(0, `{}`), remote(1, `{"changed":true}`), remote(2, `null`), remote(2, `[]`)} {
		if err = m.Apply(context.Background(), bad); err == nil {
			t.Fatalf("accepted bad config: %+v", bad)
		}
		current, _ := os.ReadFile(cfg.ConfigPath)
		if !bytes.Equal(original, current) || m.Revision() != 1 || core.restarts != 1 {
			t.Fatal("bad config replaced previous")
		}
	}
	empty := remote(2, `{"inbounds":[],"outbounds":[{"type":"direct"}]}`)
	if err = m.Apply(context.Background(), empty); err != nil {
		t.Fatal(err)
	}
	if m.Revision() != 2 || core.restarts != 2 {
		t.Fatal("empty enabled inbound revision not applied")
	}
	loaded, err := NewManager(cfg, core)
	if err != nil || loaded.Revision() != 2 {
		t.Fatalf("persist state: %v", err)
	}
	core.running = false
	if err = loaded.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if core.restarts != 3 {
		t.Fatal("crashed core not recovered")
	}
}
func TestApplyStartupFailureRollsBack(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{failRestart: true}
	m, _ := NewManager(cfg, core)
	if err := m.Apply(context.Background(), remote(4, `{"inbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.ConfigPath)
	state, _ := os.ReadFile(m.StatePath)
	err := m.Apply(context.Background(), remote(5, `{"tag":"startup-fail"}`))
	if err == nil {
		t.Fatal("startup failure ignored")
	}
	after, _ := os.ReadFile(cfg.ConfigPath)
	afterState, _ := os.ReadFile(m.StatePath)
	if !bytes.Equal(before, after) || !bytes.Equal(state, afterState) || m.Revision() != 4 || !core.Running() || core.restarts != 3 {
		t.Fatalf("rollback failed core=%+v err=%v", core, err)
	}
}
func TestFirstApplyFailureLeavesNoConfig(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{failRestart: true}
	m, _ := NewManager(cfg, core)
	if err := m.Apply(context.Background(), remote(1, `{"tag":"startup-fail"}`)); err == nil {
		t.Fatal("failure ignored")
	}
	if _, err := os.Stat(cfg.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("failed first config retained")
	}
	if m.Revision() != 0 || core.Running() {
		t.Fatal("failed first apply marked active")
	}
}
func TestInterruptedApplyRefetch(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{}
	m, _ := NewManager(cfg, core)
	if err := m.Apply(context.Background(), remote(7, `{"inbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.ConfigPath, []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(cfg, core)
	if err == nil || m == nil {
		t.Fatal("state mismatch not detected")
	}
	if m.Revision() != 0 {
		t.Fatal("unverified disk revision reported")
	}
	if err = m.Apply(context.Background(), remote(7, `{"inbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
}
func TestProcessCoreCheckAndGracefulStop(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "test-core")
	script := "#!/bin/sh\ncase \"$1\" in\ncheck) test -f \"$3\" ;;\nrun) exec sleep 60 ;;\n*) exit 2 ;;\nesac\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	_ = os.WriteFile(path, []byte(`{}`), 0600)
	p := &ProcessCore{Binary: binary, Timeout: time.Second, StartupGrace: 20 * time.Millisecond, StopGrace: time.Second}
	if err := p.Check(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), path+"-missing"); err == nil {
		t.Fatal("check accepted missing config")
	}
	if err := p.Restart(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if !p.Running() {
		t.Fatal("core not running")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.Running() {
		t.Fatal("child not stopped")
	}
}
func TestHeartbeatSurvivesUnavailableCore(t *testing.T) {
	heartbeat := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			heartbeat <- struct{}{}
			reply(w, map[string]any{"server_time": "2026-01-01T00:00:00Z", "config_revision": 1})
		case "/api/node/v1/config":
			reply(w, map[string]any{"revision": 1, "config": map[string]any{"inbounds": []any{}}})
		case "/api/node/v1/traffic":
			t.Error("must not fabricate traffic")
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, io.Discard) }()
	defer cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-heartbeat:
		case <-time.After(4 * time.Second):
			t.Fatal("heartbeat stopped when core absent")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}
func TestLocalValidationAndTokenMask(t *testing.T) {
	c := testConfig(t, "https://panel.example")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.PanelURL = "https://user:secret@panel.example" }, func(c *Config) { c.PanelURL = "http://panel.example/api" }, func(c *Config) { c.Token = "bad\nsecret" }, func(c *Config) { c.Interval = "0s" }, func(c *Config) { c.ConfigPath = "relative.json" }, func(c *Config) { c.TLSCertPath = "/cert.pem" }} {
		bad := c
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid config accepted %+v", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	raw, _ := json.Marshal(c)
	_ = os.WriteFile(path, raw, 0600)
	t.Setenv("MBOARD_NODE_INTERVAL", "2s")
	loaded, err := LoadConfig(path)
	if err != nil || loaded.Interval != "2s" {
		t.Fatalf("env override %v %+v", err, loaded)
	}
	_ = os.WriteFile(path, []byte(`{"unknown":true}`), 0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown local key accepted")
	}
	var log bytes.Buffer
	_, _ = (MaskWriter{Out: &log, Token: c.Token}).Write([]byte("token=" + c.Token))
	if strings.Contains(log.String(), c.Token) || !strings.Contains(log.String(), "[REDACTED]") {
		t.Fatal("token leaked")
	}
}
func TestCounterValidation(t *testing.T) {
	for _, input := range []string{`{"records":[{"user_id":1,"node_id":2,"upload_bytes":12,"download_bytes":3}]}`, `{"batch_id":"external-id","records":[{"user_id":1,"node_id":2,"upload_bytes":0,"download_bytes":0}]}`} {
		b, err := ReadBatch(strings.NewReader(input))
		if err != nil || b.BatchID == "" {
			t.Fatalf("actual counters rejected: %v", err)
		}
	}
	for _, input := range []string{`{"records":[]}`, `{"records":[{"user_id":1,"node_id":2,"upload_bytes":-1}]}`, `{"records":[{"user_id":1,"node_id":2,"download_bytes":9007199254740992}]}`, `{"records":[{"user_id":1.5,"node_id":2}]}`, `{"records":[{"user_id":0,"node_id":2}]}`, `{"batch_id":"../escape","records":[{"user_id":1,"node_id":2}]}`, `{"records":[{"user_id":1,"node_id":2,"extra":1}]}`, `{} {}`} {
		if _, err := ReadBatch(strings.NewReader(input)); err == nil {
			t.Fatalf("bad counters accepted %s", input)
		}
	}
}
func TestBackoffAndAgentLock(t *testing.T) {
	if Backoff(1, time.Second, time.Minute) != time.Second || Backoff(3, time.Second, time.Minute) != 4*time.Second || Backoff(100, time.Second, time.Minute) != time.Minute {
		t.Fatal("bad exponential cap")
	}
	dir := t.TempDir()
	lock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if other, err := Lock(dir); err == nil {
		other.Close()
		t.Fatal("multiple agents accepted")
	}
}
