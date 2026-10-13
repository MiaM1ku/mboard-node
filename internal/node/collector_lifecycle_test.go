package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lifecycleCore struct {
	fakeCore
	failStop bool
	onStart  func(string)
}

func (c *lifecycleCore) Restart(ctx context.Context, path string) error {
	if c.failStop {
		return errors.New("old child could not be stopped")
	}
	if err := c.fakeCore.Restart(ctx, path); err != nil {
		return err
	}
	raw, _ := os.ReadFile(path)
	if c.onStart != nil {
		c.onStart(string(raw))
	}
	return nil
}
func nativeFor(name string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"inbounds": []any{}, "experimental": map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:19090", "stats": map[string]any{"enabled": true, "users": []string{name}}}}})
	return raw
}

func TestFailedStopDoesNotRebillCoreLifetime(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &lifecycleCore{}
	m, _ := NewManager(cfg, core)
	r := RemoteConfig{Revision: 1, Config: nativeFor("opaque"), TrafficLabels: []TrafficLabel{{Label: "opaque", UserID: 7, NodeID: 21}}}
	if err := m.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	reader := &mutableStats{counters: sample("opaque", 100, 200)}
	c := &Collector{Path: filepath.Join(cfg.DataDir, "collector.json"), Spool: Spool{Dir: filepath.Join(cfg.DataDir, "spool")}, Reader: reader}
	if err := m.Collect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	generation := m.generation
	core.failStop = true
	if err := m.restart(context.Background(), m.Path); err == nil {
		t.Fatal("stop failure ignored")
	}
	if m.generation != generation {
		t.Fatal("old counter domain assigned fresh generation")
	}
	if err := m.Collect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	up, down := totals(batches(t, c.Spool))
	if up != 100 || down != 200 {
		t.Fatalf("surviving old lifetime recounted %d/%d", up, down)
	}
}
func TestFinalCheckpointSurvivesFullSpoolAndPublicationFailure(t *testing.T) {
	c, s, spec := collectorFixture(t)
	s.counters = sample("opaque>>>source", 31, 47)
	c.SpoolLimit = 1
	if err := c.Poll(context.Background(), spec, "old"); err == nil {
		t.Fatal("soft cap didn't block ordinary sample")
	}
	// Simulate unpublishable spool. Final checkpoint must only need journal disk.
	blocked := filepath.Join(t.TempDir(), "spool-blocker")
	if err := os.WriteFile(blocked, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	realSpool := c.Spool
	c.Spool.Dir = blocked
	if err := c.Final(context.Background(), spec, "old"); err != nil {
		t.Fatal(err)
	}
	j, err := c.load()
	if err != nil || len(j.Pending) != 1 {
		t.Fatalf("final pending missing %v", err)
	}
	if j.Cursors["user>>>opaque>>>source>>>traffic>>>uplink"] != 31 {
		t.Fatal("final cursor not committed")
	}
	c.Spool = realSpool
	if err = c.Recover(); err != nil {
		t.Fatal(err)
	}
	up, down := totals(batches(t, c.Spool))
	if up != 31 || down != 47 {
		t.Fatal("final bytes lost")
	}
}
func TestTelemetrySpoolBudgetValidation(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	for _, value := range []int64{-1, 1, (4 << 20) - 1, (16 << 30) + 1} {
		cfg.TelemetrySpoolMaxBytes = value
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe spool budget accepted %d", value)
		}
	}
	for _, value := range []int64{0, 4 << 20, 32 << 20, 16 << 30} {
		cfg.TelemetrySpoolMaxBytes = value
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	cfg.DataDir = "/"
	if err := cfg.Validate(); err == nil {
		t.Fatal("data_dir root could be chmodded")
	}
}

func TestStateWriteRollbackCollectsCandidateIdentity(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	reader := &mutableStats{}
	core := &lifecycleCore{}
	core.onStart = func(raw string) {
		if strings.Contains(raw, "candidate-user") {
			reader.counters = sample("candidate-user", 12, 34)
		} else {
			reader.counters = sample("old-user", 0, 0)
		}
	}
	m, _ := NewManager(cfg, core)
	c := &Collector{Path: filepath.Join(cfg.DataDir, "collector.json"), Spool: Spool{Dir: filepath.Join(cfg.DataDir, "spool")}, Reader: reader}
	m.BeforeRestart = c.Poll
	m.BeforeRollback = c.Final
	old := RemoteConfig{Revision: 1, Config: nativeFor("old-user"), TrafficLabels: []TrafficLabel{{Label: "old-user", UserID: 7, NodeID: 21}}}
	if err := m.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	m.writeState = func(string, []byte) error { return errors.New("state metadata fsync failed") }
	candidate := RemoteConfig{Revision: 2, Config: nativeFor("candidate-user"), TrafficLabels: []TrafficLabel{{Label: "candidate-user", UserID: 8, NodeID: 22}}}
	if err := m.Apply(context.Background(), candidate); err == nil {
		t.Fatal("metadata failure ignored")
	}
	if m.Revision() != 1 || !core.Running() || m.spec.Labels["old-user"].UserID != 7 {
		t.Fatal("rollback did not restore runtime mapping")
	}
	if err := c.Recover(); err != nil {
		t.Fatal(err)
	}
	bs := batches(t, c.Spool)
	if len(bs) != 1 || len(bs[0].Records) != 1 {
		t.Fatalf("candidate not drained %+v", bs)
	}
	record := bs[0].Records[0]
	if record.UserID != 8 || record.NodeID != 22 || record.UploadBytes != 12 || record.DownloadBytes != 34 {
		t.Fatalf("candidate billed with wrong identity %+v", record)
	}
	if err := m.Collect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(batches(t, c.Spool)) != 1 {
		t.Fatal("candidate replayed after rollback")
	}
}
