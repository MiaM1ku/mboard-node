package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigProtectsRelativeAndSymlinkAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	cfg := testConfig(t, "http://localhost")
	cfg.ConfigPath = path
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(relative); err == nil {
		t.Fatal("relative agent file overwritten")
	}
	alias := filepath.Join(t.TempDir(), "config-alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filepath.Join(alias, "agent.json")); err == nil {
		t.Fatal("symlink parent agent file overwritten")
	}
}
func TestAllManagedOutputsProtectLocalInputs(t *testing.T) {
	for _, name := range []string{"state.json", "agent.lock", "spool/agent.json"} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t, "http://localhost")
			path := filepath.Join(cfg.DataDir, name)
			_ = os.MkdirAll(filepath.Dir(path), 0700)
			raw, _ := json.Marshal(cfg)
			_ = os.WriteFile(path, raw, 0600)
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("managed output can overwrite agent file")
			}
		})
	}
	for _, field := range []string{"core", "ca", "cert", "key"} {
		for _, name := range []string{"state.json", "agent.lock", "spool/input"} {
			t.Run(field+"-"+name, func(t *testing.T) {
				cfg := testConfig(t, "http://localhost")
				path := filepath.Join(cfg.DataDir, name)
				switch field {
				case "core":
					cfg.CoreBinary = path
				case "ca":
					cfg.TLSCAPath = path
				case "cert":
					cfg.TLSCertPath = path
					cfg.TLSKeyPath = "/secure/key"
				case "key":
					cfg.TLSCertPath = "/secure/cert"
					cfg.TLSKeyPath = path
				}
				if err := cfg.Validate(); err == nil {
					t.Fatal("managed output overwrites protected input")
				}
			})
		}
	}
}
func TestDuplicateEnqueueConfirmsDurabilityAfterSyncFailure(t *testing.T) {
	confirmations := 0
	s := Spool{Dir: filepath.Join(t.TempDir(), "new-data", "spool"), syncDirectory: func(string) error {
		confirmations++
		if confirmations == 1 {
			return errors.New("injected fsync failure")
		}
		return nil
	}}
	b := Batch{BatchID: "retry-durable", Records: []Record{{UserID: 1, NodeID: 2, UploadBytes: 11, DownloadBytes: 12}}}
	if err := s.Enqueue(b); err == nil {
		t.Fatal("sync failure acknowledged")
	}
	if err := s.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	if confirmations != 2 {
		t.Fatalf("duplicate skipped sync: %d", confirmations)
	}
}
func TestDirectoryCreationSyncsAncestorsAndPropagatesFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data", "spool")
	var seen []string
	if err := mkdirAndSync(dir, func(path string) error { seen = append(seen, path); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 4 || seen[0] != dir || seen[1] != filepath.Dir(dir) || seen[len(seen)-1] != "/" {
		t.Fatalf("directory ancestry not synced: %v", seen)
	}
	if err := mkdirAndSync(dir, func(string) error { return errors.New("sync failed") }); err == nil {
		t.Fatal("directory fsync failure swallowed")
	}
}
func TestProtocolRequiresPresentNumericRevision(t *testing.T) {
	for _, body := range []string{`{"data":{"config":{"inbounds":[]}}}`, `{"data":{"revision":null,"config":{"inbounds":[]}}}`, `{"data":{"revision":"0","config":{}}}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			client, _ := NewClient(testConfig(t, srv.URL))
			if _, err := client.Config(context.Background()); err == nil {
				t.Fatal("invalid revision accepted")
			}
		})
	}
	for _, body := range []string{`{"data":{"server_time":"2026-01-01T00:00:00Z"}}`, `{"data":{"server_time":"2026-01-01T00:00:00Z","config_revision":null}}`, `{"data":{"server_time":"bad","config_revision":0}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		client, _ := NewClient(testConfig(t, srv.URL))
		if _, err := client.Heartbeat(context.Background(), Heartbeat{}); err == nil {
			t.Fatal("invalid heartbeat accepted")
		}
		srv.Close()
	}
	if _, err := ReadBatch(strings.NewReader(`{"records":[{"user_id":1,"node_id":2,"upload_bytes":1}]}`)); err == nil {
		t.Fatal("omitted counter silently converted to zero")
	}
}
func TestCanonicalRevisionIgnoresNestedKeyOrderAndKeepsIntegers(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{}
	m, _ := NewManager(cfg, core)
	if err := m.Apply(context.Background(), remote(1, `{"nested":{"b":2,"a":9007199254740993}}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), remote(1, `{"nested":{"a":9007199254740993,"b":2}}`)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(cfg.ConfigPath)
	if !strings.Contains(string(raw), "9007199254740993") || core.restarts != 1 {
		t.Fatal("lost precision or restarted noop")
	}
}
