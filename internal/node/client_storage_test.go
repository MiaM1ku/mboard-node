package node

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T, origin string) Config {
	t.Helper()
	d := t.TempDir()
	return Config{PanelURL: origin, Token: "test-machine-secret-token", ConfigPath: filepath.Join(d, "config.json"), CoreBinary: "/missing/sing-box", DataDir: filepath.Join(d, "data"), Interval: "1s", RequestTimeout: "1s"}
}
func reply(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }

func TestProtocolAuthPathsSnakeCase(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-machine-secret-token" {
			t.Errorf("missing auth")
			w.WriteHeader(401)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["config_revision"] != float64(4) || body["uptime_seconds"] != float64(9) || body["version"] != "test" {
				t.Errorf("heartbeat body: %v", body)
			}
			reply(w, map[string]any{"server_time": "2026-01-01T00:00:00Z", "config_revision": 5})
		case "/api/node/v1/config":
			reply(w, map[string]any{"revision": 5, "config": map[string]any{"inbounds": []any{}}})
		case "/api/node/v1/traffic":
			var b Batch
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.BatchID != "batch-1" || b.Records[0].UploadBytes != 23 {
				t.Errorf("traffic body: %+v", b)
			}
			reply(w, map[string]any{"accepted": true})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, err := NewClient(testConfig(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.Heartbeat(context.Background(), Heartbeat{Version: "test", UptimeSeconds: 9, ConfigRevision: 4})
	if err != nil || h.ConfigRevision != 5 {
		t.Fatalf("heartbeat: %+v %v", h, err)
	}
	cfg, err := c.Config(context.Background())
	if err != nil || cfg.Revision != 5 {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	if err = c.Traffic(context.Background(), Batch{BatchID: "batch-1", Records: []Record{{UserID: 1, NodeID: 2, UploadBytes: 23}}}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("requests: %v", seen)
	}
}

func TestClientErrorsDoNotExposeSecrets(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("test-machine-secret-token"))
			}))
			defer srv.Close()
			c, _ := NewClient(testConfig(t, srv.URL))
			_, err := c.Config(context.Background())
			if err == nil || strings.Contains(err.Error(), c.token) {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}
func TestClientRejectsRedirectsAndBadEnvelopes(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":null}`, `{"data":{"revision":-1,"config":{}}}`, strings.Repeat("x", MaxBody+1)} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			c, _ := NewClient(testConfig(t, srv.URL))
			if _, err := c.Config(context.Background()); err == nil {
				t.Fatal("expected invalid response")
			}
		})
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect target must never receive token") }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	c, _ := NewClient(testConfig(t, srv.URL))
	if _, err := c.Config(context.Background()); err == nil {
		t.Fatal("redirect allowed")
	}
}
func TestClientTimeoutAndHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"revision": 1, "config": map[string]any{}})
	}))
	defer srv.Close()
	c, _ := NewClient(testConfig(t, srv.URL))
	if _, err := c.Config(context.Background()); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	cfg := testConfig(t, srv.URL)
	cfg.TLSCAPath = filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(cfg.TLSCAPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Config(context.Background()); err != nil {
		t.Fatal(err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	c, _ = NewClient(testConfig(t, slow.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Config(ctx); err == nil {
		t.Fatal("timeout ignored")
	}
}

func TestSpoolReplayAckAndConflictingIDs(t *testing.T) {
	var mu sync.Mutex
	ledger := map[string]bool{}
	calls := 0
	total := int64(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		defer mu.Unlock()
		calls++
		if !ledger[b.BatchID] {
			ledger[b.BatchID] = true
			total += b.Records[0].UploadBytes
		}
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		reply(w, map[string]any{"accepted": true})
	}))
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	c, _ := NewClient(cfg)
	s := Spool{Dir: filepath.Join(cfg.DataDir, "spool")}
	b := Batch{BatchID: "stable-id", Records: []Record{{UserID: 1, NodeID: 2, UploadBytes: 37, DownloadBytes: 11}}}
	if err := s.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	conflict := b
	conflict.Records = []Record{{UserID: 1, NodeID: 2, UploadBytes: 38}}
	if err := s.Enqueue(conflict); err == nil {
		t.Fatal("conflicting ID overwrote batch")
	}
	if err := s.Flush(context.Background(), c); err == nil {
		t.Fatal("lost ack must retry")
	}
	path := filepath.Join(s.Dir, "stable-id.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unacknowledged batch deleted")
	}
	// Reconstruct spool/client, as after process restart.
	s = Spool{Dir: s.Dir}
	c, _ = NewClient(cfg)
	if err := s.Flush(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("acked batch retained: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 || total != 37 {
		t.Fatalf("calls=%d counted=%d", calls, total)
	}
}
func TestSpoolUnacceptedAndMalformed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{"accepted": false}) }))
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	c, _ := NewClient(cfg)
	s := Spool{Dir: filepath.Join(cfg.DataDir, "spool")}
	b := Batch{BatchID: "keep", Records: []Record{{UserID: 1, NodeID: 1, DownloadBytes: 3}}}
	if err := s.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(context.Background(), c); err == nil {
		t.Fatal("accepted false ignored")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "keep.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "bad.json"), []byte(`{"batch_id":"../escape","records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(context.Background(), c); err == nil {
		t.Fatal("malformed spool accepted")
	}
}
