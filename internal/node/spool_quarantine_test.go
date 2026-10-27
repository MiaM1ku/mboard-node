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
	"sync"
	"testing"
)

// panel answers per batch_id: a rejecting status for refused IDs, 200 otherwise,
// and records every batch it acknowledged.
type panelFixture struct {
	mu       sync.Mutex
	status   map[string]int
	code     map[string]string
	accepted map[string]int
}

func newPanelFixture(t *testing.T) (*panelFixture, *httptest.Server) {
	t.Helper()
	p := &panelFixture{status: map[string]int{}, code: map[string]string{}, accepted: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			w.WriteHeader(400)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if status, found := p.status[b.BatchID]; found {
			w.WriteHeader(status)
			if code := p.code[b.BatchID]; code != "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": "private detail"}})
			}
			return
		}
		p.accepted[b.BatchID]++
		reply(w, map[string]any{"accepted": true})
	}))
	return p, srv
}

func (p *panelFixture) set(id string, status int, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status[id] = status
	p.code[id] = code
}

func (p *panelFixture) acked(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted[id]
}

func drain(t *testing.T, s Spool, c *Client, passes int) error {
	t.Helper()
	for i := 0; i < passes; i++ {
		if err := s.Flush(context.Background(), c); err != nil {
			return err
		}
	}
	return nil
}

func spoolFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	return names
}

// A batch the panel refuses with a stable 403 code used to block every batch
// behind it forever: the file was never removed and always came back as the
// head of the queue. It must instead be retired so delivery continues.
func TestSpoolRetiresPermanentlyRejectedBatch(t *testing.T) {
	panel, srv := newPanelFixture(t)
	defer srv.Close()
	panel.set("poison", 403, "TRAFFIC_GRANT")
	cfg := testConfig(t, srv.URL)
	c, _ := NewClient(cfg)
	var rejected []string
	s := Spool{Dir: filepath.Join(cfg.DataDir, "spool"), OnReject: func(id string, err error) { rejected = append(rejected, id+" "+err.Error()) }}
	if err := s.Enqueue(Batch{BatchID: "poison", Records: []Record{{UserID: 21, NodeID: 23, UploadBytes: 9}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(Batch{BatchID: "healthy", Records: []Record{{UserID: 6, NodeID: 23, UploadBytes: 11}}}); err != nil {
		t.Fatal(err)
	}
	if err := drain(t, s, c, 4); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if left := spoolFiles(t, s.Dir); len(left) != 0 {
		t.Fatalf("queue not drained: %v", left)
	}
	if got := spoolFiles(t, s.rejectedDir()); len(got) != 1 || got[0] != "poison.json" {
		t.Fatalf("rejected dir: %v", got)
	}
	if panel.acked("healthy") != 1 {
		t.Fatalf("healthy batch not delivered once: %d", panel.acked("healthy"))
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "TRAFFIC_GRANT") {
		t.Fatalf("reject callback: %v", rejected)
	}
	if strings.Contains(rejected[0], "private detail") {
		t.Fatalf("panel body leaked into log: %s", rejected[0])
	}
}

// Transport and server faults must keep the batch queued, and because the
// rejected-batch pass never consumes them the retry must stay visible.
func TestSpoolKeepsRetryableFailuresQueued(t *testing.T) {
	for _, status := range []int{404, 405, 401, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			panel, srv := newPanelFixture(t)
			defer srv.Close()
			panel.set("later", status, "SOMETHING")
			cfg := testConfig(t, srv.URL)
			c, _ := NewClient(cfg)
			s := Spool{Dir: filepath.Join(cfg.DataDir, "spool")}
			if err := s.Enqueue(Batch{BatchID: "later", Records: []Record{{UserID: 1, NodeID: 1, DownloadBytes: 3}}}); err != nil {
				t.Fatal(err)
			}
			if err := s.Flush(context.Background(), c); err == nil {
				t.Fatal("retryable failure treated as delivered")
			}
			if left := spoolFiles(t, s.Dir); len(left) != 1 || left[0] != "later.json" {
				t.Fatalf("retryable batch moved: %v", left)
			}
			if _, err := os.Stat(filepath.Join(s.rejectedDir(), "later.json")); !os.IsNotExist(err) {
				t.Fatalf("retryable batch quarantined: %v", err)
			}
		})
	}
}

// Corrupt spool contents can never be delivered, so they are retired instead of
// wedging the queue.
func TestSpoolQuarantinesCorruptBatch(t *testing.T) {
	_, srv := newPanelFixture(t)
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	c, _ := NewClient(cfg)
	dir := filepath.Join(cfg.DataDir, "spool")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.json"), []byte(`{"batch_id":"invalid","records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := Spool{Dir: dir}
	if err := drain(t, s, c, 4); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if left := spoolFiles(t, dir); len(left) != 0 {
		t.Fatalf("queue not drained: %v", left)
	}
	if got := spoolFiles(t, s.rejectedDir()); len(got) != 2 {
		t.Fatalf("rejected dir: %v", got)
	}
}

func TestAPIErrorKeepsOnlyStableCode(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"error":{"code":"TRAFFIC_GRANT","message":"x"}}`, "TRAFFIC_GRANT"},
		{`{"error":{"code":"traffic grant"}}`, ""},
		{`{"error":{"code":"<script>"}}`, ""},
		{`not json`, ""},
		{strings.Repeat("x", 8192), ""},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(tc.body))
		}))
		cfg := testConfig(t, srv.URL)
		c, _ := NewClient(cfg)
		_, err := c.Config(context.Background())
		srv.Close()
		var api *APIError
		if !errors.As(err, &api) {
			t.Fatalf("not an APIError: %v", err)
		}
		if api.Status != 403 || api.Code != tc.want {
			t.Fatalf("body %q -> %d %q, want code %q", tc.body, api.Status, api.Code, tc.want)
		}
		if len(err.Error()) > 96 {
			t.Fatalf("error leaks body: %v", err)
		}
	}
}
