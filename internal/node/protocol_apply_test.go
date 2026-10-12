package node

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMockHTTPRevisionApplyErrorsPreservePrevious(t *testing.T) {
	sequence := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/config" || r.Header.Get("Authorization") != "Bearer test-machine-secret-token" {
			t.Error("incorrect config protocol request")
			w.WriteHeader(401)
			return
		}
		sequence++
		switch sequence {
		case 1, 2:
			reply(w, RemoteConfig{Revision: 1, Config: json.RawMessage(`{"inbounds":[]}`)})
		case 3:
			w.WriteHeader(500)
		case 4:
			reply(w, RemoteConfig{Revision: 2, Config: json.RawMessage(`{"invalid":true}`)})
		case 5:
			reply(w, RemoteConfig{Revision: 2, Config: json.RawMessage(`{"inbounds":[],"outbounds":[{"type":"direct"}]}`)})
		}
	}))
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	client, _ := NewClient(cfg)
	core := &fakeCore{}
	manager, _ := NewManager(cfg, core)
	fetchApply := func() error {
		remote, err := client.Config(context.Background())
		if err != nil {
			return err
		}
		return manager.Apply(context.Background(), remote)
	}
	if err := fetchApply(); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(cfg.ConfigPath)
	if err := fetchApply(); err != nil || core.restarts != 1 {
		t.Fatalf("revision noop: %v restarts=%d", err, core.restarts)
	}
	for i := 0; i < 2; i++ {
		if err := fetchApply(); err == nil {
			t.Fatal("error accepted")
		}
		now, _ := os.ReadFile(cfg.ConfigPath)
		if !bytes.Equal(original, now) || manager.Revision() != 1 || core.restarts != 1 {
			t.Fatal("error changed previous config")
		}
	}
	if err := fetchApply(); err != nil || manager.Revision() != 2 {
		t.Fatalf("valid empty revision failed: %v", err)
	}
}
