package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mboard.dev/node/internal/node"
)

func TestCLIValidationAndDurableIngest(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.json")
	cfg := node.Config{PanelURL: "http://127.0.0.1:8080", Token: "local-test-machine-token", ConfigPath: filepath.Join(dir, "server.json"), CoreBinary: "/usr/local/bin/sing-box", DataDir: filepath.Join(dir, "data"), Interval: "30s", RequestTimeout: "15s"}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate", "-config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	batchPath := filepath.Join(dir, "measured.json")
	raw = []byte(`{"batch_id":"cli-measured-1","records":[{"user_id":2,"node_id":5,"upload_bytes":341,"download_bytes":912}]}`)
	if err := os.WriteFile(batchPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"ingest", "-config", cfgPath, "-file", batchPath}); err != nil {
		t.Fatal(err)
	}
	queued := filepath.Join(cfg.DataDir, "spool", "cli-measured-1.json")
	f, err := os.Open(queued)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := node.ReadBatch(f)
	if err != nil || b.Records[0].DownloadBytes != 912 {
		t.Fatalf("bad queued counters %v %+v", err, b)
	}
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{}, {"unknown"}, {"validate", "-config", cfgPath, "unexpected"}, {"validate", "-unsupported"}, {"validate", "-config", filepath.Join(dir, "missing.json")}} {
		if err := run(args); err == nil {
			t.Fatalf("bad CLI accepted: %v", args)
		}
	}
}
