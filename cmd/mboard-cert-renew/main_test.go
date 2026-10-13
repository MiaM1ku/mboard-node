package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"mboard.dev/node/internal/certificate"
)

func capture(t *testing.T, args []string) (int, string) {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = original; r.Close(); w.Close() }()
	code := run(args)
	w.Close()
	os.Stdout = original
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return code, string(b)
}

func TestInvalidArgumentsAreJSONAndDoNotEchoSecrets(t *testing.T) {
	code, out := capture(t, []string{"--unknown-PRIVATE_TEST_TOKEN"})
	var res certificate.Result
	if code != 2 || json.Unmarshal([]byte(out), &res) != nil || res.Status != "invalid_arguments" || strings.Contains(out, "PRIVATE_TEST_TOKEN") {
		t.Fatal(code, out)
	}
}
func TestMissingConfigArgumentIsJSON(t *testing.T) {
	code, out := capture(t, []string{"--config"})
	var res certificate.Result
	if code != 2 || json.Unmarshal([]byte(out), &res) != nil || res.Status != "invalid_arguments" {
		t.Fatal(code, out)
	}
}
func TestMissingConfigDoesNotLeakPath(t *testing.T) {
	code, out := capture(t, []string{"--check", "--config", "/does-not-exist/PRIVATE_TEST_TOKEN.json"})
	var res certificate.Result
	if code != 1 || json.Unmarshal([]byte(out), &res) != nil || strings.Contains(out, "PRIVATE_TEST_TOKEN") {
		t.Fatal(code, out)
	}
	if res.Status != "root_required" && res.Status != "invalid_config" {
		t.Fatal(code, out)
	}
}
