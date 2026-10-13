package node

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// Opt-in verification against the actual pinned tagged core. No network beyond
// localhost, no panel credentials, and all files live in a private test dir.
func TestLiveCoreClosedAuthenticatedTCPAccounting(t *testing.T) {
	binaryPath := os.Getenv("MBOARD_TEST_CORE_BINARY")
	if binaryPath == "" {
		t.Skip("set MBOARD_TEST_CORE_BINARY to pinned with_v2ray_api/with_utls core")
	}
	freePort := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port
	}
	socksPort, statsPort := freePort(), freePort()
	upstream, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	upload, download := []byte("real-upload-31"), []byte("real-download-47")
	serverDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		received := make([]byte, len(upload))
		_, err = io.ReadFull(conn, received)
		if err == nil && !reflect.DeepEqual(received, upload) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = conn.Write(download)
		}
		serverDone <- err
	}()
	defer upstream.Close()
	label := "opaque-live-auth"
	raw, e := json.Marshal(map[string]any{
		"inbounds":     []any{map[string]any{"type": "socks", "tag": "entry21", "listen": "127.0.0.1", "listen_port": socksPort, "users": []any{map[string]any{"username": label, "password": "private-test-password"}}}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "direct"}},
		"experimental": map[string]any{"v2ray_api": map[string]any{"listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort)), "stats": map[string]any{"enabled": true, "users": []string{label}}}},
	})
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "native.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	core := &ProcessCore{Binary: binaryPath, Timeout: 5 * time.Second, StartupGrace: time.Second, StopGrace: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = core.Check(ctx, path); e != nil {
		t.Fatal(e)
	}
	if e = core.Restart(ctx, path); e != nil {
		t.Fatal(e)
	}
	defer core.Stop()
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	exchange := func(request []byte, n int) []byte {
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, n)
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := exchange([]byte{5, 1, 2}, 2); !reflect.DeepEqual(response, []byte{5, 2}) {
		t.Fatalf("auth method %v", response)
	}
	password := "private-test-password"
	auth := append([]byte{1, byte(len(label))}, []byte(label)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if response := exchange(auth, 2); response[1] != 0 {
		t.Fatal("authentication failed")
	}
	port := upstream.Addr().(*net.TCPAddr).Port
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(port))
	response := exchange(request, 4)
	if response[1] != 0 {
		t.Fatalf("connect failed %v", response)
	}
	addressBytes := 0
	switch response[3] {
	case 1:
		addressBytes = 4
	case 4:
		addressBytes = 16
	case 3:
		b := make([]byte, 1)
		if _, e = io.ReadFull(conn, b); e != nil {
			t.Fatal(e)
		}
		addressBytes = int(b[0])
	default:
		t.Fatal("invalid socks reply address")
	}
	if _, e = io.CopyN(io.Discard, conn, int64(addressBytes+2)); e != nil {
		t.Fatal(e)
	}
	actual := exchange(upload, len(download))
	if !reflect.DeepEqual(actual, download) {
		t.Fatal("wrong upstream bytes")
	}
	conn.Close()
	if e = <-serverDone; e != nil {
		t.Fatal(e)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort))
	reader := GRPCStats{}
	spec := TelemetrySpec{Address: address, Labels: map[string]TrafficLabel{label: {Label: label, UserID: 7, NodeID: 21}}}
	collector := &Collector{Path: filepath.Join(dir, "collector.json"), Spool: Spool{Dir: filepath.Join(dir, "spool")}, Reader: reader, Timeout: time.Second}
	for i := 0; i < 3; i++ {
		if e = collector.Poll(ctx, spec, core.CounterGeneration()); e != nil {
			t.Fatal(e)
		}
	}
	bs := batches(t, collector.Spool)
	up, down := totals(bs)
	if len(bs) != 1 || up != int64(len(upload)) || down != int64(len(download)) {
		t.Fatalf("live short closed accounting batches=%+v upload=%d download=%d", bs, up, down)
	}
	acked := 0
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received Batch
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if !reflect.DeepEqual(received, bs[0]) {
			t.Error("live-core HTTP batch changed")
		}
		acked++
		reply(w, map[string]any{"accepted": true})
	}))
	defer panel.Close()
	client, err := NewClient(testConfig(t, panel.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err = collector.Spool.Flush(ctx, client); err != nil {
		t.Fatal(err)
	}
	if acked != 1 || len(batches(t, collector.Spool)) != 0 {
		t.Fatal("live-core HTTP ACK did not clear durable batch")
	}
	if err = collector.Poll(ctx, spec, core.CounterGeneration()); err != nil {
		t.Fatal(err)
	}
	if len(batches(t, collector.Spool)) != 0 {
		t.Fatal("live-core counters rebilled after HTTP ACK")
	}
	t.Logf("real pinned core short authenticated TCP billed exact %d upload/%d download bytes once across 4 polls and HTTP ACK", up, down)
}
