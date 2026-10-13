package node

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// This tests two authenticated core users sharing a logical uid/node. All
// credentials and traffic are synthetic and stay on loopback.
func TestLiveCoreClosedTCPProfilePartitions(t *testing.T) {
	binaryPath := os.Getenv("MBOARD_TEST_CORE_BINARY")
	if binaryPath == "" {
		t.Skip("set MBOARD_TEST_CORE_BINARY to pinned with_v2ray_api/with_utls core")
	}
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port
	}
	socksPort, statsPort := freePort(), freePort()
	profiles := []string{"d931ed25-42a5-4669-b518-c30c14d0b471", "f4663c5b-5591-4d7a-bec3-f4149068fb58"}
	var names []string
	var users []any
	var mapping []TrafficLabel
	for _, profile := range profiles {
		name := "mb:u:7:n:21:p:" + profile
		names = append(names, name)
		users = append(users, map[string]any{"username": name, "password": "private-profile-test-password"})
		// The existing backend row has no profile_id. Trusted canonical metadata
		// must enable partitioning without a config/revision change.
		mapping = append(mapping, TrafficLabel{Label: name, UserID: 7, NodeID: 21})
	}
	raw, err := json.Marshal(map[string]any{
		"inbounds":     []any{map[string]any{"type": "socks", "tag": "entry21", "listen": "127.0.0.1", "listen_port": socksPort, "users": users}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "direct"}},
		"experimental": map[string]any{"v2ray_api": map[string]any{"listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort)), "stats": map[string]any{"enabled": true, "users": names, "inbounds": []string{"entry21"}, "outbounds": []string{"direct"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := telemetrySpec(raw, mapping)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "native.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	core := &ProcessCore{Binary: binaryPath, Timeout: 5 * time.Second, StartupGrace: time.Second, StopGrace: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = core.Check(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err = core.Restart(ctx, path); err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	var expected []Record
	for i, name := range names {
		upload := []byte("profile-upload-" + strconv.Itoa(i))
		download := []byte("profile-download-" + strconv.Itoa(i))
		liveProfileTCP(t, socksPort, name, upload, download)
		expected = append(expected, Record{UserID: 7, NodeID: 21, UploadBytes: int64(len(upload)), DownloadBytes: int64(len(download)), ProfileID: profiles[i]})
	}
	collector := &Collector{Path: filepath.Join(dir, "collector.json"), Spool: Spool{Dir: filepath.Join(dir, "spool")}, Reader: GRPCStats{}, Timeout: time.Second}
	for i := 0; i < 3; i++ {
		if err = collector.Poll(ctx, spec, core.CounterGeneration()); err != nil {
			t.Fatal(err)
		}
	}
	bs := batches(t, collector.Spool)
	if len(bs) != 1 || !reflect.DeepEqual(bs[0].Records, expected) {
		t.Fatalf("live profile partition/repeated polls: %+v want %+v", bs, expected)
	}
	up, down := totals(bs)
	if up != expected[0].UploadBytes+expected[1].UploadBytes || down != expected[0].DownloadBytes+expected[1].DownloadBytes {
		t.Fatalf("inbound/outbound totals billed twice: %d/%d", up, down)
	}
	t.Logf("two closed authenticated TCP users, same uid/node, exact independent profiles: %+v; totals %d/%d across 3 nonreset polls", bs[0].Records, up, down)
}

func liveProfileTCP(t *testing.T, socksPort int, name string, upload, download []byte) {
	t.Helper()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			done <- err
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
		done <- err
	}()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), time.Second)
	if err != nil {
		t.Fatal(err)
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
	password := "private-profile-test-password"
	auth := append([]byte{1, byte(len(name))}, []byte(name)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if response := exchange(auth, 2); response[1] != 0 {
		t.Fatal("authentication failed")
	}
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(upstream.Addr().(*net.TCPAddr).Port))
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
		if _, err := io.ReadFull(conn, b); err != nil {
			t.Fatal(err)
		}
		addressBytes = int(b[0])
	default:
		t.Fatal("invalid socks reply address")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressBytes+2)); err != nil {
		t.Fatal(err)
	}
	if actual := exchange(upload, len(download)); !reflect.DeepEqual(actual, download) {
		t.Fatal("wrong upstream bytes")
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
