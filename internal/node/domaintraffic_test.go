package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type domainRecorder struct {
	batches []DomainBatch
	err     error
}

func (r *domainRecorder) DomainTraffic(_ context.Context, b DomainBatch) error {
	if r.err != nil {
		return r.err
	}
	r.batches = append(r.batches, b)
	return nil
}

type fakeClash struct {
	conns []map[string]any
}

func (f *fakeClash) server(t *testing.T, secret string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret != "" && r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": f.conns})
	}))
}

func clashConn(id, tag, src, port, host, dst string, up, down int64) map[string]any {
	return map[string]any{"id": id, "upload": up, "download": down, "metadata": map[string]any{
		"type": "vless/" + tag, "sourceIP": src, "sourcePort": port, "host": host, "destinationIP": dst}}
}

func newTestDomainTraffic(t *testing.T, address, secret string) (*DomainTraffic, *ConnLog, *time.Time) {
	now := time.Unix(1762819234, 0)
	log := NewConnLog()
	log.Now = func() time.Time { return now }
	log.Labels = func() map[string]TrafficLabel { return nil }
	d := NewDomainTraffic()
	d.Now = func() time.Time { return now }
	d.Peers = log
	d.Spec = func() TelemetrySpec { return TelemetrySpec{ClashAddress: address, ClashSecret: secret} }
	n := 0
	d.NewID = func() (string, error) { n++; return "batch" + string(rune('a'+n)), nil }
	return d, log, &now
}

func feedUser(log *ConnLog, id, user, node, srcPort string) {
	log.OnLine([]byte("INFO[0001] [" + id + " 1ms] inbound/vless[node-" + node + "]: inbound connection from 203.0.113.9:" + srcPort))
	log.OnLine([]byte("INFO[0001] [" + id + " 1ms] inbound/vless[node-" + node + "]: [" + user + "] inbound connection to example.com:443"))
}

func TestDomainOf(t *testing.T) {
	cases := []struct{ host, ip, want string }{
		{"rr1---sn.googlevideo.com", "", "googlevideo.com"},
		{"WWW.Example.co.uk.", "", "example.co.uk"},
		{"", "93.184.216.34", "93.184.216.34"},
		{"2001:db8::1", "", "2001:db8::1"},
		{"localhost", "", "localhost"},
	}
	for _, c := range cases {
		got, ok := domainOf(c.host, c.ip)
		if !ok || got != c.want {
			t.Fatalf("domainOf(%q,%q)=%q,%v want %q", c.host, c.ip, got, ok, c.want)
		}
	}
	if _, ok := domainOf("", ""); ok {
		t.Fatal("empty destination must be rejected")
	}
}

func TestDomainTrafficDeltasAndAttribution(t *testing.T) {
	clash := &fakeClash{}
	srv := clash.server(t, "s3cret")
	defer srv.Close()
	d, log, _ := newTestDomainTraffic(t, strings.TrimPrefix(srv.URL, "http://"), "s3cret")
	feedUser(log, "1", "7", "21", "50001")
	feedUser(log, "2", "7", "21", "50002")
	clash.conns = []map[string]any{
		clashConn("a", "node-21", "203.0.113.9", "50001", "a.example.com", "", 100, 1000),
		clashConn("b", "node-21", "203.0.113.9", "50002", "b.example.com", "", 10, 20),
		clashConn("c", "node-21", "198.51.100.1", "40000", "stranger.test", "", 5, 5), // no identity
	}
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	clash.conns[0] = clashConn("a", "node-21", "203.0.113.9", "50001", "a.example.com", "", 150, 1500)
	clash.conns = clash.conns[:1] // b disappears
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	send := &domainRecorder{}
	if err := d.Flush(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if len(send.batches) != 1 || len(send.batches[0].Records) != 1 {
		t.Fatalf("unexpected batches: %+v", send.batches)
	}
	r := send.batches[0].Records[0]
	if r.UserID != 7 || r.NodeID != 21 || r.Domain != "example.com" || r.UploadBytes != 160 || r.DownloadBytes != 1520 || r.Hour%3600 != 0 {
		t.Fatalf("unexpected record: %+v", r)
	}
	if err := send.batches[0].Validate(); err != nil {
		t.Fatal(err)
	}
	if len(d.last) != 1 {
		t.Fatalf("vanished connection kept: %v", d.last)
	}
}

func TestDomainTrafficDisabledWithoutClash(t *testing.T) {
	d, _, _ := newTestDomainTraffic(t, "", "")
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	send := &domainRecorder{}
	if err := d.Flush(context.Background(), send); err != nil || len(send.batches) != 0 {
		t.Fatalf("flush=%v batches=%v", err, send.batches)
	}
}

func TestDomainTrafficProbeOn404(t *testing.T) {
	d, _, now := newTestDomainTraffic(t, "127.0.0.1:1", "")
	d.addLocked(domainKey{userID: 1, nodeID: 1, hour: 3600, domain: "x.com"}, 1, 1)
	send := &domainRecorder{err: &APIError{Status: 404}}
	if err := d.Flush(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if !d.probing || len(d.keys) != 0 || len(d.pending) != 0 {
		t.Fatal("expected probe pause with cleared state")
	}
	*now = now.Add(connProbeInterval + time.Second)
	d.addLocked(domainKey{userID: 1, nodeID: 1, hour: 3600, domain: "x.com"}, 1, 1)
	send.err = nil
	if err := d.Flush(context.Background(), send); err != nil || len(send.batches) != 1 {
		t.Fatalf("flush after probe window: %v %v", err, send.batches)
	}
}

func TestDomainTrafficBatchesChunk(t *testing.T) {
	d, _, _ := newTestDomainTraffic(t, "127.0.0.1:1", "")
	for i := 0; i < maxDomainBatchRecords+5; i++ {
		d.addLocked(domainKey{userID: 1, nodeID: 1, hour: 3600, domain: "d" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676)) + ".com"}, 1, 1)
	}
	send := &domainRecorder{}
	if err := d.Flush(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if len(send.batches) != 2 || len(send.batches[0].Records) != maxDomainBatchRecords {
		t.Fatalf("unexpected chunking: %d batches", len(send.batches))
	}
}

func TestClashEndpointOnlyLoopback(t *testing.T) {
	addr, secret := clashEndpoint([]byte(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:19091","secret":"k"}}}`))
	if addr != "127.0.0.1:19091" || secret != "k" {
		t.Fatalf("got %q %q", addr, secret)
	}
	if addr, _ = clashEndpoint([]byte(`{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}`)); addr != "" {
		t.Fatal("non-loopback controller must be ignored")
	}
}
