package node

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type mutableStats struct {
	mu       sync.Mutex
	counters []Counter
	fail     bool
	requests int
}

func (s *mutableStats) Query(ctx context.Context, address string) ([]Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.fail {
		return nil, errors.New("unavailable")
	}
	return append([]Counter(nil), s.counters...), nil
}
func sample(name string, up, down int64) []Counter {
	return []Counter{{"user>>>" + name + ">>>traffic>>>uplink", up}, {"user>>>" + name + ">>>traffic>>>downlink", down}}
}
func collectorFixture(t *testing.T) (*Collector, *mutableStats, TelemetrySpec) {
	t.Helper()
	dir := t.TempDir()
	reader := &mutableStats{}
	return &Collector{Path: filepath.Join(dir, "collector.json"), Spool: Spool{Dir: filepath.Join(dir, "spool")}, Reader: reader, Timeout: time.Second}, reader, TelemetrySpec{Address: "127.0.0.1:19090", Labels: map[string]TrafficLabel{"opaque>>>source": {Label: "opaque>>>source", UserID: 7, NodeID: 21}, "second-profile": {Label: "second-profile", UserID: 7, NodeID: 21}}}
}
func batches(t *testing.T, s Spool) []Batch {
	t.Helper()
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var result []Batch
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(s.Dir, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		var b Batch
		if e = json.Unmarshal(raw, &b); e != nil {
			t.Fatal(e)
		}
		result = append(result, b)
	}
	return result
}
func totals(bs []Batch) (up, down int64) {
	for _, b := range bs {
		for _, r := range b.Records {
			up += r.UploadBytes
			down += r.DownloadBytes
		}
	}
	return
}

func TestCollectorClosedCumulativeNoZerosAndAggregation(t *testing.T) {
	c, s, spec := collectorFixture(t)
	ctx := context.Background()
	if err := c.Poll(ctx, spec, "generation1"); err != nil {
		t.Fatal(err)
	}
	if len(batches(t, c.Spool)) != 0 {
		t.Fatal("empty counters fabricated traffic")
	}
	s.counters = append(sample("opaque>>>source", 100, 240), sample("second-profile", 11, 13)...)
	s.counters = append(s.counters, Counter{"inbound>>>entry21>>>traffic>>>uplink", 9999}, Counter{"outbound>>>direct>>>traffic>>>downlink", 9999})
	if err := c.Poll(ctx, spec, "generation1"); err != nil {
		t.Fatal(err)
	}
	first := batches(t, c.Spool)
	if len(first) != 1 || !reflect.DeepEqual(first[0].Records, []Record{{UserID: 7, NodeID: 21, UploadBytes: 111, DownloadBytes: 253}}) {
		t.Fatalf("wrong aggregation %+v", first)
	}
	// The connection has already closed; cumulative counters remain queryable.
	for i := 0; i < 3; i++ {
		if err := c.Poll(ctx, spec, "generation1"); err != nil {
			t.Fatal(err)
		}
	}
	if len(batches(t, c.Spool)) != 1 {
		t.Fatal("same closed counter billed again")
	}
	s.counters = nil // incomplete/empty reply must not manufacture reset zero.
	if err := c.Poll(ctx, spec, "generation1"); err != nil {
		t.Fatal(err)
	}
	s.counters = sample("opaque>>>source", 120, 250)
	if err := c.Poll(ctx, spec, "generation1"); err != nil {
		t.Fatal(err)
	}
	up, down := totals(batches(t, c.Spool))
	if up != 131 || down != 263 {
		t.Fatalf("missing-row replay inflated totals %d/%d", up, down)
	}
}
func TestCollectorJournalRecoveryStableACKReplay(t *testing.T) {
	c, s, spec := collectorFixture(t)
	s.counters = sample("opaque>>>source", 31, 47)
	realSpool := c.Spool
	c.Spool.Dir = filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(c.Spool.Dir, []byte("not directory"), 0600); err != nil {
		t.Fatal(err)
	}
	// Fail after journal commit but before immutable batch publication, rather than
	// failing capacity check early.
	c.Spool = realSpool
	failed := false
	c.writeCheckpoint = func(path string, raw []byte) error {
		if err := atomicWrite(path, raw); err != nil {
			return err
		}
		if !failed {
			failed = true
			return errors.New("crash after rename/fsync")
		}
		return nil
	}
	if err := c.Poll(context.Background(), spec, "g1"); err == nil {
		t.Fatal("fault ignored")
	}
	journal, err := c.load()
	if err != nil || len(journal.Pending) != 1 {
		t.Fatalf("missing writeahead %+v %v", journal, err)
	}
	id := journal.Pending[0].BatchID
	// New collector object simulates agent restart, but same live core generation.
	recovered := &Collector{Path: c.Path, Spool: realSpool, Reader: s, Timeout: time.Second}
	if err = recovered.Poll(context.Background(), spec, "g1"); err != nil {
		t.Fatal(err)
	}
	bs := batches(t, realSpool)
	if len(bs) != 1 || bs[0].BatchID != id {
		t.Fatal("recovery changed immutable ID")
	}
	var attempts, charged int
	var acceptedID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
			t.Error(e)
		}
		attempts++
		if acceptedID == "" {
			acceptedID = b.BatchID
			charged++
		}
		if b.BatchID != acceptedID {
			t.Error("retry changed batch ID")
		}
		if attempts == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		reply(w, map[string]any{"accepted": true})
	}))
	defer srv.Close()
	client, e := NewClient(testConfig(t, srv.URL))
	if e != nil {
		t.Fatal(e)
	}
	if err = realSpool.Flush(context.Background(), client); err == nil {
		t.Fatal("uncertain HTTP ACK removed batch")
	}
	if err = realSpool.Flush(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if charged != 1 || attempts != 2 || len(batches(t, realSpool)) != 0 {
		t.Fatal("ACK replay counted twice")
	}
	if err = recovered.Poll(context.Background(), spec, "g1"); err != nil {
		t.Fatal(err)
	}
	if len(batches(t, realSpool)) != 0 {
		t.Fatal("ACKed cumulative bytes collected twice")
	}
}
func TestCollectorResetGenerationAndFailure(t *testing.T) {
	c, s, spec := collectorFixture(t)
	ctx := context.Background()
	s.counters = sample("opaque>>>source", 100, 200)
	if err := c.Poll(ctx, spec, "g1"); err != nil {
		t.Fatal(err)
	}
	s.fail = true
	if err := c.Poll(ctx, spec, "g1"); err == nil || c.Ready.Load() {
		t.Fatal("failure reported healthy")
	}
	s.fail = false
	s.counters = sample("opaque>>>source", 2, 3)
	if err := c.Poll(ctx, spec, "g1"); err != nil {
		t.Fatal(err)
	} // decreased counter, observed reset delta
	s.counters = sample("opaque>>>source", 500, 600)
	if err := c.Poll(ctx, spec, "g2"); err != nil {
		t.Fatal(err)
	} // new generation > old values still new traffic
	up, down := totals(batches(t, c.Spool))
	if up != 602 || down != 803 {
		t.Fatalf("reset totals %d/%d", up, down)
	}
	for _, bad := range [][]Counter{sample("unmapped", 1, 2), append(sample("opaque>>>source", 501, 601), Counter{"user>>>opaque>>>source>>>traffic>>>uplink", 501}), sample("opaque>>>source", -1, 1)} {
		s.counters = bad
		if err := c.Poll(ctx, spec, "g2"); err == nil {
			t.Fatal("invalid counters accepted")
		}
	}
	up, down = totals(batches(t, c.Spool))
	if up != 602 || down != 803 {
		t.Fatal("partial invalid sample emitted traffic")
	}
}
func TestCollectorCursorFailureCapacityAndCorruption(t *testing.T) {
	c, s, spec := collectorFixture(t)
	s.counters = sample("opaque>>>source", 9, 10)
	c.writeCheckpoint = func(string, []byte) error { return errors.New("disk full") }
	if err := c.Poll(context.Background(), spec, "g"); err == nil {
		t.Fatal("disk failure ignored")
	}
	if len(batches(t, c.Spool)) != 0 {
		t.Fatal("sent before checkpoint")
	}
	c.writeCheckpoint = nil
	c.SpoolLimit = 1
	if err := c.Poll(context.Background(), spec, "g"); err == nil || s.requests != 1 {
		t.Fatal("capacity still queried/dropped counters")
	}
	c.SpoolLimit = 0
	if err := c.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	if up, down := totals(batches(t, c.Spool)); up != 9 || down != 10 {
		t.Fatal("checkpoint retry lost bytes")
	}
	if err := os.WriteFile(c.Path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Poll(context.Background(), spec, "g"); err == nil {
		t.Fatal("corrupt journal silently replaced")
	}
}

func TestNativeTelemetryMappingAndManagerRecovery(t *testing.T) {
	native := `{"inbounds":[],"experimental":{"v2ray_api":{"listen":"127.0.0.1:19090","stats":{"enabled":true,"users":["xb:anything:legacy"]}}},"future_native_field":{"keep":true}}`
	mapping := []TrafficLabel{{Label: "xb:anything:legacy", UserID: 3, NodeID: 42}}
	spec, err := telemetrySpec([]byte(native), mapping)
	if err != nil || spec.Labels[mapping[0].Label].NodeID != 42 {
		t.Fatalf("opaque mapping %v", err)
	}
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{}
	m, _ := NewManager(cfg, core)
	remote := RemoteConfig{Revision: 9, Config: json.RawMessage(native), TrafficLabels: mapping}
	if err = m.Apply(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	changed := remote
	changed.TrafficLabels = []TrafficLabel{{Label: mapping[0].Label, UserID: 4, NodeID: 42}}
	if err = m.Apply(context.Background(), changed); err == nil {
		t.Fatal("same-revision mapping changed")
	}
	loaded, e := NewManager(cfg, core)
	if e != nil || !reflect.DeepEqual(m.spec, loaded.spec) {
		t.Fatalf("mapping not durable %v", e)
	}
	c := &Collector{Reader: &mutableStats{}, Path: filepath.Join(cfg.DataDir, "collector.json"), Spool: Spool{Dir: filepath.Join(cfg.DataDir, "spool")}}
	core.running = false
	if e = loaded.Ensure(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = loaded.Collect(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	_, ready, telemetry := loaded.Status(c)
	if !ready || !telemetry {
		t.Fatal("successful collection not ready")
	}
	remote.Revision = 10
	if e = loaded.Apply(context.Background(), remote); e != nil {
		t.Fatal(e)
	}
	_, ready, telemetry = loaded.Status(c)
	if !ready || telemetry {
		t.Fatal("old-generation stats reported ready after restart")
	}
	for _, input := range []struct {
		raw     string
		mapping []TrafficLabel
	}{
		{native, nil}, {native, append(mapping, mapping[0])}, {`{"experimental":{"v2ray_api":{"listen":"0.0.0.0:19090","stats":{"enabled":true,"users":[]}}}}`, nil},
		{`{}`, mapping}, {native, []TrafficLabel{{Label: "not-in-stats", UserID: 1, NodeID: 1}}},
	} {
		if _, e = telemetrySpec([]byte(input.raw), input.mapping); e == nil {
			t.Fatal("bad telemetry accepted")
		}
	}
	canonical := `{"experimental":{"v2ray_api":{"listen":"[::1]:19090","stats":{"enabled":true,"users":["mb:u:7:n:21:p:reality"]}}}}`
	if spec, e = telemetrySpec([]byte(canonical), nil); e != nil || spec.Labels["mb:u:7:n:21:p:reality"].UserID != 7 {
		t.Fatal("canonical labels failed")
	}
}

type mockStatsService interface{}

func TestGRPCStatsWireClosedCountersAndTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	var calls int
	var mu sync.Mutex
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "v2ray.core.app.stats.command.StatsService", HandlerType: (*mockStatsService)(nil), Methods: []grpc.MethodDesc{{MethodName: "QueryStats", Handler: func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		req := dynamicpb.NewMessage(statsMessages.ByName("QueryStatsRequest"))
		if e := decode(req); e != nil {
			return nil, e
		}
		if req.Get(req.Descriptor().Fields().ByName("reset")).Bool() {
			t.Error("destructive reset requested")
		}
		if req.Get(req.Descriptor().Fields().ByName("patterns")).List().Len() != 0 {
			t.Error("query may duplicate matched counters")
		}
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 4 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		resp := dynamicpb.NewMessage(statsMessages.ByName("QueryStatsResponse"))
		list := resp.Mutable(resp.Descriptor().Fields().ByName("stat")).List()
		for _, counter := range sample("closed-opaque", 6, 8) {
			stat := dynamicpb.NewMessage(statsMessages.ByName("Stat"))
			stat.Set(stat.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString(counter.Name))
			stat.Set(stat.Descriptor().Fields().ByName("value"), protoreflect.ValueOfInt64(counter.Value))
			list.Append(protoreflect.ValueOfMessage(stat))
		}
		return resp, nil
	}}}}, struct{}{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	reader := GRPCStats{}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, e := reader.Query(ctx, listener.Addr().String())
		cancel()
		if e != nil || !reflect.DeepEqual(got, sample("closed-opaque", 6, 8)) {
			t.Fatalf("wire mismatch %+v %v", got, e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e := reader.Query(ctx, listener.Addr().String()); e == nil {
		t.Fatal("grpc deadline not enforced")
	}
}
