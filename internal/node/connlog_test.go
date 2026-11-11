package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct{ at time.Time }

func (c *testClock) Now() time.Time          { return c.at }
func (c *testClock) advance(d time.Duration) { c.at = c.at.Add(d) }
func (c *testClock) set(t time.Time)         { c.at = t }

// connRecorder is the ConnSender test double: it records every batch and replays
// a scripted list of errors, so failure classification is verified without HTTP.
type connRecorder struct {
	batches []ConnBatch
	errors  []error
	calls   int
}

func (r *connRecorder) Connections(ctx context.Context, b ConnBatch) error {
	if err := b.Validate(); err != nil {
		return err
	}
	r.batches = append(r.batches, b)
	r.calls++
	if len(r.errors) > 0 {
		err := r.errors[0]
		r.errors = r.errors[1:]
		return err
	}
	return nil
}

func sourceLine(id int, source string) []byte {
	return []byte(fmt.Sprintf("INFO[0001] [%d 12ms] inbound/vless[mb:n:21]: inbound connection from %s", id, source))
}

func destLine(id int, user, target string) []byte {
	return []byte(fmt.Sprintf("INFO[0001] [%d 14ms] inbound/vless[mb:n:21]: [%s] inbound connection to %s", id, user, target))
}

func testLabels() map[string]TrafficLabel {
	return map[string]TrafficLabel{"mb:u:7:n:21:p:0": {Label: "mb:u:7:n:21:p:0", UserID: 7, NodeID: 21}}
}

func TestParseCoreLineAndConnEvent(t *testing.T) {
	colored := "\x1b[36mINFO\x1b[0m [\x1b[38;5;123m42\x1b[0m 1.20s] inbound/vless[mb:n:21]: "
	stamped := "+0800 2026-11-11 16:00:00 "
	for _, tc := range []struct {
		name string
		line string
		want parsedEvent
		ok   bool
	}{
		{
			name: "plain listener source",
			line: "INFO[0001] [12 34ms] inbound/vless[mb:n:21]: inbound connection from 203.0.113.9:51234",
			want: parsedEvent{id: 12, tag: "inbound/vless[mb:n:21]", kind: connEventSource, addr: "203.0.113.9"},
			ok:   true,
		},
		{
			name: "colored and timestamped vless destination",
			line: stamped + colored + "[mb:u:7:n:21:p:0] inbound connection to example.com:443",
			want: parsedEvent{id: 42, tag: "inbound/vless[mb:n:21]", kind: connEventDestination, user: "mb:u:7:n:21:p:0", addr: "example.com:443"},
			ok:   true,
		},
		{
			name: "timestamp without colors",
			line: "-0700 2026-11-11 16:00:00 INFO [7 0ms] inbound/trojan[mb:n:21]: [mb:u:7:n:21:p:0] inbound connection to example.com:443",
			want: parsedEvent{id: 7, tag: "inbound/trojan[mb:n:21]", kind: connEventDestination, user: "mb:u:7:n:21:p:0", addr: "example.com:443"},
			ok:   true,
		},
		{
			name: "trojan udp destination",
			line: "INFO[0002] [13 0ms] inbound/trojan[node-21]: [mb:u:7:n:21:p:0] inbound packet connection to 1.2.3.4:53",
			want: parsedEvent{id: 13, tag: "inbound/trojan[node-21]", kind: connEventDestination, user: "mb:u:7:n:21:p:0", addr: "1.2.3.4:53", udp: true},
			ok:   true,
		},
		{
			name: "anytls domain is lowercased",
			line: "INFO[0003] [14 3ms] inbound/anytls[mb:n:21]: [shop-user] inbound connection to EXAMPLE.com:443",
			want: parsedEvent{id: 14, tag: "inbound/anytls[mb:n:21]", kind: connEventDestination, user: "shop-user", addr: "example.com:443"},
			ok:   true,
		},
		{
			name: "shadowsocks multiuser udp source and destination share colons",
			line: "INFO[0004] [15 0ms] inbound/shadowsocks[mb:n:21]: [mb:u:7:n:21:p:d931ed25-42a5-4669-b518-c30c14d0b471] inbound packet connection to example.com:443",
			want: parsedEvent{id: 15, tag: "inbound/shadowsocks[mb:n:21]", kind: connEventDestination, user: "mb:u:7:n:21:p:d931ed25-42a5-4669-b518-c30c14d0b471", addr: "example.com:443", udp: true},
			ok:   true,
		},
		{
			name: "ipv6 destination keeps its brackets",
			line: "INFO[0005] [16 2ms] inbound/vless[mb:n:21]: [mb:u:7:n:21:p:0] inbound connection to [2001:DB8::1]:8443",
			want: parsedEvent{id: 16, tag: "inbound/vless[mb:n:21]", kind: connEventDestination, user: "mb:u:7:n:21:p:0", addr: "[2001:db8::1]:8443"},
			ok:   true,
		},
		{
			name: "ipv6 source is normalized",
			line: "INFO[0006] [17 9ms] inbound/vless[mb:n:21]: inbound connection from [2001:db8::2]:51234",
			want: parsedEvent{id: 17, tag: "inbound/vless[mb:n:21]", kind: connEventSource, addr: "2001:db8::2"},
			ok:   true,
		},
		{
			name: "ipv4 mapped source unmaps to one row per client",
			line: "INFO[0007] [18 9ms] inbound/vless[mb:n:21]: inbound connection from [::ffff:203.0.113.9]:51234",
			want: parsedEvent{id: 18, tag: "inbound/vless[mb:n:21]", kind: connEventSource, addr: "203.0.113.9"},
			ok:   true,
		},
		{
			name: "non address source keeps the destination usable",
			line: "INFO[0008] [19 9ms] inbound/vless[mb:n:21]: inbound connection from client.invalid:51234",
			want: parsedEvent{id: 19, tag: "inbound/vless[mb:n:21]", kind: connEventSource},
			ok:   true,
		},
		{
			name: "packet address connection is not a destination",
			line: "INFO[0009] [20 9ms] inbound/vless[mb:n:21]: [mb:u:7:n:21:p:0] inbound packet addr connection",
			ok:   false,
		},
		{
			name: "non info level is ignored",
			line: "WARN[0001] [21 34ms] inbound/vless[mb:n:21]: inbound connection from 203.0.113.9:51234",
			ok:   false,
		},
		{
			name: "missing tag separator",
			line: "INFO[0001] [22 34ms] inbound/vless[mb:n:21] inbound connection from 203.0.113.9:51234",
			ok:   false,
		},
		{
			name: "empty message",
			line: "INFO[0001] [23 34ms] inbound/vless[mb:n:21]: ",
			ok:   false,
		},
		{
			name: "missing port",
			line: "INFO[0001] [24 34ms] inbound/vless[mb:n:21]: [u] inbound connection to example.com",
			ok:   false,
		},
		{
			name: "invalid port",
			line: "INFO[0001] [25 34ms] inbound/vless[mb:n:21]: [u] inbound connection to example.com:70000",
			ok:   false,
		},
		{
			name: "overlong target",
			line: "INFO[0001] [26 34ms] inbound/vless[mb:n:21]: [u] inbound connection to " + strings.Repeat("a", 300) + ":443",
			ok:   false,
		},
		{name: "garbage", line: "\x00\x01not a log line", ok: false},
		{name: "empty line", line: "", ok: false},
		{name: "empty user prefix", line: "INFO[0001] [27 34ms] inbound/vless[mb:n:21]: [] inbound connection to example.com:443", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, ok := parseCoreLine([]byte(tc.line))
			if !ok {
				if tc.ok {
					t.Fatalf("line not decoded: %q", tc.line)
				}
				return
			}
			event, ok := parseConnEvent(line)
			if ok != tc.ok {
				t.Fatalf("event ok=%v, want %v (%+v)", ok, tc.ok, event)
			}
			if !ok {
				return
			}
			got := parsedEvent{id: event.id, tag: event.tag, kind: event.kind, user: event.user, addr: event.addr, udp: event.udp}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("event %+v, want %+v", got, tc.want)
			}
		})
	}
}

type parsedEvent struct {
	id   uint32
	tag  string
	kind connEventKind
	user string
	addr string
	udp  bool
}

// TestConnLogAggregatesHourBuckets documents the aggregation key: the same
// destination in the same hour merges, a new hour, network or client address
// does not.
func TestConnLogAggregatesHourBuckets(t *testing.T) {
	base := time.Unix(1762819200, 0)
	clock := &testClock{at: base.Add(34 * time.Second)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	ctx := context.Background()

	log.OnLine(sourceLine(1, "203.0.113.9:51234"))
	log.OnLine(destLine(1, "mb:u:7:n:21:p:0", "example.com:443"))
	recorder := &connRecorder{}
	if err := log.Flush(ctx, recorder); err != nil {
		t.Fatal(err)
	}
	if len(recorder.batches) != 1 {
		t.Fatalf("batches %+v", recorder.batches)
	}
	want := ConnRecord{UserID: 7, NodeID: 21, Hour: 1762819200, Target: "example.com:443", SourceIP: "203.0.113.9", Network: "tcp", Count: 1, FirstAt: 1762819234, LastAt: 1762819234}
	if got := recorder.batches[0].Records; !reflect.DeepEqual(got, []ConnRecord{want}) {
		t.Fatalf("records %+v, want %+v", got, want)
	}

	// Two connections to the same key inside one aggregation window merge into a
	// single row, widened to both timestamps. Different client ports do not split
	// the row: only the client address is part of the key.
	clock.advance(5 * time.Second)
	log.OnLine(sourceLine(2, "203.0.113.9:60000"))
	log.OnLine(destLine(2, "mb:u:7:n:21:p:0", "example.com:443"))
	clock.advance(2 * time.Second)
	log.OnLine(sourceLine(3, "203.0.113.9:61000"))
	log.OnLine(destLine(3, "mb:u:7:n:21:p:0", "example.com:443"))
	recorder = &connRecorder{}
	if err := log.Flush(ctx, recorder); err != nil {
		t.Fatal(err)
	}
	want.Count, want.FirstAt, want.LastAt = 2, 1762819239, 1762819241
	if got := recorder.batches[0].Records; !reflect.DeepEqual(got, []ConnRecord{want}) {
		t.Fatalf("merged records %+v, want %+v", got, want)
	}

	// The next hour is a separate row even for the identical destination.
	clock.set(base.Add(time.Hour + 3*time.Second))
	log.OnLine(sourceLine(3, "203.0.113.9:52000"))
	log.OnLine(destLine(3, "mb:u:7:n:21:p:0", "example.com:443"))
	// A UDP flow to the same target is a separate network.
	log.OnLine([]byte("INFO[0001] [4 0ms] inbound/vless[mb:n:21]: inbound packet connection from 198.51.100.7:1234"))
	log.OnLine([]byte("INFO[0001] [4 0ms] inbound/vless[mb:n:21]: [mb:u:7:n:21:p:0] inbound packet connection to example.com:443"))
	// A different destination in the same hour is its own row.
	log.OnLine(sourceLine(6, "198.51.100.9:6000"))
	log.OnLine(destLine(6, "mb:u:7:n:21:p:0", "example.net:443"))
	// An unknown user name resolves to nothing and is dropped.
	log.OnLine(sourceLine(5, "198.51.100.8:1"))
	log.OnLine(destLine(5, "unmapped-alias", "example.org:443"))
	recorder = &connRecorder{}
	if err := log.Flush(ctx, recorder); err != nil {
		t.Fatal(err)
	}
	records := recorder.batches[0].Records
	if len(records) != 3 {
		t.Fatalf("records %+v", records)
	}
	wantBuckets := []ConnRecord{
		{7, 21, 1762822800, "example.com:443", "198.51.100.7", "udp", 1, 1762822803, 1762822803},
		{7, 21, 1762822800, "example.com:443", "203.0.113.9", "tcp", 1, 1762822803, 1762822803},
		{7, 21, 1762822800, "example.net:443", "198.51.100.9", "tcp", 1, 1762822803, 1762822803},
	}
	if !reflect.DeepEqual(records, wantBuckets) {
		t.Fatalf("records %+v\nwant %+v", records, wantBuckets)
	}
	if len(log.keys) != 0 {
		t.Fatalf("aggregates not drained: %+v", log.keys)
	}
}

// TestConnLogBasicNamingScheme covers nodes that carry no telemetry mapping:
// the panel names the authenticated user after the account ID and tags the
// inbound node-<id>.
func TestConnLogBasicNamingScheme(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	basic := func(tag, user string) []ConnRecord {
		log.OnLine([]byte("INFO[0001] [1 1ms] inbound/vless[" + tag + "]: " + user + " inbound connection from 203.0.113.9:51234"))
		log.OnLine([]byte("INFO[0001] [1 1ms] inbound/vless[" + tag + "]: [" + user + "] inbound connection to example.com:443"))
		recorder := &connRecorder{}
		if err := log.Flush(context.Background(), recorder); err != nil {
			t.Fatal(err)
		}
		if len(recorder.batches) == 0 {
			return nil
		}
		return recorder.batches[0].Records
	}
	if records := basic("node-21", "7"); len(records) != 1 || records[0].UserID != 7 || records[0].NodeID != 21 {
		t.Fatalf("basic identity %+v", records)
	}
	// Unknown tag shapes and non-decimal users are dropped, never guessed.
	if records := basic("mb:n:21", "7"); records != nil {
		t.Fatalf("non basic tag accepted %+v", records)
	}
	if records := basic("node-21", "shop-user"); records != nil {
		t.Fatalf("non decimal user accepted %+v", records)
	}
	if records := basic("node-0", "7"); records != nil {
		t.Fatalf("zero node accepted %+v", records)
	}
}

func TestConnLogBatchChunking(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	for i := 0; i < maxConnBatchRecords+1; i++ {
		target := fmt.Sprintf("host%d.example:443", i)
		log.OnLine(sourceLine(i, "203.0.113.9:51234"))
		log.OnLine(destLine(i, "mb:u:7:n:21:p:0", target))
	}
	recorder := &connRecorder{}
	if err := log.Flush(context.Background(), recorder); err != nil {
		t.Fatal(err)
	}
	if len(recorder.batches) != 2 || len(recorder.batches[0].Records) != maxConnBatchRecords || len(recorder.batches[1].Records) != 1 {
		t.Fatalf("chunks %d/%d", len(recorder.batches[0].Records), len(recorder.batches))
	}
	for _, b := range recorder.batches {
		if err := b.Validate(); err != nil {
			t.Fatalf("chunk invalid: %v", err)
		}
	}
}

func TestConnLogKeyLimitCountsDropped(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	var logged []string
	log.Log = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	log.mu.Lock()
	for i := 0; i < maxConnKeys+5; i++ {
		log.addLocked(connKey{userID: 7, nodeID: 21, hour: 1762819200, target: fmt.Sprintf("h%d.example:443", i)}, 1762819234)
	}
	log.mu.Unlock()
	if len(log.keys) != maxConnKeys || log.dropped != 5 {
		t.Fatalf("keys=%d dropped=%d", len(log.keys), log.dropped)
	}
	// The dropped count is reported exactly once, at the next flush.
	recorder := &connRecorder{}
	if err := log.Flush(context.Background(), recorder); err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "dropped 5") {
		t.Fatalf("drop log %v", logged)
	}
	total := 0
	for _, b := range recorder.batches {
		total += len(b.Records)
	}
	if total != maxConnKeys || len(recorder.batches) != maxConnKeys/maxConnBatchRecords {
		t.Fatalf("total=%d batches=%d", total, len(recorder.batches))
	}
}

func TestConnLogQueueLimitEvictsOldest(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	var logged []string
	log.Log = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	down := errors.New("panel unavailable")
	for i := 0; i < maxConnPending+2; i++ {
		log.OnLine(sourceLine(i, "203.0.113.9:51234"))
		log.OnLine(destLine(i, "mb:u:7:n:21:p:0", fmt.Sprintf("h%d.example:443", i)))
		recorder := &connRecorder{errors: []error{down}}
		if err := log.Flush(context.Background(), recorder); err != down {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	if len(log.pending) != maxConnPending {
		t.Fatalf("pending %d", len(log.pending))
	}
	// The newest batches survive, the oldest two were evicted.
	if log.pending[len(log.pending)-1].Records[0].Target != fmt.Sprintf("h%d.example:443", maxConnPending+1) {
		t.Fatalf("newest batch evicted: %+v", log.pending[len(log.pending)-1])
	}
	if !strings.Contains(strings.Join(logged, "\n"), "oldest queued batches") {
		t.Fatalf("eviction not logged: %v", logged)
	}
}

// TestConnLogRetryKeepsBatchID verifies the idempotency contract: a retryable
// failure keeps the batch with its original ID so the panel can deduplicate.
func TestConnLogRetryKeepsBatchID(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	log.NewID = func() (string, error) { return "stable-connection-batch", nil }
	log.OnLine(sourceLine(1, "203.0.113.9:51234"))
	log.OnLine(destLine(1, "mb:u:7:n:21:p:0", "example.com:443"))
	down := errors.New("panel unavailable")
	first := &connRecorder{errors: []error{down}}
	if err := log.Flush(context.Background(), first); err != down {
		t.Fatalf("retryable failure reported as %v", err)
	}
	second := &connRecorder{}
	if err := log.Flush(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if len(second.batches) != 1 || second.batches[0].BatchID != "stable-connection-batch" {
		t.Fatalf("retried batch %+v", second.batches)
	}
	if len(log.pending) != 0 {
		t.Fatalf("acknowledged batch retained: %+v", log.pending)
	}
}

func TestConnLogPermanentRejectionDiscardsBatch(t *testing.T) {
	clock := &testClock{at: time.Unix(1762819234, 0)}
	log := NewConnLog()
	log.Now = clock.Now
	log.Labels = testLabels
	var logged []string
	log.Log = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	log.OnLine(sourceLine(1, "203.0.113.9:51234"))
	log.OnLine(destLine(1, "mb:u:7:n:21:p:0", "example.com:443"))
	recorder := &connRecorder{errors: []error{&APIError{Status: 403, Code: "CONNECTION_GRANT"}}}
	if err := log.Flush(context.Background(), recorder); err != nil {
		t.Fatalf("permanent rejection must not stop the loop: %v", err)
	}
	if len(log.pending) != 0 {
		t.Fatalf("rejected batch retained: %+v", log.pending)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "discarded batch") {
		t.Fatalf("rejection log %v", logged)
	}
}

// TestConnLogPanelWithoutEndpoint covers the 404/405 rollout gate: an older panel
// must not be probed every minute, and nothing may accumulate meanwhile.
func TestConnLogPanelWithoutEndpoint(t *testing.T) {
	for _, status := range []int{404, 405} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			clock := &testClock{at: time.Unix(1762819234, 0)}
			log := NewConnLog()
			log.Now = clock.Now
			log.Labels = testLabels
			var logged []string
			log.Log = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			log.OnLine(sourceLine(1, "203.0.113.9:51234"))
			log.OnLine(destLine(1, "mb:u:7:n:21:p:0", "example.com:443"))
			probe := &connRecorder{errors: []error{&APIError{Status: status}}}
			if err := log.Flush(context.Background(), probe); err != nil {
				t.Fatalf("status %d must not fail the loop: %v", status, err)
			}
			if !log.probing || len(log.pending) != 0 || len(log.keys) != 0 {
				t.Fatalf("status %d did not enter probe state: probing=%v pending=%d keys=%d", status, log.probing, len(log.pending), len(log.keys))
			}
			if len(logged) != 1 {
				t.Fatalf("probe announced %v", logged)
			}
			// Observations during the pause are dropped instead of buffered.
			clock.advance(5 * time.Minute)
			log.OnLine(sourceLine(2, "203.0.113.9:51234"))
			log.OnLine(destLine(2, "mb:u:7:n:21:p:0", "example.com:443"))
			if len(log.keys) != 0 {
				t.Fatalf("records buffered while probing: %+v", log.keys)
			}
			// Nothing is sent inside the window.
			idle := &connRecorder{}
			if err := log.Flush(context.Background(), idle); err != nil || idle.calls != 0 {
				t.Fatalf("probed inside window: calls=%d err=%v", idle.calls, err)
			}
			// After the window the next flush is the single probe.
			clock.advance(connProbeInterval)
			log.OnLine(sourceLine(3, "203.0.113.9:51234"))
			log.OnLine(destLine(3, "mb:u:7:n:21:p:0", "example.com:443"))
			probe = &connRecorder{}
			if err := log.Flush(context.Background(), probe); err != nil || probe.calls != 1 {
				t.Fatalf("probe after pause: calls=%d err=%v", probe.calls, err)
			}
			if log.probing {
				t.Fatal("successful probe did not resume reporting")
			}
		})
	}
}

func TestConnBatchValidation(t *testing.T) {
	valid := ConnRecord{UserID: 7, NodeID: 21, Hour: 1762819200, Target: "example.com:443", SourceIP: "203.0.113.9", Network: "tcp", Count: 3, FirstAt: 1762819234, LastAt: 1762819500}
	if err := (ConnBatch{BatchID: "b-1", Records: []ConnRecord{valid}}).Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ConnRecord){
		func(r *ConnRecord) { r.UserID = 0 },
		func(r *ConnRecord) { r.NodeID = -1 },
		func(r *ConnRecord) { r.Hour = 1762819201 },
		func(r *ConnRecord) { r.Target = "example.com" },
		func(r *ConnRecord) { r.Target = "example.com:0" },
		func(r *ConnRecord) { r.Target = ":443" },
		func(r *ConnRecord) { r.Target = "a" },
		func(r *ConnRecord) { r.Network = "icmp" },
		func(r *ConnRecord) { r.Count = 0 },
		func(r *ConnRecord) { r.Count = maxConnCount + 1 },
		func(r *ConnRecord) { r.SourceIP = "not-an-ip" },
		func(r *ConnRecord) { r.FirstAt = r.Hour - 1 },
		func(r *ConnRecord) { r.LastAt = r.Hour + connSecondsPerHour },
		func(r *ConnRecord) { r.LastAt = r.FirstAt - 1 },
	}
	for i, mutate := range mutations {
		record := valid
		mutate(&record)
		if err := (ConnBatch{BatchID: "b-1", Records: []ConnRecord{record}}).Validate(); err == nil {
			t.Fatalf("mutation %d accepted: %+v", i, record)
		}
	}
	empty := ConnBatch{BatchID: "b-1"}
	if err := empty.Validate(); err == nil {
		t.Fatal("empty batch accepted")
	}
	tooMany := ConnBatch{BatchID: "b-1", Records: make([]ConnRecord, maxConnBatchRecords+1)}
	if err := tooMany.Validate(); err == nil {
		t.Fatal("oversized batch accepted")
	}
	for _, id := range []string{"", "has space", strings.Repeat("a", 129), "../escape"} {
		if err := (ConnBatch{BatchID: id, Records: []ConnRecord{valid}}).Validate(); err == nil {
			t.Fatalf("bad batch id accepted: %q", id)
		}
	}
	// An empty source_ip is legal: the panel shows a missing client address.
	unknown := valid
	unknown.SourceIP = ""
	if err := (ConnBatch{BatchID: "b-1", Records: []ConnRecord{unknown}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestClientConnectionsRequestAndReceipt(t *testing.T) {
	seen := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-machine-secret-token" {
			t.Error("missing auth")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/node/v1/connections" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		seen <- body
		reply(w, map[string]any{"accepted": true, "stored": 1, "skipped": 0})
	}))
	defer srv.Close()
	c, err := NewClient(testConfig(t, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	batch := ConnBatch{BatchID: "conn-1", Records: []ConnRecord{{UserID: 7, NodeID: 21, Hour: 1762819200, Target: "example.com:443", SourceIP: "203.0.113.9", Network: "tcp", Count: 3, FirstAt: 1762819234, LastAt: 1762819500}}}
	if err = c.Connections(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	body := <-seen
	if body["batch_id"] != "conn-1" {
		t.Fatalf("body %v", body)
	}
	records, ok := body["records"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("records %v", body["records"])
	}
	record := records[0].(map[string]any)
	for _, field := range []string{"user_id", "node_id", "hour", "target", "source_ip", "network", "count", "first_at", "last_at"} {
		if _, found := record[field]; !found {
			t.Fatalf("record missing %s: %v", field, record)
		}
	}
	if record["hour"] != float64(1762819200) || record["source_ip"] != "203.0.113.9" {
		t.Fatalf("record %v", record)
	}
}

func TestClientConnectionsRejectsBadReplies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not accepted", `{"data":{"accepted":false}}`},
		{"negative stored", `{"data":{"accepted":true,"stored":-1}}`},
		{"negative skipped", `{"data":{"accepted":true,"stored":1,"skipped":-2}}`},
		{"missing data", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			defer srv.Close()
			c, _ := NewClient(testConfig(t, srv.URL))
			batch := ConnBatch{BatchID: "conn-1", Records: []ConnRecord{{UserID: 7, NodeID: 21, Hour: 1762819200, Target: "example.com:443", Network: "tcp", Count: 1, FirstAt: 1762819234, LastAt: 1762819234}}}
			if err := c.Connections(context.Background(), batch); err == nil {
				t.Fatal("bad receipt accepted")
			}
		})
	}
	// A panel without the endpoint answers 404, which the aggregator treats as a
	// version signal rather than a per-batch verdict.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	c, _ := NewClient(testConfig(t, srv.URL))
	batch := ConnBatch{BatchID: "conn-1", Records: []ConnRecord{{UserID: 7, NodeID: 21, Hour: 1762819200, Target: "example.com:443", Network: "tcp", Count: 1, FirstAt: 1762819234, LastAt: 1762819234}}}
	err := c.Connections(context.Background(), batch)
	if err == nil || !probeRefused(err) || permanent(err) {
		t.Fatalf("404 classification: %v", err)
	}
}

// fakeLogCore writes a scripted stderr before settling into a long sleep. It is a
// shell script so the test needs no compiler, no network and no real core.
func fakeLogCore(t *testing.T, script string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "test-core")
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return binary
}

func TestProcessCoreOnLineCapture(t *testing.T) {
	binary := fakeLogCore(t, `#!/bin/sh
case "$1" in
run)
  printf 'INFO[0001] [7 12ms] inbound/vless[node-21]: inbound connection from 203.0.113.9:51234\n' >&2
  printf 'INFO[0001] [7 14ms] inbound/vless[node-21]: [9] inbound connection to example.com:443\n' >&2
  head -c 1048576 /dev/zero | tr '\0' 'x' >&2
  printf '\n' >&2
  printf 'INFO[0001] [7 15ms] inbound/vless[node-21]: [9] inbound connection to example.org:8443\n' >&2
  exec sleep 60
  ;;
*) exit 2 ;;
esac
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	received := make(chan struct{}, 8)
	p := &ProcessCore{Binary: binary, Timeout: time.Second, StartupGrace: 50 * time.Millisecond, StopGrace: time.Second}
	p.OnLine = func(line []byte) {
		mu.Lock()
		lines = append(lines, string(line))
		total := len(lines)
		mu.Unlock()
		if total <= cap(received) {
			received <- struct{}{}
		}
	}
	if err := p.Restart(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if p.cmd.Stderr == nil || p.logRead == nil {
		t.Fatal("stderr pipe not attached")
	}
	deadline := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-deadline:
			t.Fatalf("core log lines missing: %v", lines)
		}
	}
	// The 1 MiB line is discarded whole and must not stop the core: the child is
	// still alive and later lines keep arriving.
	if !p.Running() {
		t.Fatal("core exited while writing an overlong log line")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) < 3 {
		t.Fatalf("lines %v", lines)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "xxx") || len(line) > 1024 {
			t.Fatalf("overlong line delivered: %d bytes", len(line))
		}
	}
	if !strings.Contains(lines[len(lines)-1], "example.org:8443") {
		t.Fatalf("trailing line lost: %v", lines)
	}
}

func TestProcessCoreWithoutOnLineKeepsDiscardedStderr(t *testing.T) {
	binary := fakeLogCore(t, "#!/bin/sh\ncase \"$1\" in\nrun) printf 'noise\\n' >&2; exec sleep 60 ;;\n*) exit 2 ;;\nesac\n")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := &ProcessCore{Binary: binary, Timeout: time.Second, StartupGrace: 20 * time.Millisecond, StopGrace: time.Second}
	if err := p.Restart(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	// Nil OnLine means the 0.2.2 start path: no pipe, stderr discarded by exec.
	if p.cmd.Stderr != nil || p.logRead != nil {
		t.Fatalf("stderr captured without a handler: %v", p.cmd.Stderr)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
}

// TestManagerLabelsSnapshot pins the published accounting mapping to the running
// core generation: the connection log resolves identity from it, so a rolled
// back revision must never leave the candidate mapping behind.
func TestManagerLabelsSnapshot(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	core := &fakeCore{}
	m, err := NewManager(cfg, core)
	if err != nil {
		t.Fatal(err)
	}
	if labels := m.Labels(); labels == nil || len(labels) != 0 {
		t.Fatalf("initial labels %+v", labels)
	}
	first := RemoteConfig{Revision: 1, Config: nativeFor("opaque"), TrafficLabels: []TrafficLabel{{Label: "opaque", UserID: 7, NodeID: 21}}}
	if err = m.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if label := m.Labels()["opaque"]; label.UserID != 7 || label.NodeID != 21 {
		t.Fatalf("applied labels %+v", m.Labels())
	}
	candidate := RemoteConfig{Revision: 2, Config: nativeFor("candidate"), TrafficLabels: []TrafficLabel{{Label: "candidate", UserID: 8, NodeID: 22}}}
	m.writeState = func(string, []byte) error { return fmt.Errorf("state metadata fsync failed") }
	if err = m.Apply(context.Background(), candidate); err == nil {
		t.Fatal("state failure ignored")
	}
	labels := m.Labels()
	if len(labels) != 1 || labels["opaque"].UserID != 7 {
		t.Fatalf("rollback labels %+v", labels)
	}
	if _, found := labels["candidate"]; found {
		t.Fatal("candidate mapping survived rollback")
	}
	m.writeState = nil
	if err = m.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if label := m.Labels()["candidate"]; label.UserID != 8 || label.NodeID != 22 {
		t.Fatalf("candidate labels %+v", m.Labels())
	}
	// A reload from disk republishes the persisted mapping, so a restarted agent
	// resolves identities before it fetches any panel config.
	reloaded, err := NewManager(cfg, core)
	if err != nil {
		t.Fatal(err)
	}
	if label := reloaded.Labels()["candidate"]; label.NodeID != 22 {
		t.Fatalf("reloaded labels %+v", reloaded.Labels())
	}
}

func TestConnectionLogConfigToggle(t *testing.T) {
	cfg := testConfig(t, "http://localhost")
	for _, value := range []string{"", "on"} {
		cfg.ConnectionLog = value
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%q rejected: %v", value, err)
		}
		if !cfg.ConnectionLogEnabled() {
			t.Fatalf("%q disabled", value)
		}
	}
	cfg.ConnectionLog = "off"
	if err := cfg.Validate(); err != nil || cfg.ConnectionLogEnabled() {
		t.Fatalf("off handled as %v/%v", cfg.Validate(), cfg.ConnectionLogEnabled())
	}
	for _, value := range []string{"true", "ON", "0", "yes"} {
		cfg.ConnectionLog = value
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
	// The default is on, and an environment variable overrides the file.
	path := filepath.Join(t.TempDir(), "agent.json")
	base := testConfig(t, "http://localhost")
	raw, _ := json.Marshal(base)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.ConnectionLog != "on" {
		t.Fatalf("default %+v %v", loaded.ConnectionLog, err)
	}
	t.Setenv("MBOARD_NODE_CONNECTION_LOG", "off")
	loaded, err = LoadConfig(path)
	if err != nil || loaded.ConnectionLog != "off" || loaded.ConnectionLogEnabled() {
		t.Fatalf("env override %+v %v", loaded.ConnectionLog, err)
	}
}
