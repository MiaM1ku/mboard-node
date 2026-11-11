package node

// Connection log (agent 0.3.0).
//
// The core's stderr is the only place where sing-box reports which
// authenticated user asked for which destination: the V2Ray stats API
// aggregates per username and carries no destination dimension, so per-target
// reporting can only come from the info log. This file reads that log, pairs
// the listener's source address with the protocol layer's destination through
// the connection ID both lines share, and aggregates best-effort observations
// per hour. Billing is untouched: bytes still come from the collector and the
// journal/spool semantics stay exactly as they were in 0.2.2.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxConnBatchRecords mirrors the panel's per-request record limit, so one
	// flush is chunked instead of producing an oversized POST.
	maxConnBatchRecords = 2000
	// maxConnPending bounds the in-memory delivery queue: during a panel outage
	// the node keeps at most ten batch chunks and drops the oldest, keeping the
	// newest observations for the panel that comes back.
	maxConnPending = 10
	// maxConnKeys bounds distinct aggregation keys. 20k buckets is a few MiB of
	// map state on a very busy node and a documented ceiling, not a silent leak.
	maxConnKeys = 20000
	// maxConnSources bounds connection ID -> source address pairs. They live for
	// one pair of log lines, so a bound this large only exists as a safety net.
	maxConnSources = 20000
	// connSourceAge is how long a listener "from" line may wait for its
	// destination line before it is forgotten. Both lines are written for the
	// same connection within microseconds.
	connSourceAge = 60 * time.Second
	// connProbeInterval is the pause after a panel answers 404/405: the endpoint
	// does not exist yet (older panel), so records are useless until it does.
	connProbeInterval = 10 * time.Minute
	// maxConnCount is the panel's per-record connection count limit. Aggregates
	// saturate here instead of producing a record the panel must reject.
	maxConnCount = 1_000_000_000
	// Target length bounds mirror the panel contract (3..270 characters).
	minConnTargetLen = 3
	maxConnTargetLen = 270
	// connSecondsPerHour is the aggregation bucket width; the panel requires
	// hour to be a multiple of it and both timestamps inside the bucket.
	connSecondsPerHour = 3600
)

// ConnRecord is one aggregated (user, node, hour, target, source, network)
// bucket exactly as the panel stores it. Field order and names follow the
// fixed node protocol so the panel can decode the same struct.
type ConnRecord struct {
	UserID   int64  `json:"user_id"`
	NodeID   int64  `json:"node_id"`
	Hour     int64  `json:"hour"`
	Target   string `json:"target"`
	SourceIP string `json:"source_ip"`
	Network  string `json:"network"`
	Count    int64  `json:"count"`
	FirstAt  int64  `json:"first_at"`
	LastAt   int64  `json:"last_at"`
}

// ConnBatch is an immutable idempotency unit: the panel deduplicates on
// BatchID, so a retry after an uncertain acknowledgment can never double count.
type ConnBatch struct {
	BatchID string       `json:"batch_id"`
	Records []ConnRecord `json:"records"`
}

// ConnSender delivers one immutable connection batch. The agent passes the real
// Client; tests pass a recorder, so the aggregator itself has no HTTP or panel
// dependency.
type ConnSender interface {
	Connections(context.Context, ConnBatch) error
}

func (r ConnRecord) validate() error {
	if r.UserID <= 0 || r.NodeID <= 0 || r.UserID > MaxSafeInteger || r.NodeID > MaxSafeInteger {
		return errors.New("user_id and node_id must be positive safe integers")
	}
	if r.Hour < 0 || r.Hour > MaxSafeInteger-connSecondsPerHour || r.Hour%connSecondsPerHour != 0 {
		return errors.New("hour must be a non-negative multiple of 3600")
	}
	if len(r.Target) < minConnTargetLen || len(r.Target) > maxConnTargetLen {
		return fmt.Errorf("target must be %d-%d characters", minConnTargetLen, maxConnTargetLen)
	}
	host, port, err := net.SplitHostPort(r.Target)
	if err != nil || host == "" {
		return errors.New("target must be host:port")
	}
	if p, e := strconv.Atoi(port); e != nil || p < 1 || p > 65535 {
		return errors.New("target port must be 1-65535")
	}
	if r.Network != "tcp" && r.Network != "udp" {
		return errors.New("network must be tcp or udp")
	}
	if r.Count < 1 || r.Count > maxConnCount {
		return errors.New("count must be 1-1000000000")
	}
	if r.SourceIP != "" {
		if _, err = netip.ParseAddr(r.SourceIP); err != nil {
			return errors.New("source_ip must be empty or an IP address")
		}
	}
	if r.FirstAt < r.Hour || r.FirstAt >= r.Hour+connSecondsPerHour || r.LastAt < r.FirstAt || r.LastAt >= r.Hour+connSecondsPerHour {
		return errors.New("first_at and last_at must lie inside the hour bucket")
	}
	return nil
}

// Validate enforces the panel's request contract locally. The agent never sends
// a batch the panel is expected to reject, so a single bad observation cannot
// cost a whole batch on a panel that rejects requests atomically.
func (b ConnBatch) Validate() error {
	if err := validBatchID(b.BatchID); err != nil {
		return err
	}
	if len(b.Records) == 0 || len(b.Records) > maxConnBatchRecords {
		return fmt.Errorf("records must contain 1-%d entries", maxConnBatchRecords)
	}
	for i, r := range b.Records {
		if err := r.validate(); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxBody {
		return errors.New("connection batch exceeds 1 MiB")
	}
	return nil
}

type connKey struct {
	userID   int64
	nodeID   int64
	hour     int64
	target   string
	sourceIP string
	udp      bool
}

type connValue struct {
	count   int64
	firstAt int64
	lastAt  int64
}

type connSource struct {
	ip string
	at time.Time
}

// ConnLog aggregates authenticated connections seen in the core log.
//
// The design is best effort by intent: observations are in-memory only, a slow
// or missing panel costs log records but never billing data, and every structure
// has a documented bound. It is safe for concurrent use: OnLine runs on the
// core's stderr reader goroutine while Flush runs on the agent's worker.
type ConnLog struct {
	// Labels returns the accounting mapping of the running core. A nil function
	// or a miss falls back to the basic naming scheme (decimal user name and a
	// node-<id> inbound tag), which is how a node without telemetry is tagged.
	Labels func() map[string]TrafficLabel
	// Now and NewID are injection points for deterministic tests; nil uses the
	// wall clock and NewBatchID.
	Now   func() time.Time
	NewID func() (string, error)
	// Log reports one operator-facing event (drop counters, a refused endpoint,
	// a discarded batch). Nil stays silent.
	Log func(format string, args ...any)

	mu         sync.Mutex
	keys       map[connKey]connValue
	sources    map[uint32]connSource
	pending    []ConnBatch
	dropped    int64
	probing    bool
	probeUntil time.Time
	delivering bool
}

// NewConnLog returns an empty aggregator. It takes no configuration because the
// connection log has no tunables an operator could safely change: the batch
// size, key bound and probe interval come from the panel contract itself.
func NewConnLog() *ConnLog {
	return &ConnLog{keys: map[connKey]connValue{}, sources: map[uint32]connSource{}}
}

func (c *ConnLog) nowTime() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ConnLog) newBatchID() (string, error) {
	if c.NewID != nil {
		return c.NewID()
	}
	return NewBatchID()
}

func (c *ConnLog) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

// OnLine consumes one core stderr line. It never blocks on the panel and never
// panics on malformed input: unrecognised lines are simply ignored, because the
// core log is full of records this collector does not care about.
func (c *ConnLog) OnLine(line []byte) {
	parsed, ok := parseCoreLine(line)
	if !ok {
		return
	}
	event, ok := parseConnEvent(parsed)
	if !ok {
		return
	}
	now := c.nowTime()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probing && now.Before(c.probeUntil) {
		// The panel has no endpoint yet; discarding observations keeps memory
		// flat instead of accumulating records nobody can accept.
		return
	}
	switch event.kind {
	case connEventSource:
		c.rememberSourceLocked(event.id, event.addr, now)
	case connEventDestination:
		userID, nodeID, ok := resolveConnIdentity(c.labelsLocked(), event.tag, event.user)
		if !ok {
			return
		}
		source := c.takeSourceLocked(event.id, now)
		at := now.Unix()
		c.addLocked(connKey{
			userID:   userID,
			nodeID:   nodeID,
			hour:     at - at%connSecondsPerHour,
			target:   event.addr,
			sourceIP: source,
			udp:      event.udp,
		}, at)
	}
}

func (c *ConnLog) labelsLocked() map[string]TrafficLabel {
	if c.Labels == nil {
		return nil
	}
	return c.Labels()
}

func (c *ConnLog) addLocked(key connKey, at int64) {
	value, found := c.keys[key]
	if !found {
		if len(c.keys) >= maxConnKeys {
			c.dropped++
			return
		}
		value = connValue{firstAt: at, lastAt: at}
	}
	if value.count < maxConnCount {
		value.count++
	}
	if at < value.firstAt {
		value.firstAt = at
	}
	if at > value.lastAt {
		value.lastAt = at
	}
	c.keys[key] = value
}

func (c *ConnLog) rememberSourceLocked(id uint32, ip string, now time.Time) {
	if ip == "" {
		return
	}
	if len(c.sources) >= maxConnSources {
		c.pruneSourcesLocked(now)
		if len(c.sources) >= maxConnSources {
			// Every pending pair is stale or the ID space is being reused faster
			// than destinations appear; forget them rather than grow unbounded.
			c.sources = map[uint32]connSource{}
		}
	}
	c.sources[id] = connSource{ip: ip, at: now}
}

func (c *ConnLog) takeSourceLocked(id uint32, now time.Time) string {
	source, found := c.sources[id]
	if !found {
		return ""
	}
	delete(c.sources, id)
	if now.Sub(source.at) > connSourceAge {
		return ""
	}
	return source.ip
}

func (c *ConnLog) pruneSourcesLocked(now time.Time) {
	for id, source := range c.sources {
		if now.Sub(source.at) > connSourceAge {
			delete(c.sources, id)
		}
	}
}

// Flush turns the current aggregates into immutable batches, then delivers every
// queued batch in order. It is the only place that talks to the panel, so the
// agent can run it on a plain periodic worker and still keep every state change
// under the same lock as OnLine.
func (c *ConnLog) Flush(ctx context.Context, send ConnSender) error {
	if send == nil {
		return errors.New("connection flush without a sender")
	}
	now := c.nowTime()
	c.mu.Lock()
	if c.probing {
		if now.Before(c.probeUntil) {
			c.mu.Unlock()
			return nil
		}
		// The probe window elapsed: accept and send again. This flush is the
		// single probe; another 404/405 re-enters the pause.
		c.probing = false
		c.probeUntil = time.Time{}
	}
	if c.delivering {
		// Another pass owns delivery; returning quietly avoids two workers
		// racing the same batch to the panel.
		c.mu.Unlock()
		return nil
	}
	c.pruneSourcesLocked(now)
	if dropped := c.dropped; dropped > 0 {
		c.dropped = 0
		c.logf("connections: dropped %d buckets above the %d-key limit", dropped, maxConnKeys)
	}
	c.enqueueLocked()
	c.delivering = true
	queued := make([]ConnBatch, len(c.pending))
	copy(queued, c.pending)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.delivering = false
		c.mu.Unlock()
	}()
	for _, batch := range queued {
		if err := send.Connections(ctx, batch); err != nil {
			if probeRefused(err) {
				c.enterProbe(err)
				return nil
			}
			if permanent(err) {
				c.discard(batch.BatchID, err)
				continue
			}
			return err
		}
		c.acknowledge(batch.BatchID)
	}
	return nil
}

func (c *ConnLog) acknowledge(batchID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(batchID)
}

func (c *ConnLog) discard(batchID string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(batchID)
	c.logf("connections: discarded batch %s: %v", batchID, err)
}

func (c *ConnLog) removeLocked(batchID string) {
	for i := range c.pending {
		if c.pending[i].BatchID == batchID {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			return
		}
	}
}

// enterProbe forgets everything and pauses reporting for connProbeInterval.
// Clearing the queue is the point: an older panel would refuse those batches
// forever, and holding them would only grow memory on every node.
func (c *ConnLog) enterProbe(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = map[connKey]connValue{}
	c.sources = map[uint32]connSource{}
	c.pending = nil
	c.dropped = 0
	c.probing = true
	c.probeUntil = c.nowTime().Add(connProbeInterval)
	c.logf("connections: panel does not expose /api/node/v1/connections: %v; connection log paused for %s", err, connProbeInterval)
}

// enqueueLocked freezes the aggregates into batches. Failing to allocate a batch
// ID keeps the aggregates in place for the next flush instead of losing them.
func (c *ConnLog) enqueueLocked() {
	if len(c.keys) == 0 {
		return
	}
	records := make([]ConnRecord, 0, len(c.keys))
	for key, value := range c.keys {
		network := "tcp"
		if key.udp {
			network = "udp"
		}
		records = append(records, ConnRecord{
			UserID:   key.userID,
			NodeID:   key.nodeID,
			Hour:     key.hour,
			Target:   key.target,
			SourceIP: key.sourceIP,
			Network:  network,
			Count:    value.count,
			FirstAt:  value.firstAt,
			LastAt:   value.lastAt,
		})
	}
	chunks := (len(records) + maxConnBatchRecords - 1) / maxConnBatchRecords
	ids := make([]string, chunks)
	for i := range ids {
		id, err := c.newBatchID()
		if err != nil {
			c.logf("connections: cannot allocate batch id: %v", err)
			return
		}
		ids[i] = id
	}
	// Deterministic order keeps a retried batch byte-identical and makes the
	// aggregation testable without relying on map iteration order.
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.UserID != b.UserID {
			return a.UserID < b.UserID
		}
		if a.NodeID != b.NodeID {
			return a.NodeID < b.NodeID
		}
		if a.Hour != b.Hour {
			return a.Hour < b.Hour
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.SourceIP != b.SourceIP {
			return a.SourceIP < b.SourceIP
		}
		return a.Network < b.Network
	})
	c.keys = map[connKey]connValue{}
	for i, id := range ids {
		start := i * maxConnBatchRecords
		end := start + maxConnBatchRecords
		if end > len(records) {
			end = len(records)
		}
		c.pending = append(c.pending, ConnBatch{BatchID: id, Records: records[start:end]})
	}
	if evicted := len(c.pending) - maxConnPending; evicted > 0 {
		c.pending = append([]ConnBatch(nil), c.pending[evicted:]...)
		c.logf("connections: discarded %d oldest queued batches above the %d-batch limit", evicted, maxConnPending)
	}
}

// probeRefused reports the two statuses that mean "this panel predates the
// connection log". Keeping them separate from permanent() is deliberate: 404 and
// 405 stay retryable for traffic batches, while for log records they are a
// version signal that must not cost a retry loop or a full queue every minute.
func probeRefused(err error) bool {
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	return api.Status == 404 || api.Status == 405
}

var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// logTimestampPrefix is the sing-box formatter's full timestamp, produced when
// the panel config sets log{timestamp:true} with the default "-0700
// 2006-01-02 15:04:05" layout.
var logTimestampPrefix = regexp.MustCompile(`^[+-][0-9]{4} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} `)

// coreLine is one decoded sing-box record: the connection ID shared by both
// lines of a connection, the inbound logger tag and the message text.
type coreLine struct {
	id  uint32
	tag string
	msg string
}

// parseCoreLine decodes `INFO[<seconds>] [<id> <duration>] <tag>: <message>`,
// tolerating the optional full timestamp and the ANSI colours logrusorgru/aurora
// keeps on a pipe. It is a pure function so the format can be verified against
// recorded core output without any process or panel.
func parseCoreLine(line []byte) (coreLine, bool) {
	text := strings.TrimRight(ansiEscape.ReplaceAllString(string(line), ""), "\r\n")
	text = logTimestampPrefix.ReplaceAllString(text, "")
	if !strings.HasPrefix(text, "INFO") {
		return coreLine{}, false
	}
	text = text[len("INFO"):]
	if strings.HasPrefix(text, "[") {
		// Non-timestamped form: INFO[0001] seconds since start.
		end := strings.IndexByte(text, ']')
		if end < 2 || !allDigits(text[1:end]) {
			return coreLine{}, false
		}
		text = text[end+1:]
	}
	if text == "" || text[0] != ' ' {
		return coreLine{}, false
	}
	text = text[1:]
	if text == "" || text[0] != '[' {
		return coreLine{}, false
	}
	end := strings.IndexByte(text, ']')
	if end < 2 {
		return coreLine{}, false
	}
	fields := strings.SplitN(text[1:end], " ", 2)
	if len(fields) != 2 || fields[1] == "" || !allDigits(fields[0]) {
		return coreLine{}, false
	}
	id, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return coreLine{}, false
	}
	text = text[end+1:]
	if text == "" || text[0] != ' ' {
		return coreLine{}, false
	}
	text = text[1:]
	// The tag may contain colons (mb:n:21) but never ": ", so the first ": "
	// separates the inbound logger tag from the message.
	separator := strings.Index(text, ": ")
	if separator <= 0 {
		return coreLine{}, false
	}
	tag, msg := text[:separator], text[separator+2:]
	if msg == "" {
		return coreLine{}, false
	}
	return coreLine{id: uint32(id), tag: tag, msg: msg}, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type connEventKind uint8

const (
	connEventSource connEventKind = iota + 1
	connEventDestination
)

// connEvent is one usable half of a connection record: either the client
// address from the listener or the destination from the protocol layer.
type connEvent struct {
	id   uint32
	tag  string
	kind connEventKind
	user string
	addr string
	udp  bool
}

// parseConnEvent classifies a decoded line. sing-box prints the authenticated
// user as a "[user]" prefix; the user may itself contain colons, so the prefix
// ends at the first "]".
func parseConnEvent(line coreLine) (connEvent, bool) {
	msg, user := line.msg, ""
	if strings.HasPrefix(msg, "[") {
		end := strings.IndexByte(msg, ']')
		if end < 2 {
			return connEvent{}, false
		}
		user = msg[1:end]
		rest := msg[end+1:]
		if !strings.HasPrefix(rest, " ") {
			return connEvent{}, false
		}
		msg = rest[1:]
	}
	event := connEvent{id: line.id, tag: line.tag, user: user}
	var rest string
	switch {
	case strings.HasPrefix(msg, "inbound packet connection from "):
		event.kind, event.udp = connEventSource, true
		rest = msg[len("inbound packet connection from "):]
	case strings.HasPrefix(msg, "inbound connection from "):
		event.kind = connEventSource
		rest = msg[len("inbound connection from "):]
	case strings.HasPrefix(msg, "inbound packet connection to "):
		event.kind, event.udp = connEventDestination, true
		rest = msg[len("inbound packet connection to "):]
	case strings.HasPrefix(msg, "inbound connection to "):
		event.kind = connEventDestination
		rest = msg[len("inbound connection to "):]
	default:
		return connEvent{}, false
	}
	if event.kind == connEventSource {
		if ip, ok := normalizeConnSource(rest); ok {
			event.addr = ip
		}
		return event, true
	}
	target, ok := normalizeConnTarget(rest)
	if !ok {
		return connEvent{}, false
	}
	event.addr = target
	return event, true
}

// normalizeConnSource reduces a logged client address to a canonical IP string,
// or "" when it is not an address (a hostname source, for example).
func normalizeConnSource(raw string) (string, bool) {
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	// Drop IPv6 zones: a link-local zone is host-local noise the panel cannot use,
	// and Unmap keeps one row for a client that reached the core over IPv4.
	return addr.WithZone("").Unmap().String(), true
}

// normalizeConnTarget validates and canonicalises a destination. The panel keys
// rows on the target string, so the same destination must always be encoded the
// same way: lowercase host, numeric port, bracketed IPv6.
func normalizeConnTarget(raw string) (string, bool) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || port == "" {
		return "", false
	}
	if len(host) > maxConnTargetLen {
		return "", false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", false
	}
	target := net.JoinHostPort(strings.ToLower(host), strconv.Itoa(number))
	if len(target) < minConnTargetLen || len(target) > maxConnTargetLen {
		return "", false
	}
	return target, true
}

// resolveConnIdentity maps a logged user name to the panel's account and entry
// node. The accounting mapping wins because it is the only trusted source; a
// mapping that violates the panel's ID bounds is dropped rather than guessed.
// Without a mapping, the basic naming scheme is used: the panel names the
// authenticated user after the account ID and tags the inbound node-<id>.
func resolveConnIdentity(labels map[string]TrafficLabel, tag, user string) (int64, int64, bool) {
	if user == "" {
		return 0, 0, false
	}
	if label, found := labels[user]; found {
		if label.UserID <= 0 || label.NodeID <= 0 || label.UserID > MaxSafeInteger || label.NodeID > MaxSafeInteger {
			return 0, 0, false
		}
		return label.UserID, label.NodeID, true
	}
	userID, err := strconv.ParseInt(user, 10, 64)
	if err != nil || userID <= 0 || userID > MaxSafeInteger {
		return 0, 0, false
	}
	name, ok := inboundTagName(tag)
	if !ok {
		return 0, 0, false
	}
	digits, found := strings.CutPrefix(name, "node-")
	if !found || !allDigits(digits) {
		return 0, 0, false
	}
	nodeID, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || nodeID <= 0 || nodeID > MaxSafeInteger {
		return 0, 0, false
	}
	return userID, nodeID, true
}

// inboundTagName extracts the configured tag from `inbound/<type>[<tag>]`. The
// type is irrelevant for accounting, and the tag may contain colons, so only the
// bracket pair is used.
func inboundTagName(tag string) (string, bool) {
	if !strings.HasPrefix(tag, "inbound/") || !strings.HasSuffix(tag, "]") {
		return "", false
	}
	open := strings.LastIndexByte(tag, '[')
	if open < 0 || open+2 > len(tag)-1 {
		return "", false
	}
	return tag[open+1 : len(tag)-1], true
}
