package node

// Domain traffic (agent 0.5.0).
//
// The connection log counts connections per destination; this file adds bytes.
// sing-box's Clash API lists every live connection with its cumulative upload and
// download and the host the client asked for (or the sniffed domain), but names no
// user. The user comes from the core log: ConnLog remembers which authenticated
// user owns each client socket, and a Clash connection with the same inbound tag
// and source socket belongs to that user. Each poll turns the growth of every
// connection counter into bytes, folds destinations into their registrable
// domain and aggregates per (user, node, hour, domain). Billing is untouched.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	maxDomainBatchRecords = 2000
	maxDomainPending      = 10
	maxDomainKeys         = 20000
	maxDomainLength       = 253
	maxClashSnapshot      = 32 << 20
	clashRequestTimeout   = 2 * time.Second
)

// DomainRecord is one aggregated (user, node, hour, domain) byte bucket.
type DomainRecord struct {
	UserID        int64  `json:"user_id"`
	NodeID        int64  `json:"node_id"`
	Hour          int64  `json:"hour"`
	Domain        string `json:"domain"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
}

// DomainBatch is an immutable idempotency unit, deduplicated by the panel on BatchID.
type DomainBatch struct {
	BatchID string         `json:"batch_id"`
	Records []DomainRecord `json:"records"`
}

type DomainSender interface {
	DomainTraffic(context.Context, DomainBatch) error
}

func validDomainName(domain string) bool {
	if domain == "" || len(domain) > maxDomainLength {
		return false
	}
	for _, r := range domain {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (r DomainRecord) validate() error {
	if r.UserID <= 0 || r.NodeID <= 0 || r.UserID > MaxSafeInteger || r.NodeID > MaxSafeInteger {
		return errors.New("user_id and node_id must be positive safe integers")
	}
	if r.Hour < 0 || r.Hour > MaxSafeInteger-connSecondsPerHour || r.Hour%connSecondsPerHour != 0 {
		return errors.New("hour must be a non-negative multiple of 3600")
	}
	if !validDomainName(r.Domain) {
		return errors.New("domain must be 1-253 printable characters")
	}
	if r.UploadBytes < 0 || r.DownloadBytes < 0 || r.UploadBytes > MaxSafeInteger || r.DownloadBytes > MaxSafeInteger || r.UploadBytes+r.DownloadBytes > MaxSafeInteger {
		return errors.New("byte counts must be safe non-negative integers")
	}
	if r.UploadBytes == 0 && r.DownloadBytes == 0 {
		return errors.New("a record needs at least one byte")
	}
	return nil
}

func (b DomainBatch) Validate() error {
	if err := validBatchID(b.BatchID); err != nil {
		return err
	}
	if len(b.Records) == 0 || len(b.Records) > maxDomainBatchRecords {
		return fmt.Errorf("records must contain 1-%d entries", maxDomainBatchRecords)
	}
	for i, r := range b.Records {
		if err := r.validate(); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxBody {
		return errors.New("domain traffic batch exceeds 1 MiB")
	}
	return nil
}

type domainKey struct {
	userID int64
	nodeID int64
	hour   int64
	domain string
}

type domainValue struct{ up, down int64 }

type clashCounter struct{ up, down int64 }

// DomainTraffic polls the loopback Clash API and reports per-domain bytes.
type DomainTraffic struct {
	// Spec returns the telemetry spec of the running core; it carries the Clash
	// endpoint. An empty endpoint switches the feature off without error.
	Spec func() TelemetrySpec
	// Peers resolves a client socket to its authenticated user.
	Peers *ConnLog
	// Client is the HTTP client for the Clash API; nil uses a proxy-free default.
	Client *http.Client
	Now    func() time.Time
	NewID  func() (string, error)
	Log    func(format string, args ...any)

	mu         sync.Mutex
	address    string
	last       map[string]clashCounter
	keys       map[domainKey]domainValue
	pending    []DomainBatch
	dropped    int64
	probing    bool
	probeUntil time.Time
	delivering bool
}

func NewDomainTraffic() *DomainTraffic {
	return &DomainTraffic{last: map[string]clashCounter{}, keys: map[domainKey]domainValue{}}
}

func (d *DomainTraffic) nowTime() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *DomainTraffic) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log(format, args...)
	}
}

func (d *DomainTraffic) httpClient() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
}

type clashConnection struct {
	ID       string `json:"id"`
	Metadata struct {
		Type          string `json:"type"`
		SourceIP      string `json:"sourceIP"`
		SourcePort    string `json:"sourcePort"`
		DestinationIP string `json:"destinationIP"`
		Host          string `json:"host"`
	} `json:"metadata"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (d *DomainTraffic) fetch(ctx context.Context, address, secret string) ([]clashConnection, error) {
	ctx, cancel := context.WithTimeout(ctx, clashRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/connections", nil)
	if err != nil {
		return nil, errors.New("build clash request failed")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	res, err := d.httpClient().Do(req)
	if err != nil {
		return nil, errors.New("local clash api unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local clash api answered %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxClashSnapshot+1))
	if err != nil || len(raw) > maxClashSnapshot {
		return nil, errors.New("clash snapshot unreadable or too large")
	}
	var snapshot struct {
		Connections []clashConnection `json:"connections"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return nil, errors.New("invalid clash snapshot")
	}
	return snapshot.Connections, nil
}

// domainOf folds a destination into the unit the panel reports: the registrable
// domain, or the literal address when the client connected by IP.
func domainOf(host, destinationIP string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(destinationIP))
	}
	if name == "" {
		return "", false
	}
	if net.ParseIP(name) == nil {
		if base, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			name = base
		}
	}
	if !validDomainName(name) {
		return "", false
	}
	return name, true
}

// Poll reads one snapshot and adds the byte growth of every attributable
// connection to the current hour. Connections that vanish between two polls lose
// at most the bytes of their last interval.
func (d *DomainTraffic) Poll(ctx context.Context) error {
	if d.Spec == nil {
		return nil
	}
	spec := d.Spec()
	now := d.nowTime()
	d.mu.Lock()
	if spec.ClashAddress == "" || (d.probing && now.Before(d.probeUntil)) {
		d.last = map[string]clashCounter{}
		d.mu.Unlock()
		return nil
	}
	if d.address != spec.ClashAddress {
		d.address = spec.ClashAddress
		d.last = map[string]clashCounter{}
	}
	d.mu.Unlock()
	connections, err := d.fetch(ctx, spec.ClashAddress, spec.ClashSecret)
	if err != nil {
		return err
	}
	at := now.Unix()
	hour := at - at%connSecondsPerHour
	live := map[peerKey]struct{}{}
	seen := make(map[string]struct{}, len(connections))
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range connections {
		if c.ID == "" {
			continue
		}
		seen[c.ID] = struct{}{}
		prev, known := d.last[c.ID]
		current := clashCounter{up: max(c.Upload, 0), down: max(c.Download, 0)}
		d.last[c.ID] = current
		up, down := current.up, current.down
		if known {
			up, down = max(up-prev.up, 0), max(down-prev.down, 0)
		}
		_, tag, found := strings.Cut(c.Metadata.Type, "/")
		if !found || d.Peers == nil {
			continue
		}
		if ip, ok := normalizeConnSource(c.Metadata.SourceIP); ok {
			live[peerKey{tag: tag, addr: net.JoinHostPort(ip, c.Metadata.SourcePort)}] = struct{}{}
		}
		if up == 0 && down == 0 {
			continue
		}
		userID, nodeID, ok := d.Peers.IdentityFor(tag, c.Metadata.SourceIP, c.Metadata.SourcePort)
		if !ok {
			continue
		}
		domain, ok := domainOf(c.Metadata.Host, c.Metadata.DestinationIP)
		if !ok {
			continue
		}
		d.addLocked(domainKey{userID: userID, nodeID: nodeID, hour: hour, domain: domain}, up, down)
	}
	for id := range d.last {
		if _, present := seen[id]; !present {
			delete(d.last, id)
		}
	}
	if d.Peers != nil {
		d.mu.Unlock()
		d.Peers.RefreshPeers(live)
		d.mu.Lock()
	}
	return nil
}

func (d *DomainTraffic) addLocked(key domainKey, up, down int64) {
	value, found := d.keys[key]
	if !found && len(d.keys) >= maxDomainKeys {
		d.dropped++
		return
	}
	value.up = min(value.up+up, MaxSafeInteger/2)
	value.down = min(value.down+down, MaxSafeInteger/2)
	d.keys[key] = value
}

// Flush freezes the aggregates into batches and delivers the queue in order.
func (d *DomainTraffic) Flush(ctx context.Context, send DomainSender) error {
	if send == nil {
		return errors.New("domain traffic flush without a sender")
	}
	now := d.nowTime()
	d.mu.Lock()
	if d.probing {
		if now.Before(d.probeUntil) {
			d.mu.Unlock()
			return nil
		}
		d.probing = false
		d.probeUntil = time.Time{}
	}
	if d.delivering {
		d.mu.Unlock()
		return nil
	}
	if dropped := d.dropped; dropped > 0 {
		d.dropped = 0
		d.logf("domain traffic: dropped %d buckets above the %d-key limit", dropped, maxDomainKeys)
	}
	d.enqueueLocked()
	d.delivering = true
	queued := make([]DomainBatch, len(d.pending))
	copy(queued, d.pending)
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.delivering = false
		d.mu.Unlock()
	}()
	for _, batch := range queued {
		if err := send.DomainTraffic(ctx, batch); err != nil {
			if probeRefused(err) {
				d.enterProbe(err)
				return nil
			}
			if permanent(err) {
				d.remove(batch.BatchID)
				d.logf("domain traffic: discarded batch %s: %v", batch.BatchID, err)
				continue
			}
			return err
		}
		d.remove(batch.BatchID)
	}
	return nil
}

func (d *DomainTraffic) remove(batchID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.pending {
		if d.pending[i].BatchID == batchID {
			d.pending = append(d.pending[:i], d.pending[i+1:]...)
			return
		}
	}
}

func (d *DomainTraffic) enterProbe(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = map[domainKey]domainValue{}
	d.pending = nil
	d.dropped = 0
	d.probing = true
	d.probeUntil = d.nowTime().Add(connProbeInterval)
	d.logf("domain traffic: panel does not expose /api/node/v1/domain-traffic: %v; paused for %s", err, connProbeInterval)
}

func (d *DomainTraffic) enqueueLocked() {
	if len(d.keys) == 0 {
		return
	}
	records := make([]DomainRecord, 0, len(d.keys))
	for key, value := range d.keys {
		if value.up == 0 && value.down == 0 {
			continue
		}
		records = append(records, DomainRecord{UserID: key.userID, NodeID: key.nodeID, Hour: key.hour, Domain: key.domain, UploadBytes: value.up, DownloadBytes: value.down})
	}
	if len(records) == 0 {
		d.keys = map[domainKey]domainValue{}
		return
	}
	chunks := (len(records) + maxDomainBatchRecords - 1) / maxDomainBatchRecords
	ids := make([]string, chunks)
	for i := range ids {
		id := ""
		var err error
		if d.NewID != nil {
			id, err = d.NewID()
		} else {
			id, err = NewBatchID()
		}
		if err != nil {
			d.logf("domain traffic: cannot allocate batch id: %v", err)
			return
		}
		ids[i] = id
	}
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
		return a.Domain < b.Domain
	})
	d.keys = map[domainKey]domainValue{}
	for i, id := range ids {
		start := i * maxDomainBatchRecords
		end := min(start+maxDomainBatchRecords, len(records))
		d.pending = append(d.pending, DomainBatch{BatchID: id, Records: records[start:end]})
	}
	if evicted := len(d.pending) - maxDomainPending; evicted > 0 {
		d.pending = append([]DomainBatch(nil), d.pending[evicted:]...)
		d.logf("domain traffic: discarded %d oldest queued batches above the %d-batch limit", evicted, maxDomainPending)
	}
}
