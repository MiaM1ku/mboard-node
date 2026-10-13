package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const maxTrafficLabels = 10000
const maxJournalBytes = 32 << 20
const defaultSpoolLimit int64 = 256 << 20

var ErrTelemetryDisabled = errors.New("native config has no enabled per-user V2Ray telemetry")
var canonicalLabel = regexp.MustCompile(`^mb:u:([1-9][0-9]*):n:([1-9][0-9]*)(?::p:(.+))?$`)

// Only an explicit, matching accounting row can supply profile identity from a
// canonical suffix. Unmapped canonical stats names retain legacy accounting.
func mappedTrafficLabel(label TrafficLabel) (TrafficLabel, error) {
	if !validProfileID(label.ProfileID) {
		return label, errors.New("traffic label has invalid profile_id")
	}
	parts := canonicalLabel.FindStringSubmatch(label.Label)
	if parts == nil {
		return label, nil
	}
	uid, e1 := strconv.ParseInt(parts[1], 10, 64)
	nid, e2 := strconv.ParseInt(parts[2], 10, 64)
	if e1 != nil || e2 != nil || uid != label.UserID || nid != label.NodeID {
		return label, errors.New("canonical traffic label IDs disagree with mapping")
	}
	profile := parts[3]
	if profile == "0" {
		profile = ""
	}
	if !validProfileID(profile) {
		return label, errors.New("canonical traffic label has invalid profile suffix")
	}
	if label.ProfileID != "" && label.ProfileID != profile {
		return label, errors.New("canonical traffic label profile disagrees with mapping")
	}
	label.ProfileID = profile
	return label, nil
}

type TelemetrySpec struct {
	Address string
	Labels  map[string]TrafficLabel
}

func telemetrySpec(raw []byte, labels []TrafficLabel) (TelemetrySpec, error) {
	var native struct {
		Experimental struct {
			V2RayAPI struct {
				Listen string `json:"listen"`
				Stats  struct {
					Enabled bool     `json:"enabled"`
					Users   []string `json:"users"`
				} `json:"stats"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(raw, &native); err != nil {
		return TelemetrySpec{}, errors.New("invalid native telemetry config")
	}
	api := native.Experimental.V2RayAPI
	spec := TelemetrySpec{Address: api.Listen, Labels: map[string]TrafficLabel{}}
	if api.Listen == "" || !api.Stats.Enabled {
		if len(labels) > 0 {
			return spec, errors.New("traffic_labels requires enabled experimental.v2ray_api stats")
		}
		return TelemetrySpec{}, nil
	}
	host, port, err := net.SplitHostPort(api.Listen)
	ip := net.ParseIP(host)
	p, e := strconv.Atoi(port)
	if err != nil || e != nil || ip == nil || !ip.IsLoopback() || p < 1 || p > 65535 {
		return spec, errors.New("V2Ray stats listen must be a literal loopback IP with a valid port")
	}
	if len(labels) > maxTrafficLabels || len(api.Stats.Users) > maxTrafficLabels {
		return spec, errors.New("too many traffic labels (maximum 10000)")
	}
	supplied := map[string]TrafficLabel{}
	for _, label := range labels {
		if !validProfileID(label.ProfileID) {
			return spec, errors.New("traffic label has invalid profile_id")
		}
		if label.Label == "" || len(label.Label) > 512 || strings.ContainsRune(label.Label, 0) || label.UserID <= 0 || label.NodeID <= 0 || label.UserID > MaxSafeInteger || label.NodeID > MaxSafeInteger {
			return spec, errors.New("traffic label requires an opaque 1-512 byte label and safe positive user_id/node_id")
		}
		if _, found := supplied[label.Label]; found {
			return spec, errors.New("duplicate traffic label")
		}
		label, err = mappedTrafficLabel(label)
		if err != nil {
			return spec, err
		}
		supplied[label.Label] = label
	}
	for _, name := range api.Stats.Users {
		if name == "" || len(name) > 512 || strings.ContainsRune(name, 0) {
			return spec, errors.New("invalid stats user label")
		}
		if _, found := spec.Labels[name]; found {
			return spec, errors.New("duplicate stats user label")
		}
		label, found := supplied[name]
		if !found {
			parts := canonicalLabel.FindStringSubmatch(name)
			if parts == nil {
				return spec, errors.New("every opaque stats user requires a traffic_labels mapping")
			}
			uid, e1 := strconv.ParseInt(parts[1], 10, 64)
			nid, e2 := strconv.ParseInt(parts[2], 10, 64)
			if e1 != nil || e2 != nil || uid > MaxSafeInteger || nid > MaxSafeInteger {
				return spec, errors.New("unsafe IDs in stats user label")
			}
			label = TrafficLabel{Label: name, UserID: uid, NodeID: nid}
		}
		spec.Labels[name] = label
	}
	for name := range supplied {
		if _, found := spec.Labels[name]; !found {
			return spec, errors.New("traffic_labels entry is absent from stats.users")
		}
	}
	return spec, nil
}

// One atomic checkpoint is the write-ahead journal for cursors AND immutable
// batches. Pending batches are published before advancing another sample.
// At most 20k cursor values and three 4000-record pending batches are kept.
type CollectorJournal struct {
	Generation string           `json:"generation"`
	Cursors    map[string]int64 `json:"cursors"`
	Pending    []Batch          `json:"pending,omitempty"`
}
type Collector struct {
	Path            string
	Spool           Spool
	Reader          StatsReader
	Timeout         time.Duration
	SpoolLimit      int64
	Ready           atomic.Bool
	readyGeneration atomic.Pointer[string]
	// Fault injection in tests; production uses atomicWrite.
	writeCheckpoint func(string, []byte) error
}

func (c *Collector) load() (CollectorJournal, error) {
	j := CollectorJournal{Cursors: map[string]int64{}}
	info, err := os.Lstat(c.Path)
	if os.IsNotExist(err) {
		return j, nil
	}
	if err != nil {
		return j, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxJournalBytes {
		return j, errors.New("invalid collector journal file")
	}
	raw, err := os.ReadFile(c.Path)
	if err != nil {
		return j, err
	}
	if err = decodeStrict(bytes.NewReader(raw), &j); err != nil {
		return j, errors.New("invalid collector journal; restore it before collecting")
	}
	if j.Cursors == nil || len(j.Cursors) > 2*maxTrafficLabels || len(j.Pending) > 6 || len(j.Generation) > 128 {
		return j, errors.New("invalid collector journal bounds")
	}
	for key, value := range j.Cursors {
		if len(key) > 600 || value < 0 {
			return j, errors.New("invalid collector journal cursor")
		}
	}
	for _, b := range j.Pending {
		if err = b.Validate(); err != nil {
			return j, err
		}
	}
	return j, nil
}
func (c *Collector) commit(j CollectorJournal) error {
	raw, err := json.Marshal(j)
	if err != nil || len(raw) > maxJournalBytes {
		return errors.New("collector journal exceeds bound")
	}
	if c.writeCheckpoint != nil {
		return c.writeCheckpoint(c.Path, raw)
	}
	return atomicWrite(c.Path, raw)
}
func (c *Collector) publish(j *CollectorJournal) error {
	if len(j.Pending) == 0 {
		return nil
	}
	for _, b := range j.Pending {
		if err := c.Spool.Enqueue(b); err != nil {
			return err
		}
	}
	j.Pending = nil
	return c.commit(*j)
}
func (c *Collector) spoolCapacity() error {
	dir, err := os.Open(c.Spool.Dir)
	if os.IsNotExist(err) {
		dir = nil
	} else if err != nil {
		return err
	}
	if dir != nil {
		defer dir.Close()
	}
	var total int64
	count := 0
	if dir != nil {
		for {
			entries, e := dir.ReadDir(128)
			if e != nil && e != io.EOF {
				return e
			}
			for _, entry := range entries {
				count++
				if count >= 10000 {
					return errors.New("traffic spool entry limit reached; core counters retained")
				}
				if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
					continue
				}
				info, e := entry.Info()
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				total += info.Size()
			}
			if e == io.EOF {
				break
			}
		}
	}
	limit := c.SpoolLimit
	if limit == 0 {
		limit = defaultSpoolLimit
	}
	// Leave room for the next sample's batches; never discard already queued data.
	if total+int64(2*MaxBody) > limit {
		return errors.New("traffic spool capacity reached; core counters retained until panel recovers")
	}
	return nil
}

func (c *Collector) Recover() error {
	j, err := c.load()
	if err != nil {
		return err
	}
	return c.publish(&j)
}

// Poll must run under the Manager's lifecycle lock so a core generation cannot
// change between reading counters and committing them. It never resets gRPC.
func (c *Collector) Poll(ctx context.Context, spec TelemetrySpec, generation string) error {
	return c.poll(ctx, spec, generation, false)
}
func (c *Collector) Final(ctx context.Context, spec TelemetrySpec, generation string) error {
	return c.poll(ctx, spec, generation, true)
}
func (c *Collector) poll(ctx context.Context, spec TelemetrySpec, generation string, final bool) (err error) {
	c.Ready.Store(false)
	defer func() {
		if err == nil {
			c.readyGeneration.Store(&generation)
		}
		c.Ready.Store(err == nil)
	}()
	for _, label := range spec.Labels {
		if !validProfileID(label.ProfileID) {
			return errors.New("traffic label has invalid profile_id")
		}
	}
	j, err := c.load()
	if err != nil {
		return err
	}
	if !final {
		if err = c.publish(&j); err != nil {
			return err
		}
	}
	if spec.Address == "" {
		return ErrTelemetryDisabled
	}
	if generation == "" {
		return errors.New("core generation unavailable")
	}
	if !final {
		if err = c.spoolCapacity(); err != nil {
			return err
		}
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	values, err := c.Reader.Query(queryCtx, spec.Address)
	if err != nil {
		return err
	}
	if j.Generation != generation {
		j.Cursors = map[string]int64{}
		j.Generation = generation
	}
	next := CollectorJournal{Generation: generation, Cursors: map[string]int64{}}
	if final {
		next.Pending = j.Pending
	}
	type key struct {
		user, node int64
		profile    string
	}
	aggregates := map[key]Record{}
	seen := map[string]bool{}
	for _, counter := range values {
		if !strings.HasPrefix(counter.Name, "user>>>") {
			continue
		} // Never bill inbound/outbound totals.
		var labelName string
		upload := false
		if strings.HasSuffix(counter.Name, ">>>traffic>>>uplink") {
			labelName = strings.TrimSuffix(strings.TrimPrefix(counter.Name, "user>>>"), ">>>traffic>>>uplink")
			upload = true
		} else if strings.HasSuffix(counter.Name, ">>>traffic>>>downlink") {
			labelName = strings.TrimSuffix(strings.TrimPrefix(counter.Name, "user>>>"), ">>>traffic>>>downlink")
		} else {
			continue
		}
		label, known := spec.Labels[labelName]
		if !known {
			return errors.New("unmapped user counter returned by core; refusing partial accounting")
		}
		if seen[counter.Name] {
			return errors.New("duplicate user counter returned by core")
		}
		seen[counter.Name] = true
		if counter.Value < 0 {
			return errors.New("negative core counter (overflow or incompatible stats API)")
		}
		old := j.Cursors[counter.Name]
		// A decrease means a reset or wrap. The observed value is the only truthful
		// recoverable delta; bytes after the last poll and before reset are unknowable.
		delta := counter.Value - old
		if counter.Value < old {
			delta = counter.Value
		}
		next.Cursors[counter.Name] = counter.Value
		k := key{label.UserID, label.NodeID, label.ProfileID}
		record := aggregates[k]
		record.UserID = k.user
		record.NodeID = k.node
		record.ProfileID = k.profile
		if upload {
			if delta > MaxSafeInteger-record.UploadBytes {
				return errors.New("unsafe aggregated upload delta")
			}
			record.UploadBytes += delta
		} else {
			if delta > MaxSafeInteger-record.DownloadBytes {
				return errors.New("unsafe aggregated download delta")
			}
			record.DownloadBytes += delta
		}
		aggregates[k] = record
	}
	// A missing row isn't a zero. Keep its cursor for this core generation so a
	// transiently incomplete reply cannot charge the same cumulative bytes twice.
	for name, value := range j.Cursors {
		if _, found := next.Cursors[name]; found {
			continue
		}
		var labelName string
		if strings.HasSuffix(name, ">>>traffic>>>uplink") {
			labelName = strings.TrimSuffix(strings.TrimPrefix(name, "user>>>"), ">>>traffic>>>uplink")
		} else if strings.HasSuffix(name, ">>>traffic>>>downlink") {
			labelName = strings.TrimSuffix(strings.TrimPrefix(name, "user>>>"), ">>>traffic>>>downlink")
		}
		if _, known := spec.Labels[labelName]; known {
			next.Cursors[name] = value
		}
	}
	records := make([]Record, 0, len(aggregates))
	for _, record := range aggregates {
		if record.UploadBytes > 0 || record.DownloadBytes > 0 {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].UserID == records[j].UserID {
			if records[i].NodeID == records[j].NodeID {
				return records[i].ProfileID < records[j].ProfileID
			}
			return records[i].NodeID < records[j].NodeID
		}
		return records[i].UserID < records[j].UserID
	})
	for start := 0; start < len(records); start += 4000 {
		end := start + 4000
		if end > len(records) {
			end = len(records)
		}
		id, e := NewBatchID()
		if e != nil {
			return e
		}
		next.Pending = append(next.Pending, Batch{BatchID: id, Records: records[start:end]})
	}
	// Even a zero-delta sample can commit cursors, but never invents zero records.
	if len(next.Pending) > 6 {
		return errors.New("final collector checkpoint pending limit reached; publish pending batches first")
	}
	if err = c.commit(next); err != nil {
		return fmt.Errorf("commit collector checkpoint: %w", err)
	}
	if final {
		return nil
	}
	return c.publish(&next)
}
