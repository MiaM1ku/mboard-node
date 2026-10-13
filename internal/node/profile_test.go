package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProfileWireCompatibilityAndValidation(t *testing.T) {
	legacy := `{"batch_id":"legacy","records":[{"user_id":7,"node_id":21,"upload_bytes":11,"download_bytes":13}]}`
	b, err := ReadBatch(strings.NewReader(legacy))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil || string(raw) != legacy {
		t.Fatalf("legacy wire changed: %s %v", raw, err)
	}
	labelRaw, err := json.Marshal(TrafficLabel{Label: "mb:u:7:n:21:p:0", UserID: 7, NodeID: 21})
	if err != nil || string(labelRaw) != `{"label":"mb:u:7:n:21:p:0","user_id":7,"node_id":21}` {
		t.Fatalf("legacy label wire changed: %s %v", labelRaw, err)
	}
	for _, profile := range []string{"", "a", "00", "Profile-123", "d931ed25-42a5-4669-b518-c30c14d0b471", strings.Repeat("a", 64)} {
		t.Run("valid-"+profile, func(t *testing.T) {
			b.Records[0].ProfileID = profile
			if err := b.Validate(); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := ReadBatch(bytes.NewReader(raw))
			if err != nil || !reflect.DeepEqual(restored, b) {
				t.Fatalf("profile roundtrip: %+v %v", restored, err)
			}
		})
	}
	for _, profile := range []string{"0", "a_b", "a:b", "a/b", " a", "a ", "a\n", "a\x00", "é", strings.Repeat("a", 65)} {
		t.Run("invalid-"+profile, func(t *testing.T) {
			b.Records[0].ProfileID = profile
			if err := b.Validate(); err == nil {
				t.Fatal("invalid profile accepted")
			}
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadBatch(bytes.NewReader(raw)); err == nil {
				t.Fatal("invalid profile decoded")
			}
		})
	}
	for _, profileJSON := range []string{"42", "true", "[]", "{}"} {
		raw := `{"user_id":7,"node_id":21,"upload_bytes":1,"download_bytes":2,"profile_id":` + profileJSON + `}`
		var r Record
		if err := json.Unmarshal([]byte(raw), &r); err == nil {
			t.Fatalf("nonstring profile accepted: %s", profileJSON)
		}
	}
}

func TestProfileMetadataMappingIsExplicit(t *testing.T) {
	names := []string{"opaque>>>source", "mb:u:7:n:21:p:0", "mb:u:7:n:21:p:d931ed25-42a5-4669-b518-c30c14d0b471"}
	raw, err := json.Marshal(map[string]any{"experimental": map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:19090", "stats": map[string]any{"enabled": true, "users": names}}}})
	if err != nil {
		t.Fatal(err)
	}
	mapping := []TrafficLabel{{Label: names[0], UserID: 7, NodeID: 21, ProfileID: "Profile-A"}}
	spec, err := telemetrySpec(raw, mapping)
	if err != nil || spec.Labels[names[0]].ProfileID != "Profile-A" {
		t.Fatalf("explicit profile lost: %+v %v", spec, err)
	}
	for _, name := range names[1:] {
		if spec.Labels[name].ProfileID != "" {
			t.Fatalf("profile guessed from canonical label: %+v", spec.Labels[name])
		}
	}
	for _, profile := range []string{"0", "bad_profile", strings.Repeat("x", 65)} {
		mapping[0].ProfileID = profile
		if _, err := telemetrySpec(raw, mapping); err == nil {
			t.Fatalf("invalid mapping profile accepted: %q", profile)
		}
		c, s, spec := collectorFixture(t)
		label := spec.Labels["opaque>>>source"]
		label.ProfileID = profile
		spec.Labels[label.Label] = label
		s.counters = sample(label.Label, 10, 20)
		if err := c.Poll(context.Background(), spec, "g"); err == nil || s.requests != 0 {
			t.Fatal("invalid profile reached query/checkpoint")
		}
		if _, err := os.Stat(c.Path); !os.IsNotExist(err) {
			t.Fatalf("invalid profile persisted a journal: %v", err)
		}
	}
}

func TestCollectorProfilesSeparateAndSorted(t *testing.T) {
	c, s, spec := collectorFixture(t)
	spec.Labels = map[string]TrafficLabel{
		"default": {Label: "default", UserID: 7, NodeID: 21},
		"b":       {Label: "b", UserID: 7, NodeID: 21, ProfileID: "Profile-B"},
		"a":       {Label: "a", UserID: 7, NodeID: 21, ProfileID: "Profile-A"},
		"a-alias": {Label: "a-alias", UserID: 7, NodeID: 21, ProfileID: "Profile-A"},
	}
	s.counters = append(sample("b", 30, 40), sample("a", 10, 20)...)
	s.counters = append(s.counters, sample("default", 1, 2)...)
	s.counters = append(s.counters, sample("a-alias", 3, 4)...)
	s.counters = append(s.counters, Counter{"inbound>>>entry21>>>traffic>>>uplink", 9999}, Counter{"outbound>>>direct>>>traffic>>>downlink", 9999})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.Poll(ctx, spec, "g"); err != nil {
			t.Fatal(err)
		}
	}
	bs := batches(t, c.Spool)
	want := []Record{
		{UserID: 7, NodeID: 21, UploadBytes: 1, DownloadBytes: 2},
		{UserID: 7, NodeID: 21, UploadBytes: 13, DownloadBytes: 24, ProfileID: "Profile-A"},
		{UserID: 7, NodeID: 21, UploadBytes: 30, DownloadBytes: 40, ProfileID: "Profile-B"},
	}
	if len(bs) != 1 || !reflect.DeepEqual(bs[0].Records, want) {
		t.Fatalf("profile partition/sort changed: %+v", bs)
	}
	if up, down := totals(bs); up != 44 || down != 66 {
		t.Fatalf("global counters double counted: %d/%d", up, down)
	}
	j, err := c.load()
	if err != nil || len(j.Cursors) != 8 || len(j.Pending) != 0 {
		t.Fatalf("profile change altered counter cursors: %+v %v", j, err)
	}
}

func TestCollectorProfileMappingChangeKeepsPendingDimensionsAndCursor(t *testing.T) {
	c, s, spec := collectorFixture(t)
	label := spec.Labels["opaque>>>source"]
	label.ProfileID = "Profile-A"
	spec.Labels[label.Label] = label
	s.counters = sample(label.Label, 31, 47)
	c.writeCheckpoint = func(path string, raw []byte) error {
		if err := atomicWrite(path, raw); err != nil {
			return err
		}
		return errors.New("crash after durable checkpoint")
	}
	if err := c.Poll(context.Background(), spec, "g"); err == nil {
		t.Fatal("fault ignored")
	}
	j, err := c.load()
	if err != nil || len(j.Pending) != 1 || j.Pending[0].Records[0].ProfileID != "Profile-A" {
		t.Fatalf("profile not journaled: %+v %v", j, err)
	}
	pending := j.Pending[0]
	label.ProfileID = "Profile-B"
	spec.Labels[label.Label] = label
	s.counters = sample(label.Label, 36, 54)
	recovered := &Collector{Path: c.Path, Spool: c.Spool, Reader: s, Timeout: time.Second}
	if err := recovered.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	bs := batches(t, c.Spool)
	if len(bs) != 2 {
		t.Fatalf("recovery lost/merged partitions: %+v", bs)
	}
	var foundPending, foundNew bool
	for _, b := range bs {
		if b.BatchID == pending.BatchID {
			foundPending = reflect.DeepEqual(b, pending)
		} else {
			foundNew = reflect.DeepEqual(b.Records, []Record{{UserID: 7, NodeID: 21, UploadBytes: 5, DownloadBytes: 7, ProfileID: "Profile-B"}})
		}
	}
	if !foundPending || !foundNew {
		t.Fatalf("mapping rewrote old records or reset cursor: %+v", bs)
	}
	j, err = recovered.load()
	if err != nil || j.Cursors[sample(label.Label, 0, 0)[0].Name] != 36 || len(j.Pending) != 0 {
		t.Fatalf("cursor changed with profile: %+v %v", j, err)
	}
}

func TestCollectorProfileACKReplayPreservesPayload(t *testing.T) {
	c, s, spec := collectorFixture(t)
	label := spec.Labels["opaque>>>source"]
	label.ProfileID = "d931ed25-42a5-4669-b518-c30c14d0b471"
	spec.Labels[label.Label] = label
	s.counters = sample(label.Label, 17, 19)
	if err := c.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	want := batches(t, c.Spool)[0]
	attempts := 0
	var first []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received Batch
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(received, want) {
			t.Error("profile or batch ID changed on POST")
		}
		raw, _ := json.Marshal(received)
		if attempts == 0 {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Error("retry payload changed")
		}
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		reply(w, map[string]any{"accepted": true})
	}))
	defer server.Close()
	client, err := NewClient(testConfig(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Spool.Flush(context.Background(), client); err == nil {
		t.Fatal("uncertain ACK removed batch")
	}
	if err = c.Spool.Flush(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if err = c.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(batches(t, c.Spool)) != 0 {
		t.Fatal("profile traffic replayed after ACK")
	}
}

func TestTrustedCanonicalProfilesNeedNoMetadataRevision(t *testing.T) {
	profiles := []string{"", "d931ed25-42a5-4669-b518-c30c14d0b471", "f4663c5b-5591-4d7a-bec3-f4149068fb58"}
	var labels []TrafficLabel
	var names []string
	for _, profile := range profiles {
		suffix := profile
		if suffix == "" {
			suffix = "0"
		}
		name := "mb:u:7:n:21:p:" + suffix
		labels = append(labels, TrafficLabel{Label: name, UserID: 7, NodeID: 21})
		names = append(names, name)
	}
	raw, err := json.Marshal(map[string]any{"experimental": map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:19090", "stats": map[string]any{"enabled": true, "users": names}}}})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := telemetrySpec(raw, labels)
	if err != nil {
		t.Fatal(err)
	}
	c, s, _ := collectorFixture(t)
	for i, name := range names {
		if spec.Labels[name].ProfileID != profiles[i] || labels[i].ProfileID != "" {
			t.Fatalf("trusted canonical resolution changed source row: %+v", spec.Labels[name])
		}
		s.counters = append(s.counters, sample(name, 1, 2)...)
	}
	if err = c.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	bs := batches(t, c.Spool)
	if len(bs) != 1 || len(bs[0].Records) != 3 {
		t.Fatalf("canonical profile partitions merged: %+v", bs)
	}
	for i, record := range bs[0].Records {
		if record.ProfileID != profiles[i] || record.UploadBytes != 1 || record.DownloadBytes != 2 {
			t.Fatalf("wrong canonical partition: %+v", record)
		}
	}
	for _, bad := range []TrafficLabel{
		{Label: names[1], UserID: 8, NodeID: 21},
		{Label: names[1], UserID: 7, NodeID: 22},
		{Label: names[1], UserID: 7, NodeID: 21, ProfileID: profiles[2]},
		{Label: names[0], UserID: 7, NodeID: 21, ProfileID: profiles[1]},
		{Label: names[0], UserID: 7, NodeID: 21, ProfileID: "0"},
		{Label: "mb:u:7:n:21:p:bad_profile", UserID: 7, NodeID: 21},
	} {
		if _, err = telemetrySpec(nativeFor(bad.Label), []TrafficLabel{bad}); err == nil {
			t.Fatalf("ambiguous canonical mapping accepted: %+v", bad)
		}
	}
	labels[1].ProfileID = profiles[1]
	if _, err = telemetrySpec(raw, labels); err != nil {
		t.Fatalf("matching explicit canonical profile rejected: %v", err)
	}
}

func TestProfileConfigWireAndManagerPersistence(t *testing.T) {
	remote := RemoteConfig{Revision: 9, Config: nativeFor("opaque-source"), TrafficLabels: []TrafficLabel{{Label: "opaque-source", UserID: 7, NodeID: 21, ProfileID: "Profile-A"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/node/v1/config" {
			t.Error("unexpected config request")
		}
		reply(w, remote)
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	received, err := client.Config(context.Background())
	if err != nil || !reflect.DeepEqual(received, remote) {
		t.Fatalf("profile config wire changed: %+v %v", received, err)
	}
	core := &fakeCore{}
	manager, err := NewManager(cfg, core)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Apply(context.Background(), received); err != nil {
		t.Fatal(err)
	}
	restored, err := NewManager(cfg, core)
	if err != nil || !reflect.DeepEqual(restored.spec, manager.spec) || restored.spec.Labels["opaque-source"].ProfileID != "Profile-A" {
		t.Fatalf("profile mapping not durable: %v", err)
	}
	for _, profile := range []string{"Profile-B", "bad_profile", "0"} {
		changed := received
		changed.TrafficLabels = []TrafficLabel{{Label: "opaque-source", UserID: 7, NodeID: 21, ProfileID: profile}}
		if err = manager.Apply(context.Background(), changed); err == nil || core.restarts != 1 {
			t.Fatal("invalid/same-revision profile change touched core")
		}
	}
}

func TestLegacySpoolAndJournalUpgradeRecovery(t *testing.T) {
	c, s, spec := collectorFixture(t)
	legacyBatch := `{"batch_id":"old-0-2-0","records":[{"user_id":7,"node_id":21,"upload_bytes":11,"download_bytes":13}]}`
	journal := `{"generation":"g","cursors":{"user>>>opaque>>>source>>>traffic>>>uplink":11,"user>>>opaque>>>source>>>traffic>>>downlink":13},"pending":[` + legacyBatch + `]}`
	if err := atomicWrite(c.Path, []byte(journal)); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(c.Spool.Dir+"/old-0-2-0.json", []byte(legacyBatch)); err != nil {
		t.Fatal(err)
	}
	s.counters = sample("opaque>>>source", 11, 13)
	if err := c.Poll(context.Background(), spec, "g"); err != nil {
		t.Fatal(err)
	}
	bs := batches(t, c.Spool)
	if len(bs) != 1 || bs[0].BatchID != "old-0-2-0" || bs[0].Records[0].ProfileID != "" {
		t.Fatalf("old journal recovery replayed bytes: %+v", bs)
	}
	raw, err := os.ReadFile(c.Spool.Dir + "/old-0-2-0.json")
	if err != nil || string(raw) != legacyBatch {
		t.Fatalf("old immutable spool rewritten: %s %v", raw, err)
	}
}
