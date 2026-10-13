package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	http          *http.Client
	origin, token string
}
type TrafficLabel struct {
	Label  string `json:"label"`
	UserID int64  `json:"user_id"`
	NodeID int64  `json:"node_id"`
}

// SharedConfig keeps the complete native core JSON separate from accounting metadata.
// Unknown envelope fields are tolerated for forward-compatible panel additions.
type SharedConfig struct {
	Revision      int64           `json:"revision"`
	Config        json.RawMessage `json:"config"`
	TrafficLabels []TrafficLabel  `json:"traffic_labels,omitempty"`
}
type RemoteConfig = SharedConfig
type Heartbeat struct {
	Version        string `json:"version"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	ConfigRevision int64  `json:"config_revision"`
	CoreReady      *bool  `json:"core_ready,omitempty"`
	TelemetryReady *bool  `json:"telemetry_ready,omitempty"`
}
type HeartbeatReply struct {
	ServerTime     string `json:"server_time"`
	ConfigRevision int64  `json:"config_revision"`
}

func NewClient(c Config) (*Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSCAPath != "" {
		pem, err := os.ReadFile(c.TLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("load panel CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("panel CA file has no certificates")
		}
		tc.RootCAs = pool
	}
	if c.TLSCertPath != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCertPath, c.TLSKeyPath)
		if err != nil {
			return nil, errors.New("load panel client certificate/key failed")
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	timeout, _ := time.ParseDuration(c.RequestTimeout)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &Client{http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("panel redirects are disabled") }}, origin: strings.TrimRight(c.PanelURL, "/"), token: c.Token}, nil
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errors.New("encode request failed")
		}
		if len(raw) > MaxBody {
			return errors.New("request exceeds 1 MiB")
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, reader)
	if err != nil {
		return errors.New("create panel request failed")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("panel request failed (transport or timeout)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("panel returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil || len(raw) > MaxBody {
		return errors.New("invalid or oversized panel response")
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal(raw, &envelope); err != nil || len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) {
		return errors.New("panel response missing data")
	}
	if err = json.Unmarshal(envelope.Data, out); err != nil {
		return errors.New("invalid panel data")
	}
	return nil
}
func (c *Client) Heartbeat(ctx context.Context, h Heartbeat) (HeartbeatReply, error) {
	var wire struct {
		ServerTime     string `json:"server_time"`
		ConfigRevision *int64 `json:"config_revision"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/node/v1/heartbeat", h, &wire); err != nil {
		return HeartbeatReply{}, err
	}
	if wire.ConfigRevision == nil || *wire.ConfigRevision < 0 || *wire.ConfigRevision > MaxSafeInteger {
		return HeartbeatReply{}, errors.New("invalid heartbeat revision")
	}
	if _, err := time.Parse(time.RFC3339Nano, wire.ServerTime); err != nil {
		return HeartbeatReply{}, errors.New("invalid heartbeat server_time")
	}
	return HeartbeatReply{ServerTime: wire.ServerTime, ConfigRevision: *wire.ConfigRevision}, nil
}
func (c *Client) Config(ctx context.Context) (RemoteConfig, error) {
	var wire struct {
		Revision      *int64          `json:"revision"`
		Config        json.RawMessage `json:"config"`
		TrafficLabels []TrafficLabel  `json:"traffic_labels"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/node/v1/config", nil, &wire); err != nil {
		return RemoteConfig{}, err
	}
	if wire.Revision == nil || *wire.Revision < 0 || *wire.Revision > MaxSafeInteger {
		return RemoteConfig{}, errors.New("invalid config revision")
	}
	return RemoteConfig{Revision: *wire.Revision, Config: wire.Config, TrafficLabels: wire.TrafficLabels}, nil
}
func (c *Client) Traffic(ctx context.Context, b Batch) error {
	if err := b.Validate(); err != nil {
		return err
	}
	var out struct {
		Accepted bool `json:"accepted"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/node/v1/traffic", b, &out); err != nil {
		return err
	}
	if !out.Accepted {
		return errors.New("panel did not acknowledge batch")
	}
	return nil
}
