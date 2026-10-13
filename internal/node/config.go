package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Version = "0.2.1"
const MaxBody = 1 << 20
const MaxSafeInteger int64 = 9007199254740991

type Config struct {
	PanelURL               string `json:"panel_url"`
	Token                  string `json:"token"`
	ConfigPath             string `json:"config_path"`
	CoreBinary             string `json:"core_binary"`
	DataDir                string `json:"data_dir"`
	Interval               string `json:"interval"`
	RequestTimeout         string `json:"request_timeout"`
	TelemetryInterval      string `json:"telemetry_interval,omitempty"`
	TelemetryTimeout       string `json:"telemetry_timeout,omitempty"`
	TelemetrySpoolMaxBytes int64  `json:"telemetry_spool_max_bytes,omitempty"`
	TLSCAPath              string `json:"tls_ca_path"`
	TLSCertPath            string `json:"tls_cert_path"`
	TLSKeyPath             string `json:"tls_key_path"`
}

func LoadConfig(path string) (Config, error) {
	c := Config{ConfigPath: "/etc/mboard-node/sing-box.json", CoreBinary: "/usr/local/bin/sing-box", DataDir: "/var/lib/mboard-node", Interval: "30s", RequestTimeout: "15s", TelemetryInterval: "5s", TelemetryTimeout: "5s"}
	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("open agent config: %w", err)
	}
	defer f.Close()
	if err = decodeStrict(io.LimitReader(f, MaxBody+1), &c); err != nil {
		return c, errors.New("invalid agent config JSON")
	}
	vars := map[string]*string{"PANEL_URL": &c.PanelURL, "TOKEN": &c.Token, "CONFIG_PATH": &c.ConfigPath, "CORE_BINARY": &c.CoreBinary, "DATA_DIR": &c.DataDir, "INTERVAL": &c.Interval, "REQUEST_TIMEOUT": &c.RequestTimeout, "TELEMETRY_INTERVAL": &c.TelemetryInterval, "TELEMETRY_TIMEOUT": &c.TelemetryTimeout, "TLS_CA_PATH": &c.TLSCAPath, "TLS_CERT_PATH": &c.TLSCertPath, "TLS_KEY_PATH": &c.TLSKeyPath}
	for key, dst := range vars {
		if v, ok := os.LookupEnv("MBOARD_NODE_" + key); ok {
			*dst = v
		}
	}
	if value, ok := os.LookupEnv("MBOARD_NODE_TELEMETRY_SPOOL_MAX_BYTES"); ok {
		budget, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return c, errors.New("invalid telemetry spool byte budget")
		}
		c.TelemetrySpoolMaxBytes = budget
	}
	if c.managesPath(path) {
		return c, errors.New("agent config collides with a managed config, state, lock or spool path")
	}
	return c, c.Validate()
}

func pathIdentity(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(absolute)); err == nil {
		return filepath.Join(parent, filepath.Base(absolute))
	}
	return absolute
}

func (c Config) managesPath(path string) bool {
	input := pathIdentity(path)
	for _, output := range []string{c.ConfigPath, filepath.Join(c.DataDir, "state.json"), filepath.Join(c.DataDir, "collector.json"), filepath.Join(c.DataDir, "agent.lock")} {
		if input == pathIdentity(output) {
			return true
		}
	}
	spool := pathIdentity(filepath.Join(c.DataDir, "spool"))
	return input == spool || strings.HasPrefix(input, spool+string(filepath.Separator))
}

func (c Config) Validate() error {
	u, err := url.Parse(c.PanelURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("panel_url must be an HTTP(S) origin without credentials, query, or path")
	}
	if len(c.Token) < 16 || len(c.Token) > 4096 || strings.ContainsAny(c.Token, "\r\n \t") {
		return errors.New("token must contain 16-4096 non-whitespace characters")
	}
	for name, p := range map[string]string{"config_path": c.ConfigPath, "core_binary": c.CoreBinary, "data_dir": c.DataDir} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	if pathIdentity(c.DataDir) == string(filepath.Separator) {
		return errors.New("data_dir cannot be the filesystem root")
	}
	for _, protected := range []string{c.CoreBinary, c.TLSCAPath, c.TLSCertPath, c.TLSKeyPath} {
		if protected != "" && c.managesPath(protected) {
			return errors.New("core or TLS input collides with a managed config, state, lock or spool path")
		}
	}
	live := pathIdentity(c.ConfigPath)
	for _, output := range []string{filepath.Join(c.DataDir, "state.json"), filepath.Join(c.DataDir, "collector.json"), filepath.Join(c.DataDir, "agent.lock")} {
		if live == pathIdentity(output) {
			return errors.New("config_path collides with agent metadata")
		}
	}
	spool := pathIdentity(filepath.Join(c.DataDir, "spool"))
	if live == spool || strings.HasPrefix(live, spool+string(filepath.Separator)) {
		return errors.New("config_path cannot be inside the traffic spool")
	}
	for name, value := range map[string]string{"interval": c.Interval, "request_timeout": c.RequestTimeout} {
		d, e := time.ParseDuration(value)
		if e != nil || d < time.Second || d > time.Hour {
			return fmt.Errorf("%s must be between 1s and 1h", name)
		}
	}
	if c.TelemetrySpoolMaxBytes != 0 && (c.TelemetrySpoolMaxBytes < 4<<20 || c.TelemetrySpoolMaxBytes > 16<<30) {
		return errors.New("telemetry_spool_max_bytes must be 0 (256MiB default) or 4MiB..16GiB")
	}
	for name, value := range map[string]string{"telemetry_interval": c.TelemetryInterval, "telemetry_timeout": c.TelemetryTimeout} {
		if value == "" {
			continue
		}
		d, e := time.ParseDuration(value)
		if e != nil || d < time.Second || d > time.Hour {
			return fmt.Errorf("%s must be between 1s and 1h", name)
		}
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return errors.New("tls_cert_path and tls_key_path must be set together")
	}
	for _, p := range []string{c.TLSCAPath, c.TLSCertPath, c.TLSKeyPath} {
		if p != "" && !filepath.IsAbs(p) {
			return errors.New("TLS paths must be absolute")
		}
	}
	return nil
}

func decodeStrict(r io.Reader, v any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

type Record struct {
	UserID        int64  `json:"user_id"`
	NodeID        int64  `json:"node_id"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	ProfileID     string `json:"profile_id,omitempty"`
}

// Empty identifies legacy/default traffic. "0" is the reserved default label
// suffix, not a profile ID. Profile identity comes only from explicit metadata.
func validProfileID(id string) bool {
	if id == "" {
		return true
	}
	if id == "0" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (r *Record) UnmarshalJSON(raw []byte) error {
	var input struct {
		UserID        *int64 `json:"user_id"`
		NodeID        *int64 `json:"node_id"`
		UploadBytes   *int64 `json:"upload_bytes"`
		DownloadBytes *int64 `json:"download_bytes"`
		ProfileID     string `json:"profile_id,omitempty"`
	}
	if err := decodeStrict(strings.NewReader(string(raw)), &input); err != nil {
		return err
	}
	if input.UserID == nil || input.NodeID == nil || input.UploadBytes == nil || input.DownloadBytes == nil {
		return errors.New("record requires explicit user_id, node_id, upload_bytes and download_bytes")
	}
	if !validProfileID(input.ProfileID) {
		return errors.New("profile_id must be empty or 1-64 letters, digits or hyphens, excluding reserved 0")
	}
	*r = Record{UserID: *input.UserID, NodeID: *input.NodeID, UploadBytes: *input.UploadBytes, DownloadBytes: *input.DownloadBytes, ProfileID: input.ProfileID}
	return nil
}

type Batch struct {
	BatchID string   `json:"batch_id"`
	Records []Record `json:"records"`
}

func (b Batch) Validate() error {
	if len(b.BatchID) < 1 || len(b.BatchID) > 128 {
		return errors.New("batch_id must be 1-128 safe filename characters")
	}
	for _, r := range b.BatchID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return errors.New("batch_id must use letters, digits, hyphen or underscore")
		}
	}
	if len(b.Records) == 0 || len(b.Records) > 10000 {
		return errors.New("records must contain 1-10000 entries")
	}
	for i, r := range b.Records {
		if !validProfileID(r.ProfileID) {
			return errors.New("record " + strconv.Itoa(i) + " has invalid profile_id")
		}
		if r.UserID <= 0 || r.NodeID <= 0 || r.UserID > MaxSafeInteger || r.NodeID > MaxSafeInteger || r.UploadBytes < 0 || r.DownloadBytes < 0 || r.UploadBytes > MaxSafeInteger || r.DownloadBytes > MaxSafeInteger {
			return errors.New("record " + strconv.Itoa(i) + " has invalid IDs or unsafe byte counters")
		}
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxBody {
		return errors.New("batch exceeds 1 MiB")
	}
	return nil
}
