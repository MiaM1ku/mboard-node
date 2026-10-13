// Package certificate implements an independent, one-shot certificate exporter.
// It is deliberately not imported by the node agent.
package certificate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Config is read from a root-owned 0600 JSON file, never from command arguments.
type Config struct {
	Domain          string `json:"domain"`
	Email           string `json:"email"`
	DNSProvider     string `json:"dns_provider"`
	DNSAPIToken     string `json:"dns_api_token"`
	StoragePath     string `json:"storage_path"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	RenewBeforeDays int    `json:"renew_before_days"`
	RestartService  string `json:"restart_service"`
}

// Result contains only safe, bounded information. Raw underlying errors are
// intentionally never returned to the CLI, since provider errors can contain secrets.
type Result struct {
	Domain    string `json:"domain"`
	Expiry    string `json:"expiry"`
	Status    string `json:"status"`
	Renewed   bool   `json:"renewed"`
	Restarted bool   `json:"restarted"`
}

type pair struct{ cert, key []byte }
type runner struct {
	uid     int
	now     func() time.Time
	renew   func(context.Context, Config) (pair, error)
	restart func(context.Context) error
	// Hooks make disk/restart failure handling testable without ACME or systemd.
	stage  func(string, []byte) (string, error)
	rename func(string, string) error
	roots  *x509.CertPool
}

func production() runner {
	return runner{uid: 0, now: time.Now, renew: renewACME, restart: restartService,
		stage: stageFile, rename: os.Rename}
}

// Run requires root and validates local files before doing anything networked.
// check always returns after local validation, without ACME or a service restart.
func Run(ctx context.Context, configPath string, check bool) (Result, error) {
	if os.Geteuid() != 0 {
		return failed(Result{}, "root_required")
	}
	// This is a standalone one-shot API: umask is process-global, so Run must
	// not be embedded in an agent or called concurrently within one process.
	restoreMask := privateUmask()
	defer restoreMask()
	r := production()
	cfg, err := r.loadConfig(configPath)
	if err != nil {
		return failed(Result{}, "invalid_config")
	}
	return r.run(ctx, cfg, check)
}

func privateUmask() func() {
	previous := syscall.Umask(0077)
	return func() { syscall.Umask(previous) }
}

func failed(res Result, status string) (Result, error) {
	res.Status = status
	return res, errors.New(status)
}

var domainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (r runner) loadConfig(path string) (Config, error) {
	var c Config
	b, err := r.readPrivate(path, true)
	if err != nil || len(b) > 65536 {
		return c, errors.New("invalid_config")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("invalid_config")
	}
	if c.validate() != nil {
		return Config{}, errors.New("invalid_config")
	}
	return c, nil
}

func (c Config) validate() error {
	if len(c.Domain) > 253 || !domainRE.MatchString(c.Domain) || net.ParseIP(c.Domain) != nil {
		return errors.New("domain")
	}
	a, err := mail.ParseAddress(c.Email)
	if err != nil || a.Address != c.Email || a.Name != "" {
		return errors.New("email")
	}
	if c.DNSProvider != "cloudflare" || strings.TrimSpace(c.DNSAPIToken) == "" {
		return errors.New("provider")
	}
	if c.RenewBeforeDays < 1 || c.RenewBeforeDays > 90 || c.RestartService != "mboard-node" {
		return errors.New("policy")
	}
	for _, p := range []string{c.StoragePath, c.CertificatePath, c.PrivateKeyPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return errors.New("path")
		}
	}
	if c.CertificatePath == c.PrivateKeyPath || filepath.Dir(c.CertificatePath) != filepath.Dir(c.PrivateKeyPath) {
		return errors.New("pair_paths")
	}
	// ACME storage must not be the deployed TLS directory (or any ancestor of it).
	tlsDir := filepath.Dir(c.CertificatePath)
	if tlsDir == c.StoragePath || strings.HasPrefix(tlsDir, c.StoragePath+string(os.PathSeparator)) {
		return errors.New("storage_separation")
	}
	return nil
}

// noSymlinks checks every existing component, not just the final filename.
func noSymlinks(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path")
	}
	p := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(path, p), p) {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe_path")
		}
	}
	return nil
}

// secureParents rejects untrusted mutable ancestors. A root-owned sticky
// directory (such as /tmp during local tests) is safe only above a private directory.
func (r runner) secureParents(path string) error {
	if noSymlinks(path) != nil {
		return errors.New("unsafe_path")
	}
	p := string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), p), p)
	for _, part := range parts {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !fi.IsDir() {
			return errors.New("unsafe_parent")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || (int(st.Uid) != r.uid && st.Uid != 0) {
			return errors.New("unsafe_parent")
		}
		if fi.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && fi.Mode()&os.ModeSticky != 0 && p != filepath.Dir(path)) {
			return errors.New("unsafe_parent")
		}
	}
	return nil
}

func (r runner) readPrivate(path string, secret bool) ([]byte, error) {
	if r.secureParents(path) != nil {
		return nil, errors.New("unsafe_path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("unreadable_file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("unsafe_file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != r.uid || st.Nlink != 1 || fi.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe_file")
	}
	if secret && fi.Mode().Perm() != 0600 {
		return nil, errors.New("private_mode_required")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil || len(b) == 1<<20 {
		return nil, errors.New("file_read_failed")
	}
	return b, nil
}

func (r runner) prepareStorage(path string, create bool) error {
	if r.secureParents(path) != nil {
		return errors.New("unsafe_storage")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil
		}
		if os.MkdirAll(path, 0700) != nil {
			return errors.New("storage_create_failed")
		}
	}
	return filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe_storage")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != r.uid {
			return errors.New("unsafe_storage")
		}
		if fi.IsDir() {
			if fi.Mode().Perm() != 0700 {
				return errors.New("storage_mode_required")
			}
		} else {
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || st.Nlink != 1 {
				return errors.New("storage_mode_required")
			}
		}
		return nil
	})
}

func validatePair(p pair, domain string, now time.Time, roots *x509.CertPool, replacement bool) (*x509.Certificate, error) {
	kp, err := tls.X509KeyPair(p.cert, p.key)
	if err != nil || len(kp.Certificate) == 0 {
		return nil, errors.New("invalid_pair")
	}
	certs := make([]*x509.Certificate, len(kp.Certificate))
	for i, der := range kp.Certificate {
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("invalid_chain")
		}
	}
	leaf := certs[0]
	if leaf.VerifyHostname(domain) != nil || now.Before(leaf.NotBefore) {
		return nil, errors.New("invalid_domain_or_time")
	}
	for i := 0; i+1 < len(certs); i++ {
		if certs[i].CheckSignatureFrom(certs[i+1]) != nil {
			return nil, errors.New("invalid_chain")
		}
	}
	if replacement {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		if _, err = leaf.Verify(x509.VerifyOptions{DNSName: domain, CurrentTime: now, Roots: roots, Intermediates: intermediates}); err != nil {
			return nil, errors.New("untrusted_new_chain")
		}
	}
	// An expired existing pair is allowed: it needs recovery, not a local abort.
	return leaf, nil
}

func (r runner) current(c Config) (pair, error) {
	crt, err := r.readPrivate(c.CertificatePath, false)
	if err != nil {
		return pair{}, err
	}
	key, err := r.readPrivate(c.PrivateKeyPath, true)
	if err != nil {
		return pair{}, err
	}
	return pair{crt, key}, nil
}

func (r runner) run(ctx context.Context, c Config, check bool) (Result, error) {
	res := Result{Domain: c.Domain}
	if c.validate() != nil {
		return failed(Result{}, "invalid_config")
	}
	if r.prepareStorage(c.StoragePath, !check) != nil {
		return failed(res, "unsafe_storage")
	}
	var lock *os.File
	if !check {
		var err error
		lock, err = r.lock(c.StoragePath)
		if err != nil {
			return failed(res, "locked_or_unsafe_lock")
		}
		defer lock.Close() // flock is released on close, including abnormal process exit.
	}
	old, err := r.current(c)
	if err != nil {
		return failed(res, "unsafe_current_pair")
	}
	now := r.now()
	leaf, err := validatePair(old, c.Domain, now, r.roots, false)
	if err != nil {
		return failed(res, "invalid_current_pair")
	}
	res.Expiry = leaf.NotAfter.UTC().Format(time.RFC3339)
	threshold := now.Add(time.Duration(c.RenewBeforeDays) * 24 * time.Hour)
	if leaf.NotAfter.After(threshold) {
		res.Status = "valid"
		return res, nil
	}
	if check {
		res.Status = "renewal_pending"
		return res, nil
	}
	next, err := r.renew(ctx, c)
	if err != nil {
		return failed(res, "renewal_failed")
	}
	fresh, err := validatePair(next, c.Domain, now, r.roots, true)
	if err != nil || !fresh.NotAfter.After(threshold) || !fresh.NotAfter.After(leaf.NotAfter) {
		return failed(res, "invalid_renewed_pair")
	}
	if bytes.Equal(next.cert, old.cert) && bytes.Equal(next.key, old.key) {
		res.Status = "unchanged"
		return res, nil
	}
	if r.prepareStorage(c.StoragePath, false) != nil {
		return failed(res, "unsafe_storage")
	}
	status, err := r.replace(ctx, c, old, next)
	if err != nil {
		return failed(res, status)
	}
	res.Expiry = fresh.NotAfter.UTC().Format(time.RFC3339)
	res.Status = "renewed"
	res.Renewed = true
	res.Restarted = true
	return res, nil
}

func (r runner) lock(dir string) (*os.File, error) {
	p := filepath.Join(dir, "renew.lock")
	if noSymlinks(p) != nil {
		return nil, errors.New("unsafe_lock")
	}
	fd, err := syscall.Open(p, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("unsafe_lock")
	}
	f := os.NewFile(uintptr(fd), p)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, errors.New("unsafe_lock")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || int(st.Uid) != r.uid || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("unsafe_lock")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("locked")
	}
	return f, nil
}

func stageFile(path string, data []byte) (string, error) {
	if noSymlinks(filepath.Dir(path)) != nil {
		return "", errors.New("unsafe_path")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mboard-cert-stage-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if f.Chmod(0600) != nil {
		return "", errors.New("chmod_failed")
	}
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Both files are staged and fsynced before either rename. POSIX cannot rename
// two regular files atomically as a pair; the running service keeps its loaded
// pair until the single restart. A private durable backup is retained for recovery.
func (r runner) replace(ctx context.Context, c Config, old, next pair) (string, error) {
	backup, err := os.MkdirTemp(c.StoragePath, "backup-")
	if err != nil {
		return "backup_failed", err
	}
	// Backups intentionally remain private, including after success.
	for _, entry := range []struct {
		name string
		data []byte
	}{{"certificate.crt", old.cert}, {"private.key", old.key}} {
		path := filepath.Join(backup, entry.name)
		staged, err := r.stage(path, entry.data)
		if err != nil {
			return "backup_failed", err
		}
		if err = r.rename(staged, path); err != nil {
			os.Remove(staged)
			return "backup_failed", err
		}
	}
	if syncDir(backup) != nil || syncDir(c.StoragePath) != nil {
		return "backup_failed", errors.New("sync_failed")
	}
	certStage, err := r.stage(c.CertificatePath, next.cert)
	if err != nil {
		return "staging_failed", err
	}
	defer os.Remove(certStage)
	keyStage, err := r.stage(c.PrivateKeyPath, next.key)
	if err != nil {
		return "staging_failed", err
	}
	defer os.Remove(keyStage)
	// Recheck live paths immediately before replacement.
	actual, err := r.current(c)
	if err != nil || !bytes.Equal(actual.cert, old.cert) || !bytes.Equal(actual.key, old.key) {
		return "current_pair_changed", errors.New("changed")
	}
	if err = r.rename(certStage, c.CertificatePath); err != nil {
		return "replacement_failed", err
	}
	if err = r.rename(keyStage, c.PrivateKeyPath); err != nil {
		if r.restore(c, old) != nil {
			return "rollback_failed", errors.New("rollback_failed")
		}
		return "replacement_failed_rolled_back", err
	}
	if err = syncDir(filepath.Dir(c.CertificatePath)); err != nil {
		if r.restore(c, old) != nil {
			return "rollback_failed", errors.New("rollback_failed")
		}
		return "replacement_failed_rolled_back", err
	}
	if err = r.restart(ctx); err != nil {
		if r.restore(c, old) != nil {
			return "rollback_failed", errors.New("rollback_failed")
		}
		// Recovery must not inherit an expired ACME/command context.
		recovery, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if r.restart(recovery) != nil {
			return "restart_failed_rolled_back_recovery_failed", errors.New("recovery_failed")
		}
		return "restart_failed_rolled_back", err
	}
	return "renewed", nil
}

func (r runner) restore(c Config, old pair) error {
	crt, err := r.stage(c.CertificatePath, old.cert)
	if err != nil {
		return err
	}
	defer os.Remove(crt)
	key, err := r.stage(c.PrivateKeyPath, old.key)
	if err != nil {
		return err
	}
	defer os.Remove(key)
	if noSymlinks(c.CertificatePath) != nil || noSymlinks(c.PrivateKeyPath) != nil {
		return errors.New("unsafe_restore")
	}
	if r.rename(crt, c.CertificatePath) != nil || r.rename(key, c.PrivateKeyPath) != nil {
		return errors.New("restore_failed")
	}
	return syncDir(filepath.Dir(c.CertificatePath))
}

func restartService(ctx context.Context) error {
	restartCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// Fixed executable and arguments; no shell, no user-supplied service name.
	cmd := exec.CommandContext(restartCtx, "/bin/systemctl", "restart", "mboard-node.service")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
