package certificate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	cfg              Config
	r                runner
	old, next        pair
	now              time.Time
	ca               *x509.Certificate
	caKey            *ecdsa.PrivateKey
	renews, restarts int
}

func issue(t *testing.T, domain string, now, expiry time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey) pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pair{append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func newFixture(t *testing.T, days int) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic test CA"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := &fixture{now: now, ca: ca, caKey: caKey}
	f.cfg = Config{Domain: "node.example.com", Email: "acme@example.com", DNSProvider: "cloudflare", DNSAPIToken: "PRIVATE_TEST_TOKEN_NEVER_PRINT", StoragePath: filepath.Join(dir, "storage"), CertificatePath: filepath.Join(dir, "180.crt"), PrivateKeyPath: filepath.Join(dir, "180.key"), RenewBeforeDays: 30, RestartService: "mboard-node"}
	f.old = issue(t, f.cfg.Domain, now, now.Add(time.Duration(days)*24*time.Hour), ca, caKey)
	f.next = issue(t, f.cfg.Domain, now, now.Add(90*24*time.Hour), ca, caKey)
	f.r = runner{uid: os.Getuid(), now: func() time.Time { return now }, roots: roots, stage: stageFile, rename: os.Rename,
		renew:   func(context.Context, Config) (pair, error) { f.renews++; return f.next, nil },
		restart: func(context.Context) error { f.restarts++; return nil }}
	writePair(t, f.cfg, f.old)
	return f
}

func writePair(t *testing.T, c Config, p pair) {
	t.Helper()
	for _, v := range []struct {
		path string
		data []byte
	}{{c.CertificatePath, p.cert}, {c.PrivateKeyPath, p.key}} {
		if err := os.WriteFile(v.path, v.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func assertOld(t *testing.T, f *fixture) {
	t.Helper()
	actual, err := f.r.current(f.cfg)
	if err != nil || !bytes.Equal(actual.cert, f.old.cert) || !bytes.Equal(actual.key, f.old.key) {
		t.Fatal("old pair was not retained/restored")
	}
}
func runFixture(f *fixture, check bool) (Result, error) {
	return f.r.run(context.Background(), f.cfg, check)
}

func TestLongValidNoNetworkOrRestart(t *testing.T) {
	f := newFixture(t, 90)
	res, err := runFixture(f, false)
	if err != nil || res.Status != "valid" || res.Renewed || res.Restarted || f.renews != 0 || f.restarts != 0 {
		t.Fatalf("%+v %v calls %d/%d", res, err, f.renews, f.restarts)
	}
	assertOld(t, f)
}
func TestCheckPendingNoNetworkOrMutation(t *testing.T) {
	f := newFixture(t, 7)
	res, err := runFixture(f, true)
	if err != nil || res.Status != "renewal_pending" || f.renews != 0 || f.restarts != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(f.cfg.StoragePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("check created storage")
	}
	assertOld(t, f)
}
func TestCheckLongValid(t *testing.T) {
	f := newFixture(t, 90)
	res, err := runFixture(f, true)
	if err != nil || res.Status != "valid" || f.renews != 0 || f.restarts != 0 {
		t.Fatal(res, err)
	}
}
func TestNearExpiryRenewsAndRestartsOnce(t *testing.T) {
	f := newFixture(t, 7)
	res, err := runFixture(f, false)
	if err != nil || res.Status != "renewed" || !res.Renewed || !res.Restarted || f.renews != 1 || f.restarts != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	actual, err := f.r.current(f.cfg)
	if err != nil || !bytes.Equal(actual.cert, f.next.cert) || !bytes.Equal(actual.key, f.next.key) {
		t.Fatal("new pair missing")
	}
	entries, err := filepath.Glob(filepath.Join(f.cfg.StoragePath, "backup-*", "private.key"))
	if err != nil || len(entries) != 1 {
		t.Fatal("backup missing")
	}
	b, err := os.ReadFile(entries[0])
	if err != nil || !bytes.Equal(b, f.old.key) {
		t.Fatal("backup differs")
	}
	fi, _ := os.Stat(f.cfg.PrivateKeyPath)
	if fi.Mode().Perm() != 0600 {
		t.Fatal("private key permissions")
	}
	// Following day's run uses the live certificate, not another ACME request.
	res, err = runFixture(f, false)
	if err != nil || res.Status != "valid" || f.renews != 1 || f.restarts != 1 {
		t.Fatal("repeat run changed state", res, err)
	}
}
func TestExpiredCertificateCanRecover(t *testing.T) {
	f := newFixture(t, -1)
	res, err := runFixture(f, false)
	if err != nil || !res.Renewed || f.restarts != 1 {
		t.Fatal(res, err)
	}
}
func TestThresholdExactlyThirtyDaysRenews(t *testing.T) {
	f := newFixture(t, 30)
	res, err := runFixture(f, false)
	if err != nil || !res.Renewed {
		t.Fatal(res, err)
	}
}
func TestProviderFailureRedacted(t *testing.T) {
	f := newFixture(t, 7)
	f.r.renew = func(context.Context, Config) (pair, error) {
		return pair{}, errors.New("cloudflare " + f.cfg.DNSAPIToken)
	}
	res, err := runFixture(f, false)
	b, _ := json.Marshal(res)
	if err == nil || strings.Contains(err.Error(), f.cfg.DNSAPIToken) || bytes.Contains(b, []byte(f.cfg.DNSAPIToken)) || res.Status != "renewal_failed" || f.restarts != 0 {
		t.Fatal("secret leaked or wrong state")
	}
	assertOld(t, f)
}
func TestInvalidCurrentKeyRejected(t *testing.T) {
	f := newFixture(t, 90)
	os.WriteFile(f.cfg.PrivateKeyPath, f.next.key, 0600)
	res, err := runFixture(f, false)
	if err == nil || res.Status != "invalid_current_pair" || f.renews != 0 {
		t.Fatal(res, err)
	}
}
func TestWorldReadableCurrentKeyRejected(t *testing.T) {
	f := newFixture(t, 90)
	os.Chmod(f.cfg.PrivateKeyPath, 0644)
	res, err := runFixture(f, false)
	if err == nil || res.Status != "unsafe_current_pair" || f.renews != 0 {
		t.Fatal(res, err)
	}
}
func TestCurrentSymlinkRejected(t *testing.T) {
	f := newFixture(t, 90)
	target := f.cfg.PrivateKeyPath + ".real"
	os.Rename(f.cfg.PrivateKeyPath, target)
	os.Symlink(target, f.cfg.PrivateKeyPath)
	res, err := runFixture(f, false)
	if err == nil || res.Status != "unsafe_current_pair" || f.renews != 0 {
		t.Fatal(res, err)
	}
}
func TestConfigPrivateStrictJSON(t *testing.T) {
	f := newFixture(t, 90)
	p := filepath.Join(filepath.Dir(f.cfg.CertificatePath), "config.json")
	b, _ := json.Marshal(f.cfg)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := f.r.loadConfig(p)
	if err != nil || cfg.Domain != f.cfg.Domain {
		t.Fatal(err)
	}
	os.Chmod(p, 0644)
	if _, err = f.r.loadConfig(p); err == nil {
		t.Fatal("accepted public config")
	}
	os.Chmod(p, 0600)
	os.WriteFile(p, append(b, []byte(` {"unknown":1}`)...), 0600)
	if _, err = f.r.loadConfig(p); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	os.WriteFile(p, []byte(`{"dns_api_token":"PRIVATE_TEST_TOKEN_NEVER_PRINT","unknown":1}`), 0600)
	if _, err = f.r.loadConfig(p); err == nil || strings.Contains(err.Error(), f.cfg.DNSAPIToken) {
		t.Fatal("config error not redacted")
	}
}
func TestConfigSymlinkRejected(t *testing.T) {
	f := newFixture(t, 90)
	p := filepath.Join(filepath.Dir(f.cfg.CertificatePath), "config.json")
	real := p + ".real"
	b, _ := json.Marshal(f.cfg)
	os.WriteFile(real, b, 0600)
	os.Symlink(real, p)
	if _, err := f.r.loadConfig(p); err == nil {
		t.Fatal("accepted config symlink")
	}
}
func TestStorageRejectsPublicPermissions(t *testing.T) {
	f := newFixture(t, 90)
	os.Mkdir(f.cfg.StoragePath, 0755)
	res, err := runFixture(f, false)
	if err == nil || res.Status != "unsafe_storage" {
		t.Fatal(res, err)
	}
}
func TestStorageRejectsSymlink(t *testing.T) {
	f := newFixture(t, 90)
	os.Mkdir(f.cfg.StoragePath, 0700)
	os.Symlink(f.cfg.PrivateKeyPath, filepath.Join(f.cfg.StoragePath, "linked.key"))
	res, err := runFixture(f, false)
	if err == nil || res.Status != "unsafe_storage" {
		t.Fatal(res, err)
	}
}
func TestParentSymlinkRejected(t *testing.T) {
	f := newFixture(t, 90)
	p := filepath.Join(filepath.Dir(f.cfg.CertificatePath), "linked-dir")
	os.Symlink(filepath.Dir(f.cfg.CertificatePath), p)
	f.cfg.CertificatePath = filepath.Join(p, "180.crt")
	f.cfg.PrivateKeyPath = filepath.Join(p, "180.key")
	res, err := runFixture(f, false)
	if err == nil || res.Status != "unsafe_current_pair" {
		t.Fatal(res, err)
	}
}
func TestConcurrentRunLockedBeforeNetwork(t *testing.T) {
	f := newFixture(t, 7)
	if err := f.r.prepareStorage(f.cfg.StoragePath, true); err != nil {
		t.Fatal(err)
	}
	lock, err := f.r.lock(f.cfg.StoragePath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	res, err := runFixture(f, false)
	if err == nil || res.Status != "locked_or_unsafe_lock" || f.renews != 0 || f.restarts != 0 {
		t.Fatal(res, err)
	}
}
func TestInvalidRenewedPairDoesNotReplace(t *testing.T) {
	for _, which := range []string{"key_mismatch", "wrong_domain", "untrusted_chain", "short_expiry", "broken_chain"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, 7)
			switch which {
			case "key_mismatch":
				f.next.key = f.old.key
			case "wrong_domain":
				f.next = issue(t, "other.example.com", f.now, f.now.Add(90*24*time.Hour), f.ca, f.caKey)
			case "untrusted_chain":
				f.r.roots = x509.NewCertPool()
			case "short_expiry":
				f.next = f.old
			case "broken_chain":
				block, _ := pem.Decode(f.next.cert)
				other := newFixture(t, 90)
				f.next.cert = append(pem.EncodeToMemory(block), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.ca.Raw})...)
			}
			res, err := runFixture(f, false)
			if err == nil || f.restarts != 0 {
				t.Fatal(res, err)
			}
			assertOld(t, f)
		})
	}
}
func TestStagingFailureKeepsOldPair(t *testing.T) {
	f := newFixture(t, 7)
	normal := f.r.stage
	f.r.stage = func(p string, b []byte) (string, error) {
		if p == f.cfg.PrivateKeyPath {
			return "", errors.New("disk full " + f.cfg.DNSAPIToken)
		}
		return normal(p, b)
	}
	res, err := runFixture(f, false)
	if err == nil || res.Status != "staging_failed" || f.restarts != 0 || strings.Contains(err.Error(), f.cfg.DNSAPIToken) {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestSecondRenameFailureRollsBack(t *testing.T) {
	f := newFixture(t, 7)
	failedOnce := false
	f.r.rename = func(a, b string) error {
		if b == f.cfg.PrivateKeyPath && !failedOnce {
			failedOnce = true
			return errors.New("rename fail")
		}
		return os.Rename(a, b)
	}
	res, err := runFixture(f, false)
	if err == nil || res.Status != "replacement_failed_rolled_back" || f.restarts != 0 {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestRestartFailureRollsBackAndRestartsOld(t *testing.T) {
	f := newFixture(t, 7)
	f.r.restart = func(context.Context) error {
		f.restarts++
		if f.restarts == 1 {
			return errors.New("systemctl fail " + f.cfg.DNSAPIToken)
		}
		return nil
	}
	res, err := runFixture(f, false)
	if err == nil || res.Status != "restart_failed_rolled_back" || res.Renewed || res.Restarted || f.restarts != 2 || strings.Contains(err.Error(), f.cfg.DNSAPIToken) {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestRecoveryRestartFailureReported(t *testing.T) {
	f := newFixture(t, 7)
	f.r.restart = func(context.Context) error { f.restarts++; return errors.New("failure") }
	res, err := runFixture(f, false)
	if err == nil || res.Status != "restart_failed_rolled_back_recovery_failed" || f.restarts != 2 {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestBackupFailureKeepsOldPair(t *testing.T) {
	f := newFixture(t, 7)
	f.r.stage = func(string, []byte) (string, error) { return "", errors.New("disk full") }
	res, err := runFixture(f, false)
	if err == nil || res.Status != "backup_failed" || f.restarts != 0 {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestFirstRenameFailureKeepsOldPair(t *testing.T) {
	f := newFixture(t, 7)
	f.r.rename = func(a, b string) error {
		if b == f.cfg.CertificatePath {
			return errors.New("failure")
		}
		return os.Rename(a, b)
	}
	res, err := runFixture(f, false)
	if err == nil || res.Status != "replacement_failed" || f.restarts != 0 {
		t.Fatal(res, err)
	}
	assertOld(t, f)
}
func TestMutableParentRejected(t *testing.T) {
	f := newFixture(t, 90)
	os.Chmod(filepath.Dir(f.cfg.CertificatePath), 0777)
	res, err := runFixture(f, true)
	if err == nil || res.Status != "unsafe_storage" || f.renews != 0 {
		t.Fatal(res, err)
	}
}
func TestHardLinkedCurrentKeyRejected(t *testing.T) {
	f := newFixture(t, 90)
	if err := os.Link(f.cfg.PrivateKeyPath, f.cfg.PrivateKeyPath+".linked"); err != nil {
		t.Fatal(err)
	}
	res, err := runFixture(f, true)
	if err == nil || res.Status != "unsafe_current_pair" || f.renews != 0 {
		t.Fatal(res, err)
	}
}
func TestCurrentWrongHostnameRejectedBeforeNetwork(t *testing.T) {
	f := newFixture(t, 90)
	f.cfg.Domain = "wrong.example.com"
	res, err := runFixture(f, false)
	if err == nil || res.Status != "invalid_current_pair" || f.renews != 0 || f.restarts != 0 {
		t.Fatal(res, err)
	}
}

func TestConfigRejectsShellAndUnsafeDomain(t *testing.T) {
	for _, which := range []string{"service", "domain", "path", "storage", "provider", "email", "renewal"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t, 90)
			switch which {
			case "service":
				f.cfg.RestartService = "mboard-node; echo secret"
			case "domain":
				f.cfg.Domain = "../example.com"
			case "path":
				f.cfg.PrivateKeyPath = "relative.key"
			case "storage":
				f.cfg.StoragePath = filepath.Dir(f.cfg.CertificatePath)
			case "provider":
				f.cfg.DNSProvider = "shell"
			case "email":
				f.cfg.Email = "Someone <acme@example.com>"
			case "renewal":
				f.cfg.RenewBeforeDays = 0
			}
			if f.cfg.validate() == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}
