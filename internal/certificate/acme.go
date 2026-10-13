package certificate

import (
	"context"
	"errors"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
)

// renewACME owns a separate ACME account/cache/storage. It never imports the old
// node's runtime state, never listens on a port, and only solves DNS-01.
func renewACME(ctx context.Context, c Config) (pair, error) {
	log := zap.NewNop()
	storage := newPrivateStorage(c.StoragePath)
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert:   func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:             log,
		RenewCheckInterval: 24 * time.Hour,
		OCSPCheckInterval:  24 * time.Hour,
	})
	defer cache.Stop()
	magic = certmagic.New(cache, certmagic.Config{Storage: storage, Logger: log})
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      certmagic.LetsEncryptProductionCA,
		Email:                   c.Email,
		Agreed:                  true,
		Logger:                  log,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		CertObtainTimeout:       8 * time.Minute,
		DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{APIToken: c.DNSAPIToken},
		}},
	})
	magic.Issuers = []certmagic.Issuer{issuer}
	certKey := certmagic.StorageKeys.SiteCert(issuer.IssuerKey(), c.Domain)
	privateKey := certmagic.StorageKeys.SitePrivateKey(issuer.IssuerKey(), c.Domain)
	// A successful previous ACME issuance may already be in storage even if its
	// deployment/restart failed. Reuse that validated pair, not another CA request.
	if storage.Exists(ctx, certKey) {
		crt, err := storage.Load(ctx, certKey)
		if err != nil {
			return pair{}, errors.New("storage_read_failed")
		}
		key, err := storage.Load(ctx, privateKey)
		if err != nil {
			return pair{}, errors.New("storage_read_failed")
		}
		p := pair{crt, key}
		leaf, err := validatePair(p, c.Domain, time.Now(), nil, true)
		if err == nil && leaf.NotAfter.After(time.Now().Add(time.Duration(c.RenewBeforeDays)*24*time.Hour)) {
			return p, nil
		}
		if err := magic.RenewCertSync(ctx, c.Domain, true); err != nil {
			return pair{}, errors.New("acme_failed")
		}
	} else {
		if err := magic.ObtainCertSync(ctx, c.Domain); err != nil {
			return pair{}, errors.New("acme_failed")
		}
	}
	// StorageKeys is the public CertMagic API for exporting TLS assets. Only
	// one issuer and one validated static domain are used, so no glob/cache scan.
	crt, err := storage.Load(ctx, certKey)
	if err != nil {
		return pair{}, errors.New("storage_read_failed")
	}
	key, err := storage.Load(ctx, privateKey)
	if err != nil {
		return pair{}, errors.New("storage_read_failed")
	}
	return pair{crt, key}, nil
}
