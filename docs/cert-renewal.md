# Independent DNS-01 certificate renewal (root180 / AnyTLS)

`mboard-cert-renew` is a separate one-shot executable. The node agent does not
import it. Keep the existing v0.2.0 agent binary and its hash unchanged.
The old node's copied certificate/key remain the active pair until they enter
the renewal window. A certificate expiring on 2026-11-22 is not reissued before
its exact `NotAfter - 30 days` timestamp (approximately 2026-10-23).

## CLI and private configuration

```text
mboard-cert-renew [--config /etc/mboard-node/cert-renew.json] [--check]
```

The default config path is `/etc/mboard-node/cert-renew.json`. Run as root.
`--check` validates local configuration, storage (if present), and the deployed
certificate/key. It never creates storage, acquires a lock, contacts ACME/DNS,
changes certificates, or restarts a service. It exits 0 for `valid` or
`renewal_pending`. A normal run also exits 0 with `valid` and does **not** contact
ACME/DNS or restart the service when `NotAfter` is more than 30 days away.
Failures exit 1. Unsupported arguments exit 2. stdout is exactly one JSON object;
there are no provider error strings, tokens, email addresses, key material, or
path values in it. The standalone process enforces umask 0077 even when run
directly, not just by systemd. The JSON schema is:

```json
{"domain":"node.example.com","expiry":"2026-11-22T00:00:00Z","status":"valid","renewed":false,"restarted":false}
```

Use the actual static DNS name in the existing certificate's SAN and the
operator's ACME account email. Those are required explicit metadata, not inferred
from the machine hostname. The exact configuration schema is:

```json
{
  "domain": "ACTUAL_EXISTING_CERTIFICATE_DNS_NAME",
  "email": "OPERATOR_ACME_EMAIL",
  "dns_provider": "cloudflare",
  "dns_api_token": "POPULATE_PRIVATELY_ON_REMOTE_HOST_ONLY",
  "storage_path": "/opt/mboard-node/certificate-data",
  "certificate_path": "/etc/mboard-node/tls/180.crt",
  "private_key_path": "/etc/mboard-node/tls/180.key",
  "renew_before_days": 30,
  "restart_service": "mboard-node"
}
```

Config and private key must be root-owned regular files with mode **0600** and
one hard link. Every storage directory must be root-owned **0700** and every
storage file **0600**. The existing certificate must be root-owned, regular,
and not group/world-writable (0600 recommended). Symlinks in any component are
rejected. Writable/untrusted ancestors are rejected. The certificate and key
must be distinct files in the same directory. Storage cannot contain the active
TLS directory. `restart_service` accepts only `mboard-node`.

Do not copy or reuse the old node's certmagic runtime storage. This dedicated
storage creates its own persistent ACME account and managed certificate state.
The Cloudflare token stays only in the private remote config. A remote private
helper may read the old provider's token environment keys in this precedence:
`CLOUDFLARE_DNS_API_TOKEN`, `CF_API_TOKEN`, `CLOUDFLARE_API_TOKEN`. It must parse the
old environment privately, not `source` it or print it. Write JSON with a JSON
encoder into a 0600 root-owned temporary file, then rename it to the config
path. Do not put the token in shell arguments, logs, local files, chat, or Git.
If no usable token is present, stop instead of guessing credentials. Use a
Cloudflare API **token**, not the legacy global API key. The provider documents
single-token permissions as Zone:Read and Zone.DNS:Write (with its supported
zone visibility); confirm the inherited token has the necessary scope privately.

## Local build and tests

Go 1.26+ is required by the pinned upstream dependencies. A Go 1.26.6 toolchain
was used for this build. Build the renewal command alone, not `cmd/mboard-node`:

```sh
/usr/local/go/bin/go test ./...
/usr/local/go/bin/go test -race ./internal/certificate ./cmd/mboard-cert-renew
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build \
  -trimpath -ldflags='-s -w' -o /tmp/mboard-cert-renew-linux-amd64 \
  ./cmd/mboard-cert-renew
```

Tests use synthetic X.509 chains and injectable renewal, filesystem, and restart
functions. They do not call real ACME, change DNS, or run systemctl.

## Remote installation (performed by the deployment operator, not this build)

Install the standalone executable to `/usr/local/bin/mboard-cert-renew` with
root ownership and mode 0755. Create `/opt/mboard-node/certificate-data` mode
0700, and ensure `/etc/mboard-node/tls/180.key` and the config are root:root 0600.
Populate the config privately, then run these in this order:

```sh
/usr/local/bin/mboard-cert-renew --config /etc/mboard-node/cert-renew.json --check
/usr/local/bin/mboard-cert-renew --config /etc/mboard-node/cert-renew.json
```

The first command is always network-free. The second is also network-free and
restart-free while the copied leaf is more than 30 days from expiry. Only after
local checks succeed, install the units below and enable the daily timer.
This first long-valid run is **not evidence that Cloudflare credentials or ACME
issuance work**: it deliberately doesn't use them. Check the token scope
privately and monitor the eventual near-expiry run's JSON/result.

`/etc/systemd/system/mboard-cert-renew.service`:

```ini
[Unit]
Description=Renew and export mboard-node AnyTLS certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/local/bin/mboard-cert-renew --config /etc/mboard-node/cert-renew.json
TimeoutStartSec=12min
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/mboard-node/certificate-data /etc/mboard-node/tls
StandardOutput=journal
StandardError=journal
```

`/etc/systemd/system/mboard-cert-renew.timer`:

```ini
[Unit]
Description=Daily mboard-node certificate expiry check

[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true
Unit=mboard-cert-renew.service

[Install]
WantedBy=timers.target
```

```sh
/bin/systemctl daemon-reload
/bin/systemctl enable --now mboard-cert-renew.timer
/bin/systemctl list-timers mboard-cert-renew.timer
```

The oneshot must run as root, with the private JSON config available to it.
No Cloudflare token environment variable is needed by the unit. It needs
outbound DNS and HTTPS, CA trust roots, a correct clock, and access to systemd's
local control interface. `ProtectSystem` permits writes only to the dedicated
storage and deployed TLS directory. The storage directory must exist before
systemd starts the service.

## Renewal, restart, and recovery

At or inside the 30-day window, CertMagic uses only DNS-01 against Let's Encrypt
production. HTTP-01 and TLS-ALPN-01 are disabled. Issuance metadata and account
keys live in the independent private storage. DNS challenge records are removed
by the provider/CertMagic solver. A `renew.lock` file uses a nonblocking kernel
flock across local runs; concurrent writers fail without ACME or restart. Kernel
locks are released on process exit. CertMagic's asset storage is a FileStorage
wrapper with quiet per-name 0600 kernel flock files in `private-locks`, overriding
Lock/Unlock/TryLock. These files are never unlinked (to prevent split inode locks)
and are immediately reusable after a crash. This avoids upstream FileStorage's
0644 orphan locks and stale-lock logging. Storage must be on a local filesystem,
not shared/NFS storage. The timer's persistent daily check keeps
renewal available after the old node is removed.

The exporter uses the public CertMagic APIs `StorageKeys.SiteCert`,
`StorageKeys.SitePrivateKey`, `ACMEIssuer.IssuerKey`, and `FileStorage.Load` for
one static domain and one issuer. It verifies TLS key match, hostname, chain
signatures, system trust for the new fullchain, server authentication, and a new
`NotAfter` beyond both the old expiry and the renewal window. If a successful
issuance is already stored after an earlier failed deployment, it reuses that
valid pair rather than unnecessarily issuing again.

Before replacement it saves a durable root-private `backup-*` directory in
storage containing the old fullchain and key. Both new files are staged with
mode 0600 and fsynced before atomic per-file renames. The loaded node keeps its
old TLS pair until the exporter directly executes this fixed command:

```text
/bin/systemctl restart mboard-node.service
```

There is no shell and no arbitrary service argument. Restart happens only after
a validated, changed pair is deployed. **That restart disconnects existing
AnyTLS connections once per renewal.** Staging failures keep the active pair.
Second-rename, directory-sync, or restart failures attempt to restore both old
files. After a failed restart, the exporter attempts one bounded restart of the
restored pair. The original error is reported as a redacted status and exit 1.
`restart_failed_rolled_back_recovery_failed` means the old pair is restored but
the recovery restart also failed: the operator must restore service health.
`rollback_failed` requires immediate operator attention and use of the private
backup. Backups are retained; prune old backups only after verifying the active
pair and service, and retain the latest known-good pair.

POSIX cannot atomically rename two existing regular files as one pair. A host
crash/SIGKILL between the two renames can leave a mismatched active pair, although
the old private backup is durable. Recovery from that interruption is manual:
stop the renewal timer, restore **both** files from the same known-good backup
with root:root ownership/mode 0600, run `--check`, then restart the node and
re-enable the timer. Do not restore just one file. A failed normal run never
prints the private backup's contents.

## Upstream API references

Pinned: CertMagic v0.25.6, libdns/cloudflare v0.2.2. Current CertMagic documentation
was fetched with Context7 before implementation; the pinned source was inspected
for the export, synchronous obtain/renew, file modes, and issuer APIs.

- [CertMagic DNS challenge and advanced configuration](https://github.com/caddyserver/certmagic/blob/v0.25.6/README.md)
- [Public StorageKeys export API](https://github.com/caddyserver/certmagic/blob/v0.25.6/storage.go)
- [ObtainCertSync and RenewCertSync](https://github.com/caddyserver/certmagic/blob/v0.25.6/config.go)
- [ACMEIssuer API](https://github.com/caddyserver/certmagic/blob/v0.25.6/acmeissuer.go)
- [FileStorage 0700 directories / 0600 files](https://github.com/caddyserver/certmagic/blob/v0.25.6/filestorage.go)
- [Cloudflare v0.2.2 APIToken configuration and scopes](https://github.com/libdns/cloudflare/blob/v0.2.2/README.md)
