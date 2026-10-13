# Operations manual

## Files and permissions

Default local layout:

```text
/etc/mboard-node/agent.json                 operator settings + machine token (0600)
/etc/mboard-node/sing-box.json              generated server config + user credentials (0600)
/etc/mboard-node/tls/<node_id>.crt          inbound server full certificate chain
/etc/mboard-node/tls/<node_id>.key          inbound private key (0600)
/var/lib/mboard-node/state.json             applied revision + SHA-256 config digest (0600)
/var/lib/mboard-node/collector.json         cursors + pending immutable batch journal (0600)
/var/lib/mboard-node/agent.lock             exclusive daemon lock (0600)
/var/lib/mboard-node/spool/<batch_id>.json   pending real traffic deltas (0600)
```

Use an administrator-controlled account. Keep config/data directories mode `0700` and on a local filesystem that supports atomic rename, hard links, directory fsync and flock. The daemon creates missing managed directories with `0700` and enforces `data_dir` mode `0700` even when it exists. `ingest` can run concurrently with the daemon, but must not duplicate automatic core accounting. Two daemons cannot share a data directory. Do not run a separate sing-box service against the same ports; this agent owns one child. Reserve sufficient disk space because accounting batches remain on disk until acknowledged. Monitor spool size and free disk space outside this agent.

To install a built binary and create the directories:

```sh
sudo install -m 0755 mboard-node /usr/local/bin/mboard-node
sudo install -d -m 0700 /etc/mboard-node /etc/mboard-node/tls /var/lib/mboard-node
sudo install -m 0600 config.example.json /etc/mboard-node/agent.json
# Edit agent.json securely and replace the sample token/panel origin.
```

The binary does not install sing-box. Install a release from the upstream vendor and verify it independently. Keep `core_binary` and all its parent directories unwritable by traffic collectors. Local collectors that can edit `agent.json` could select any executable, so collector write access must be limited to ingest through a narrowly controlled service account/command or spool directory. Treat the spool as trusted local input, not a public upload endpoint.

## Provision inbound TLS

The backend's complete native JSON references inbound TLS paths, normally under `/etc/mboard-node/tls`. Provision exactly those paths. A common layout is `<node_id>.crt` / `<node_id>.key`, but the agent doesn't rewrite arbitrary source certificate filenames. Changing agent `config_path` does not rewrite inbound TLS references. TLS-enabled VLESS/Trojan/AnyTLS nodes need a certificate valid for the configured `server_name`, its matching private key and the full intermediate chain. Acquire/renew with your chosen trusted certificate workflow; this agent does not issue certificates or receive private keys from the panel.

For a node whose numeric ID is 3:

```sh
sudo install -m 0644 /secure/cert-source/fullchain.pem /etc/mboard-node/tls/3.crt
sudo install -m 0600 /secure/cert-source/privkey.pem /etc/mboard-node/tls/3.key
sudo /usr/local/bin/sing-box check -c /etc/mboard-node/sing-box.json
```

The service account must be able to read both files. A missing/unreadable certificate causes `check` to fail, which preserves the previous live configuration. Renew certificates using atomic file replacement. Restart the agent service after renewal so its sing-box child reads renewed files even if the panel revision is unchanged. This interrupts existing proxy connections. The TLS files for panel transport (`tls_ca_path`, `tls_cert_path`, `tls_key_path`) are separate from these inbound files.

## systemd example

```ini
[Unit]
Description=mboard standalone node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mboard-node run -config /etc/mboard-node/agent.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=75
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Install as `/etc/systemd/system/mboard-node.service`, then run `systemctl daemon-reload` and `systemctl enable --now mboard-node`. Root is shown for simple file/low-port provisioning; a dedicated account with suitable permissions and only the capabilities its chosen core needs is preferable. Test any further sandbox hardening against your core network features. Logs use UTC and replace the machine token with `[REDACTED]`. HTTP response bodies and core stdout/stderr are not copied into logs because they can contain credentials. Core-check errors are consequently brief; run `sing-box check` manually in a protected terminal for details.

## Revision lifecycle and restart cost

1. Heartbeat, config fetch/apply, automatic collection and spool delivery have separate loops. Core startup/check failures do not stop heartbeat. Heartbeat keeps its three required fields and adds optional `core_ready` / `telemetry_ready`; these distinguish agent liveness from a living applied core and successful current-generation accounting. They don't prove external client connectivity.
2. Config fetch is a full `GET /api/node/v1/config`. A higher revision is staged in the live config directory, synced, and checked with `sing-box check -c <temp>` using the fixed local binary. JSON object configuration with zero enabled inbounds is allowed. The core decides whether its contents are valid.
3. After successful validation, the agent checkpoints old core counters before replacing the live config by atomic rename. A failed checkpoint blocks the update. The old child receives SIGTERM, then is killed if it has not exited within 10 seconds. A new child starts with `run -c <live-path>`. This still has a sample-to-stop traffic tail window; see telemetry.md.
4. The new process must remain alive for one second. Then the agent syncs an atomic state file containing revision and digest. The identical revision/config is a no-op when the core is alive. Changed content at the same revision and backwards revisions are rejected.
5. If startup/state persistence fails, the previous config is restored. The previous child is restarted if feasible. If this was the first apply, the candidate is removed and no core runs. A rollback can also fail (for example disk failure or the old port cannot bind); the agent logs that distinction and keeps heartbeating.

**Every accepted new revision restarts the core and disconnects existing proxy connections.** `check` constructs/validates configuration but does not test listener startup. The one-second startup probe detects early process exits, not a working TLS handshake or routing. Verify a real connection from an external client after rollout. A delayed core crash is recovered on the next config loop. There is no traffic-draining rollout or automatic rollback after a later crash.

Config and revision metadata are two files, not one filesystem transaction. A power loss between their renames can leave a digest mismatch. On startup the agent logs the mismatch, reports revision 0 until confirmed, refetches and validates the panel configuration, then repairs the pair. It does not trust an inconsistent on-disk pair. A matching persisted pair is checked before the core restarts, including during panel outages. Once a daemon is running, `state.json` and the generated config are agent-owned: do not edit them manually. File replacements and directory fsync provide local durability, not backups.

## Retries and shutdown

Successful heartbeat/config polls use `interval` (default 30 seconds). Traffic sends at most one pending batch per second. Each loop retries errors starting at one second and doubles up to five minutes, with up to 25% jitter. Loops are independent so a backlog or hung traffic endpoint does not delay heartbeat. HTTP requests and `check` commands are bounded by `request_timeout` (default 15 seconds). Persistent authentication errors also back off; replace a rotated token and restart the agent.

SIGTERM or Ctrl-C cancels HTTP/check work, waits for workers, and takes a final bounded journal checkpoint before stopping the child with SIGTERM/10-second kill fallback. This final checkpoint bypasses the soft spool cap and can retain pending batches without publishing them; startup recovery publishes them even if the core is down. Hard disk failure or unavailable gRPC can still prevent that sample and is logged. Linux parent-death SIGKILL prevents orphan core listeners after agent death. A rollback already in progress can take up to its 30-second recovery deadline plus child-stop time and a 15-second candidate drain. Set the service shutdown timeout to at least 75 seconds. Pending batches remain for the next start.

## Automatic accounting and recovery

The agent ships an automatic local V2Ray gRPC collector. Use pinned sing-box v1.14.3 built with `with_v2ray_api`, emitted authenticated user names and the optional envelope `traffic_labels` mappings. The API reads nonreset cumulative user counters, including short closed connections, and commits cursor + immutable batch records atomically in `collector.json`. See [telemetry.md](telemetry.md) for exact config/heartbeat fields, opaque identity rules, SS2022 multiuser requirements, state bounds and unavoidable core-exit loss limits.

Automatic collection stops admission at 256 MiB by default or 10,000 spool entries without resetting core counters. Set `telemetry_spool_max_bytes` to `33554432` (32 MiB) for tiny containers and reserve filesystem space separately. Final shutdown checkpoints bypass this soft admission limit into bounded journal storage. File enumeration is paged rather than materializing the whole backlog. Manual ingest can bypass those bounds; operate it as a separate trusted source, never the same core's counters.

Do not delete or hand-edit collector cursors to fix an outage: resetting a cursor while the core still lives can bill its lifetime traffic again. A malformed journal blocks collection instead of silently resetting it. Stop the service, preserve journal+spool together, and reconcile/restore from a known-good backup. Core counters after the last checkpoint disappear when that core exits, so a pending outage should be repaired before restarting if possible. Certificate renewal and every accepted config revision restart the core, disconnecting existing users.

Clash snapshots are not a replacement: they lack authenticated user identity. The V2Ray API is per username, so distinct entry nodes need distinct auth names. Aliases can stay unchanged through exact `traffic_labels` mappings. Inbound-wide/outbound-wide stats are never added to user records. The backend ledger must retain machine+batch deduplication through restores.

A malformed spool file blocks the delivery loop rather than silently discarding accounting data. Stop the daemon, inspect the file in a protected terminal, then repair it or move it outside `spool` into an operator-owned quarantine directory. Reconcile its counters before deleting it. Records the server rejects because their node/user grant changed also stay queued and need operator reconciliation. Neither the agent nor the contract provides historical-grant reconciliation automatically.

## Backups and troubleshooting

Back up the generated config and `state.json` together, plus `collector.json`, pending spool files and TLS keys in encrypted storage. Retain the panel's machine+batch idempotency ledger through panel restores. Losing that ledger while replaying old batches can count traffic twice. Losing spool files can lose unreported accounting.

- `401`/`403`: check enabled machine and token rotation. Never paste the token into issue logs.
- `sing-box check failed`: inspect core version, generated JSON and required TLS files locally. The old config is kept.
- Repeated startup failure: check occupied ports, privileges and core compatibility. Inspect the returned generic error and run core in a protected terminal if needed.
- Digest mismatch: usually an interrupted apply or manual disk edits. The agent will refetch. Restore the known-good pair if the panel is unavailable.
- Large spool: inspect transport errors, grant rejections and disk capacity. Batches are intentionally not dropped.
- Online machine but unreachable proxy: heartbeat means the agent can reach the panel, not that the core, firewall or TLS works. Test a real client connection.
