# Operations manual

## Files and permissions

Default local layout:

```text
/etc/mboard-node/agent.json                 operator settings + machine token (0600)
/etc/mboard-node/sing-box.json              generated server config + user credentials (0600)
/etc/mboard-node/tls/<node_id>.crt          inbound server full certificate chain
/etc/mboard-node/tls/<node_id>.key          inbound private key (0600)
/var/lib/mboard-node/state.json             applied revision + SHA-256 config digest (0600)
/var/lib/mboard-node/agent.lock             exclusive daemon lock (0600)
/var/lib/mboard-node/spool/<batch_id>.json   pending real traffic deltas (0600)
```

Use an administrator-controlled account. Keep config/data directories mode `0700` and on a local filesystem that supports atomic rename, hard links, directory fsync and flock. The daemon creates missing managed directories with `0700` but does not silently change existing permissions. `ingest` can run concurrently with the daemon. Two daemons cannot share a data directory. Do not run a separate sing-box service against the same ports; this agent owns one child. Reserve sufficient disk space because accounting batches remain on disk until acknowledged. Monitor spool size and free disk space outside this agent.

To install a built binary and create the directories:

```sh
sudo install -m 0755 mboard-node /usr/local/bin/mboard-node
sudo install -d -m 0700 /etc/mboard-node /etc/mboard-node/tls /var/lib/mboard-node
sudo install -m 0600 config.example.json /etc/mboard-node/agent.json
# Edit agent.json securely and replace the sample token/panel origin.
```

The binary does not install sing-box. Install a release from the upstream vendor and verify it independently. Keep `core_binary` and all its parent directories unwritable by traffic collectors. Local collectors that can edit `agent.json` could select any executable, so collector write access must be limited to ingest through a narrowly controlled service account/command or spool directory. Treat the spool as trusted local input, not a public upload endpoint.

## Provision inbound TLS

mboard emits fixed inbound paths `/etc/mboard-node/tls/<node_id>.crt` and `/etc/mboard-node/tls/<node_id>.key`. Changing agent `config_path` does not rewrite them. TLS-enabled VLESS/Trojan nodes need a certificate valid for the configured `server_name`, its matching private key and the full intermediate chain. Acquire/renew with your chosen trusted certificate workflow; this agent does not issue certificates or receive private keys from the panel.

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
TimeoutStopSec=45
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Install as `/etc/systemd/system/mboard-node.service`, then run `systemctl daemon-reload` and `systemctl enable --now mboard-node`. Root is shown for simple file/low-port provisioning; a dedicated account with suitable permissions and only the capabilities its chosen core needs is preferable. Test any further sandbox hardening against your core network features. Logs use UTC and replace the machine token with `[REDACTED]`. HTTP response bodies and core stdout/stderr are not copied into logs because they can contain credentials. Core-check errors are consequently brief; run `sing-box check` manually in a protected terminal for details.

## Revision lifecycle and restart cost

1. Heartbeat, config fetch/apply and spool delivery have separate loops. Core startup/check failures do not stop heartbeat. A heartbeat reports agent uptime and the last committed local config revision; it is not a proxy health check.
2. Config fetch is a full `GET /api/node/v1/config`. A higher revision is staged in the live config directory, synced, and checked with `sing-box check -c <temp>` using the fixed local binary. JSON object configuration with zero enabled inbounds is allowed. The core decides whether its contents are valid.
3. Only after successful validation, the candidate replaces the live file by atomic rename. The old child receives SIGTERM, then is killed if it has not exited within 10 seconds. A new child starts with `run -c <live-path>`.
4. The new process must remain alive for one second. Then the agent syncs an atomic state file containing revision and digest. The identical revision/config is a no-op when the core is alive. Changed content at the same revision and backwards revisions are rejected.
5. If startup/state persistence fails, the previous config is restored. The previous child is restarted if feasible. If this was the first apply, the candidate is removed and no core runs. A rollback can also fail (for example disk failure or the old port cannot bind); the agent logs that distinction and keeps heartbeating.

**Every accepted new revision restarts the core and disconnects existing proxy connections.** `check` constructs/validates configuration but does not test listener startup. The one-second startup probe detects early process exits, not a working TLS handshake or routing. Verify a real connection from an external client after rollout. A delayed core crash is recovered on the next config loop. There is no traffic-draining rollout or automatic rollback after a later crash.

Config and revision metadata are two files, not one filesystem transaction. A power loss between their renames can leave a digest mismatch. On startup the agent logs the mismatch, reports revision 0 until confirmed, refetches and validates the panel configuration, then repairs the pair. It does not trust an inconsistent on-disk pair. A matching persisted pair is checked before the core restarts, including during panel outages. Once a daemon is running, `state.json` and the generated config are agent-owned: do not edit them manually. File replacements and directory fsync provide local durability, not backups.

## Retries and shutdown

Successful heartbeat/config polls use `interval` (default 30 seconds). Traffic sends at most one pending batch per second. Each loop retries errors starting at one second and doubles up to five minutes, with up to 25% jitter. Loops are independent so a backlog or hung traffic endpoint does not delay heartbeat. HTTP requests and `check` commands are bounded by `request_timeout` (default 15 seconds). Persistent authentication errors also back off; replace a rotated token and restart the agent.

SIGTERM or Ctrl-C cancels HTTP/check work, waits for worker loops, and stops the managed child with SIGTERM/10-second kill fallback. A rollback already in progress can take up to its 30-second recovery deadline plus child-stop time. Do not set a service shutdown timeout below 45 seconds. Pending batches remain for the next start.

## Counter collector requirements

The local collector must attribute actual upload/download bytes to both a decimal user ID and a node ID. It must map sing-box inbound tags/listener identity to mboard node IDs and keep its own persistent checkpoints. It must capture final bytes for closed connections and connections that begin and end between polls; active-connection snapshots alone miss those bytes. Do not treat aggregate connection totals or a core-wide Clash `/traffic` stream as per-user billing. A suitable future integration could use a verified per-user statistics source, but this repository ships only durable ingestion and delivery.

For the verified stock sing-box v1.14.3, [Clash `/connections` source](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/clashapi/connections.go) includes inbound type/tag but **does not expose the authenticated user**, so polling it cannot attribute bytes to mboard users. [V2Ray API stats source](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/v2rayapi/stats.go) exposes user totals aggregated across inbounds, not per-user/per-node pairs. That API also requires a `with_v2ray_api` build, which is absent from the verified official Linux v1.14.3 binary. A working automatic integration needs an actual attribution source or a separately designed telemetry extension; merely enabling Clash does not provide accurate billing.

When the source supplies monotonically increasing totals, compute deltas per user/node from a persistent checkpoint. Handle source restart/reset without subtracting a larger previous total. Before advancing the checkpoint, persist a stable ID plus exact delta records so a crash can retry the same batch. Commit your source checkpoint only after durable ingest, keeping the ID if the CLI outcome is uncertain. The example numbers in README illustrate shape, not measured activity.

A malformed spool file blocks the delivery loop rather than silently discarding accounting data. Stop the daemon, inspect the file in a protected terminal, then repair it or move it outside `spool` into an operator-owned quarantine directory. Reconcile its counters before deleting it. Records the server rejects because their node/user grant changed also stay queued and need operator reconciliation. Neither the agent nor the contract provides historical-grant reconciliation automatically.

## Backups and troubleshooting

Back up the generated config and `state.json` together, plus pending spool files and TLS keys in encrypted storage. Retain the panel's machine+batch idempotency ledger through panel restores. Losing that ledger while replaying old batches can count traffic twice. Losing spool files can lose unreported accounting.

- `401`/`403`: check enabled machine and token rotation. Never paste the token into issue logs.
- `sing-box check failed`: inspect core version, generated JSON and required TLS files locally. The old config is kept.
- Repeated startup failure: check occupied ports, privileges and core compatibility. Inspect the returned generic error and run core in a protected terminal if needed.
- Digest mismatch: usually an interrupted apply or manual disk edits. The agent will refetch. Restore the known-good pair if the panel is unavailable.
- Large spool: inspect transport errors, grant rejections and disk capacity. Batches are intentionally not dropped.
- Online machine but unreachable proxy: heartbeat means the agent can reach the panel, not that the core, firewall or TLS works. Test a real client connection.
