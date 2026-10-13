# Automatic telemetry contract and production deployment

## Compatible core

Use sing-box **v1.14.3**, upstream commit `7054cac5124465ffdb145870d7c01885566711b1`, with `with_v2ray_api`. This tag is absent from the verified stock Linux release. The agent remains independent: it imports official gRPC/protobuf, not sing-box or legacy-node modules. V2Ray stats in v1.12 have the same wire/cumulative semantics, but the migration's full native JSON should be validated against pinned v1.14.3 because feature/config support differs.

Build privately, not on running hosts. Core v1.14.3 requires Go 1.25.5 or newer. The agent was tested using Go 1.26.6. For full native transport compatibility the practical expanded tag set is:

```sh
export PATH=/usr/local/go/bin:$PATH
mkdir -p /tmp/mboard-core-build && cd /tmp/mboard-core-build
go mod init local.mboard/corebuild
go mod download -json github.com/sagernet/sing-box@v1.14.3
# Use the Dir returned above as the source directory.
cd /path/from/download/Dir
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -tags 'with_v2ray_api,with_utls,with_quic,with_grpc' \
  -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3' \
  -o /tmp/mboard-core-build/sing-box ./cmd/sing-box
/tmp/mboard-core-build/sing-box version
/tmp/mboard-core-build/sing-box check -c /secure/staged/native.json
```

Minimal tags for VLESS Reality, SS2022, Trojan TLS, AnyTLS and stats: `with_v2ray_api,with_utls`. **Reality server requires `with_utls`.** `with_quic` enables QUIC protocols/transports. `with_grpc` selects standard gRPC transport instead of the lite implementation; V2Ray stats gRPC itself doesn't require it. ECH is provided by stdlib in this version: **do not pass `with_ech`**, because its deprecated-tag stub intentionally fails compilation. `with_clash_api` is optional and provides no authenticated per-user billing. Build/check the actual complete config rather than reducing its routes or outbounds to a synthetic subset.

## Backend config envelope

The existing full GET `/api/node/v1/config` remains:

```json
{
  "data": {
    "revision": 42,
    "config": {
      "inbounds": [],
      "outbounds": [{"type": "direct", "tag": "direct"}],
      "experimental": {
        "v2ray_api": {
          "listen": "127.0.0.1:19090",
          "stats": {
            "enabled": true,
            "users": ["arbitrary-source-alias", "mb:u:7:n:21:p:reality"]
          }
        }
      }
    },
    "traffic_labels": [
      {"label": "arbitrary-source-alias", "user_id": 7, "node_id": 21}
    ]
  }
}
```

`config` is the FULL native core object, not the simplified illustration above. Unknown native fields and unknown envelope additions remain supported. `traffic_labels` is accounting metadata outside native JSON. Each `stats.users` entry must have either an exact opaque mapping or canonical `mb:u:<positive uid>:n:<positive entry id>[:p:<nonempty profile>]`. Explicit mapping wins, allowing legacy aliases without any runtime old-prefix rule. The entry node ID is the subscribed logical entry, including parent/alias routing semantics, not the outbound target node. Preserve full labels, including embedded delimiters, by exact equality. One label cannot represent two entry nodes: the core aggregates per username across inbounds, so different entries require distinct authenticated names.

The mapping must include every noncanonical name. Duplicate names, missing mappings, extra mappings absent from stats.users, unsafe IDs and non-loopback API addresses are rejected before stopping the previous core. Maximum: 10,000 stats users, 512 bytes per label, IDs 1..9007199254740991. The API must use a literal loopback IP and valid port, e.g. `127.0.0.1:19090` or `[::1]:19090`. It has no authentication: restrict local user access. Do not let any second collector issue `reset:true`.

The compiler must emit the exact authenticated `name` in VLESS/Trojan/AnyTLS/SS2022 users and matching stats.users. SS2022 must use `users:[{name,password}]` multiuser mode even for one subscriber; a single-user password-only inbound doesn't set metadata.User. SS2022 multiuser supports `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`, not chacha20 multiuser. Empty user names never produce attributed counters. Preserve source user route names by mapping them rather than renaming them. If native config uses identity routing, preserve the matching auth username and route identity together.

All changes to native JSON OR accounting mappings require a higher revision. Mappings persist beside revision/digest so cached config can restart during panel outages. Unmapped user stats cause a failed poll, not a partially charged batch. Protocol `SharedConfig` includes optional `traffic_labels`; `RemoteConfig` aliases it.

## Counter semantics and durability

The agent invokes `/v2ray.core.app.stats.command.StatsService/QueryStats` using official protobuf wire messages and **reset:false**. Empty patterns enumerate counters exactly once. sing-box's generated client namespace differs from the rewritten V2Ray-compatible server name; this agent intentionally doesn't import that client. Never use deprecated `pattern` field1 (ignored in v1.14.3) or overlapping patterns (can duplicate rows).

Only `user>>>FULL-LABEL>>>traffic>>>uplink` and `downlink` counters are billed. Inbound/outbound totals are ignored, preventing subset double counting. Counters are process-local cumulative atomics, remain after short TCP/UDP closes, and are read independently (not a simultaneous snapshot). Each sample aggregates deltas across profile labels into `(user_id,node_id)`. A zero/empty sample creates no fake zero traffic records. Missing rows retain their previous cursor, not a zero baseline.

1. Recover any committed pending batches before reading more counters, including while the core is down.
2. Read cumulative counters with a bounded gRPC deadline.
3. Atomically rename+fsync `collector.json`, containing both new cursors and immutable batch IDs/records in the SAME checkpoint.
4. Publish pending batches through synced immutable spool links.
5. Clear the journal's pending handoff ONLY after spool publication is durable.
6. POST existing `/api/node/v1/traffic` payloads. Delete spool files only after `{data:{accepted:true}}` and directory fsync.

A crash before step3 leaves core counters available for reread while that core lives. A crash after step3 replays the exact immutable batches. If a panel accepts a POST but the response or local delete is lost, replay uses the same machine+batch ID. The backend must retain its idempotency ledger through retries and restores. Unlike reset:true, no destructive gRPC-reset/spool window exists. An fsync/rename error can leave a committed checkpoint despite returning error, so every retry rereads the journal from disk rather than trusting in-memory cursors.

Bounded local state: <=20,000 current per-label/direction cursors, <=3 normal pending 4,000-record chunks (<=6 during a final checkpoint retaining an older handoff), <=32 MiB journal, <=32 MiB gRPC response /100,000 response rows. Automatic spool admission stops at 256 MiB by default or 10,000 directory entries, leaving 2 MiB byte headroom for the next sample. Set agent `telemetry_spool_max_bytes` (or `MBOARD_NODE_TELEMETRY_SPOOL_MAX_BYTES`) to an integer byte budget between 4 MiB and 16 GiB, or 0 for default. A 32 MiB budget is suitable for tiny containers with only about 0.246 GiB free, but reserve space for the static agent/core, journal and OS first. The cap is not a filesystem free-space guarantee. Enumeration uses paged directory reads. It retains core totals instead of dropping accounting. Final shutdown/rollback sampling bypasses the soft spool limit and only commits the journal, leaving publication for recovery. Manual `ingest` is a trusted bypass of that budget and must be monitored separately. Core map size is itself bounded by the current stats.users/inbound/outbound configuration only until restart; avoid unnecessary inbound/outbound stats. Counters across successful samples must remain within signed int64 and deltas within JS safe integers. Disk failure, capacity, invalid source values or malformed journal disable `telemetry_ready` and retry with backoff.

Core generation gets a new random identity only after the old managed core has stopped, including rollback starts. A failed stop that leaves the old child alive keeps its generation and cursors, preventing lifetime rebilling. A serving candidate gets its own mapping immediately; if revision-state persistence fails, a final candidate checkpoint precedes rollback. Failed candidate checkpoint defers rollback and reports core readiness false until reconciliation rather than destroying those counters. A new generation starts from zero even if its totals exceed the old core's totals. Within a generation, a decrease is treated as a reset: bill only the new observed total. Negative overflow values fail closed. The lifecycle lock prevents restarts between query and journal commit. No other process should own/restart this core. Linux parent-death SIGKILL prevents orphan core listeners after an agent crash.

**Unrecoverable boundary:** counters are volatile inside sing-box. A core crash/power loss loses bytes after the last durable sample. Planned config changes and graceful agent shutdown take a final sample first, but bytes transmitted between that sample and child termination cannot be recovered. Active connections are disconnected by each accepted config revision. Failed final collection blocks a planned config update while the old core is alive, so accounting isn't silently discarded. A reset by a second local reader can also hide bytes; don't run it. The collector isn't an exactly-once NIC meter and must not be advertised as one.

## Heartbeat and availability

The existing required fields stay `version`, `uptime_seconds`, `config_revision`. Optional booleans `core_ready`, `telemetry_ready` report applied config + living managed child, and successful current-generation stats checkpoint/publish respectively. A new core generation can't inherit the old telemetry-ready flag. Collector errors keep agent heartbeat running. These are process/API readiness, not proof of every inbound's TLS, firewall, user authentication or outbound connectivity. The backend must accept/store these optional keys and combine readiness with revision and heartbeat recency for UI online status.

Defaults: telemetry poll `5s`, local deadline `5s`, heartbeat/config `30s`, HTTP/core-check `15s`. `telemetry_interval`, `telemetry_timeout` and matching `MBOARD_NODE_...` environment overrides accept 1s..1h. Each failed worker backs off 1s..5m with up to25% jitter. Recovery after a prolonged telemetry failure can lose a longer core-crash tail than the normal five-second poll interval.

## What is measured and what isn't

Pinned source probes used real loopback TCP/UDP around upstream counter wrappers. After short closed TCP, three nonreset reads kept uplink6/downlink4 bytes. After short closed UDP, three kept uplink6/downlink8. An opt-in test against the actual parent-built tagged v1.14.3 core also passed under `-race`: a short authenticated SOCKS TCP connection sent 14 upload/16 download payload bytes, closed before polling, produced exactly one durable user7/node21 batch across four nonreset polls, reached HTTP ACK, and wasn't billed again after ACK. Run `MBOARD_TEST_CORE_BINARY=/tmp/mboard-core-build/sing-box go test -race ./internal/node -run TestLiveCoreClosedAuthenticatedTCPAccounting -count=1 -v`. This proves the actual core's auth→counter→journal→HTTP path, not production Reality/Vision, SS2022 two-user TCP/UDP, Trojan UDP or AnyTLS UoT acceptance. The independent agent's mock-gRPC and HTTP tests cover wire path/reset flag, deltas, mapping, ACK replay and crash journal recovery. They do not prove production TLS credentials, all native routes, NIC accounting or live host connectivity.

Authenticated routed payload is counted. DNS `hijack-dns` handling returns before router trackers, so locally hijacked DNS bytes are not billed. Authentication failures, handshake overhead, Reality camouflage/fallback traffic have no attributed user counter. AnyTLS multiplexed streams/UoT keep authenticated user context. TUN RoutedFlow counters measure raw packet lengths, unlike proxy payload bytes: don't mix them as the same billing unit. Closed counters persist for process lifetime, not across core restarts.

Source references: [v1.14.3 stats](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/v2rayapi/stats.go), [proto](https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/v2rayapi/stats.proto), [router](https://github.com/SagerNet/sing-box/blob/v1.14.3/route/route.go), [V2Ray API docs](https://sing-box.sagernet.org/configuration/experimental/v2ray-api/).

## Install/cutover and TLS renewal

The deployment operator matches hosts and backs up old units/config/users/TLS/data before uninstalling the old node. This agent does not inventory or mutate remote hosts. Don't run old and new listeners simultaneously on the same ports. On each authorized host:

```sh
# First: verify backup, mapped full native config, TLS files and machine token.
# Stop/disable the discovered old unit; remove old service/launcher by its exact
# inventoried name. Don't assume a global unit name across all 21 hosts.
systemctl stop <inventoried-old-unit>
systemctl disable <inventoried-old-unit>
# Uninstall old package/service after backup, using its verified install method.
install -m 0755 /staged/sing-box /usr/local/bin/sing-box
install -m 0755 /staged/mboard-node /usr/local/bin/mboard-node
install -d -m 0700 /etc/mboard-node /etc/mboard-node/tls /var/lib/mboard-node
install -m 0600 /staged/agent.json /etc/mboard-node/agent.json
# Copy each preserved full certificate chain/key to native config's new TLS paths.
sing-box version
sing-box check -c /staged/full-native.json
mboard-node validate -config /etc/mboard-node/agent.json
# Install the mboard-node unit shown in operations.md.
systemctl daemon-reload
systemctl enable --now mboard-node
# Verify revision+readiness, external authenticated TCP/UDP, preserved identity
# routes/outbounds, and one real traffic batch ACK before progressing.
```

The agent fetches full config on start; staged check alone doesn't install it. The parent backend must have the same revision/native config ready. Rollback stops the new unit before restoring the exact old backup; reconcile already reported batches rather than deleting the panel ledger.

TLS certificate issuance/renewal is external. The parent migrates files under `/etc/mboard-node/tls`; native JSON must reference these paths. Renewal installs matching key/fullchain atomically, runs protected `sing-box check`, then restarts `mboard-node` even if panel revision is unchanged. That restart interrupts active traffic and has the documented final-sample tail window. The agent never silently ignores renewal, issues certificates, copies legacy secrets, or implements legacy certificate-provider hooks. Bind explicit renewal deploy hooks to the new service and test them before cutover.
