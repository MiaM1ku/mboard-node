# mboard-node

A standalone Go machine agent for mboard's v1 node protocol. Module: `mboard.dev/node`. The executable has no runtime or protocol dependency on another panel. The only non-standard runtime libraries are official gRPC/protobuf packages and their pinned Go dependencies. Linux is the supported operating system (local `flock`, parent-death signal and SIGTERM lifecycle).

The agent authenticates with a machine Bearer token, sends heartbeats, fetches complete native sing-box server JSON, validates revisions, manages one external sing-box child, and automatically collects per-user/per-entry-node counters. It never downloads executables or runs remote shell commands. Install the pinned compatible core separately.

**Automatic accounting requires a core built with `with_v2ray_api`.** The verified stock v1.14.3 Linux binary lacks that tag. The panel must emit authenticated user names, enable local V2Ray user stats, and supply opaque-name mappings when names aren't canonical `mb:u:<uid>:n:<entry>[:p:<profile>]`. Closed TCP/UDP counters survive until the core exits, so connections that start and end between polls are counted. This measures routed authenticated payload bytes, not NIC totals. See [telemetry contract](docs/telemetry.md) for exact fields, durable guarantees and restart loss limits.

## Build and test

Go 1.24 or newer for the agent. Dependencies are pinned in `go.mod`/`go.sum`. The pinned core may need a newer Go toolchain.

```sh
/usr/local/go/bin/go mod download
/usr/local/go/bin/go test ./...
/usr/local/go/bin/go vet ./...
/usr/local/go/bin/go test -race ./...
# Optional local authenticated-TCP → gRPC → durable batch → HTTP ACK smoke:
MBOARD_TEST_CORE_BINARY=/tmp/mboard-core-build/sing-box /usr/local/go/bin/go test -race ./internal/node -run TestLiveCoreClosedAuthenticatedTCPAccounting -count=1 -v
/usr/local/go/bin/go build -o mboard-node ./cmd/mboard-node
./mboard-node version
```

The build output is ignored by Git. The tests use mock HTTP servers and a local fake core executable. They do not prove a production certificate chain, firewall rules, or end-to-end proxy connectivity.

## Pair with mboard

1. In mboard's admin panel, create an enabled machine. Copy its one-time token into a root-readable agent config or `MBOARD_NODE_TOKEN`.
2. Add enabled nodes and assign them to that machine. Set group grants, protocol, endpoint, ports, TLS and users in mboard. Each emitted authenticated username must identify its user and entry node through `traffic_labels` or the canonical label shape. Preserve source aliases through the mapping rather than rewriting user route names.
3. Install pinned sing-box v1.14.3 with `with_v2ray_api` and the features needed by the native config. The server config comes from mboard unchanged. Verify the installed core's tags and `check` result. See `docs/telemetry.md` for build commands.
4. Create `/etc/mboard-node/agent.json` from `config.example.json`, then set its panel origin and machine token. Use mode `0600`; the installed binary and its parents should be owned by the administrator.
5. Provision every inbound TLS certificate/key before starting the agent. See `docs/operations.md`.
6. Run:

```sh
./mboard-node validate -config /etc/mboard-node/agent.json
./mboard-node run -config /etc/mboard-node/agent.json
```

`validate` checks local agent JSON only. Each fetched server revision runs `sing-box check -c <same-directory-temp-file>` before any replacement or restart. The path is passed as a direct process argument; a shell is never used.

HTTPS checks certificates using the system trust store. `tls_ca_path` can add a private CA. Optional `tls_cert_path` and `tls_key_path` identify the agent to a panel reverse proxy using mutual TLS. These settings **do not** provision inbound proxy certificates. HTTP is accepted for isolated local development only: a Bearer token sent over HTTP is plaintext. Redirects are rejected to prevent forwarding the token to another origin.

## Local configuration

All keys are snake_case. Unknown agent keys are rejected. Paths must be absolute. `panel_url` is an origin such as `https://panel.example.com`, with no path, credentials or query.

| Key | Default / meaning |
| --- | --- |
| `panel_url` | Required mboard origin |
| `token` | Required machine token, 16–4096 non-whitespace characters |
| `config_path` | `/etc/mboard-node/sing-box.json`, generated live server JSON |
| `core_binary` | `/usr/local/bin/sing-box`, fixed local executable |
| `data_dir` | `/var/lib/mboard-node`, local state/spool/lock |
| `interval` | `30s`, heartbeat/config successful poll interval |
| `request_timeout` | `15s`, HTTP and core-check timeout |
| `telemetry_interval` | `5s`, successful cumulative gRPC poll interval |
| `telemetry_timeout` | `5s`, local gRPC deadline |
| `telemetry_spool_max_bytes` | `268435456` (256 MiB), automatic spool admission budget; 0 uses default. Set `33554432` (32 MiB) for low-disk containers. |
| `tls_ca_path` | Empty, or private panel CA PEM |
| `tls_cert_path`, `tls_key_path` | Empty, or paired panel mTLS client files |

Durations accept Go forms such as `15s` and `1m`, from one second to one hour. Every key can be overridden with `MBOARD_NODE_` plus its uppercase name, for example `MBOARD_NODE_PANEL_URL`, `MBOARD_NODE_TOKEN`, `MBOARD_NODE_CONFIG_PATH`, `MBOARD_NODE_CORE_BINARY`, `MBOARD_NODE_INTERVAL`, `MBOARD_NODE_TLS_CA_PATH`. The local JSON file is still required. Command `-config` selects that agent file; JSON `config_path` selects the generated sing-box file.

## Manual ingest (trusted integrations only)

Normal operation uses the automatic gRPC collector. `ingest` remains available for separate trusted accounting sources or reconciled historical deltas. **Do not ingest the same core's traffic in parallel with automatic collection:** different batch IDs would charge the bytes twice.

Feed this shape to stdin or `-file`. Omit `batch_id` to generate a cryptographically random ID; the CLI prints the durable ID after enqueue.

```json
{
  "batch_id": "collector-host1-0000042",
  "records": [
    {"user_id": 7, "node_id": 3, "upload_bytes": 12000, "download_bytes": 45000}
  ]
}
```

```sh
./mboard-node ingest -config /etc/mboard-node/agent.json -file /var/lib/collector/batch-42.json
# Or pipe a real collector's JSON batch into:
./mboard-node ingest -config /etc/mboard-node/agent.json
```

These are **deltas**, not ever-growing totals. IDs are positive integers. Counters are nonnegative integer bytes and cannot exceed JavaScript's safe integer range (`9007199254740991`). A batch has 1–10000 records and must encode to at most 1 MiB. IDs use 1–128 letters, digits, hyphens or underscores. The server checks machine ownership and user grants.

Use a deterministic collector batch ID and retain it when retrying a local ingest. Otherwise an uncertain CLI acknowledgment followed by a new random ID could count the same real deltas twice. Queuing the same ID and records while it is pending succeeds without overwriting it. Different pending contents for the same ID fail. After server acknowledgment a repeated ID can be re-enqueued, but mboard's machine+batch ledger prevents recounting it; never reuse an ID for different counters.

The spool stores immutable `data_dir/spool/<batch_id>.json` files, mode `0600`, published from synced temporary files. The agent removes a batch only after `{data:{accepted:true}}`, then syncs the directory. A timeout, HTTP error, malformed reply, or `accepted:false` keeps it. A crash after server acceptance but before local deletion replays the same batch ID, so the server ledger must be retained. Direct manual spool files must have an identical filename/ID and validated contents; using `ingest` is safer.

See `docs/operations.md` for service management, rollout/rollback limits, recovery, certificate provisioning and security.
