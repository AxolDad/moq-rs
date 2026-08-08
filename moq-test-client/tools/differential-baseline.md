# Cross-relay differential — telehealth conformance (#43)

Relays: ietf-local moqdev-local

| Scenario | ietf-local | moqdev-local |
|---|---|---|
| setup-only | PASS | PASS |
| announce-only | PASS | PASS |
| subscribe-error | PASS | PASS |
| announce-subscribe | PASS | PASS |
| subscribe-before-announce | PASS | PASS |
| publish-namespace-done | PASS | PASS |
| telehealth-session-e2e | PASS | PASS |
| telehealth-path-secrecy | PASS | PASS |
| telehealth-control-integrity | PASS | PASS |
| telehealth-priority-drain | SKIP | SKIP |
| telehealth-fault-garbage-stream | PASS | PASS |
| telehealth-fault-subscribe-churn | PASS | PASS |
| telehealth-fault-abrupt-disconnect | PASS | PASS |

PASS / SKIP (inconclusive, e.g. priority-drain on a live-forwarding relay) / FAIL / n/a.

## Legs

- **ietf-local** — locally built `moq-relay-ietf` (this repo).
- **moqdev-local** — `kixelated/moq` `moq-relay` **v0.14.9** (moq.dev lineage),
  built from source and run locally. See the runbook below.
- **toq-gce** *(blocked)* — the ToQ GCE relay
  (`moq-relay.outsideinsights.health`). Needs the relay's auth/JWT; pass it
  through the client once available.

Regenerate: `tools/relay-differential.sh --tls-disable-verify ietf-local=https://127.0.0.1:4443 moqdev-local=https://127.0.0.1:4444`

## Findings

### 1. The telehealth contract is portable across both MoQ families

The moq-rs (IETF-lineage) client completes SETUP against the moq.dev relay and
every scenario produces an **identical verdict** on both. Derived-path routing,
multi-track sessions, path secrecy, signed control envelopes, and all three
fault-isolation behaviors hold on both implementations. Draft-version
incompatibility — the risk this ring existed to find — did **not** materialize.

### 2. Latency: moq.dev is ~2× faster on this hardware

`moq-telehealth-bench`, 15 concurrent sessions × 12 s, loopback:

| Relay | Delivery | p50 | p95 | p99 |
|---|---|---|---|---|
| ietf-local | 100% | 2.4 ms | 3.9 ms | 4.1 ms |
| moqdev-local | 100% | 1.2 ms | 1.5 ms | 1.7 ms |

Both deliver every alert. Loopback numbers are a floor, not a WAN prediction.

### 3. Retention is per-track and *advertised*, not a blanket 30 s window

Reading `rs/moq-relay/src/cache.rs` in the moq.dev tree corrects a loose
assumption from the 2026-08-06 upstream note:

- The relay caches **non-latest** groups until *that track's own advertised
  retention window* expires, clamped by the relay's `--cache-duration`
  ceiling and the byte-budget pool.
- **The latest group of every track is always retained** (the live edge).
- `hang` **media** tracks declare a retention (that is where the "30 s" comes
  from). A track that advertises nothing gets live-edge-only.
- Caveat from upstream's own docs: expiry is evaluated when a track writes its
  *next* group, so a publisher that stops writing without disconnecting keeps
  whatever it had cached.

**Consequence for the perception contract:** our data tracks advertise no
retention, so on this relay a late-joining subscriber gets the live edge and
**no history at all** — not 30 s of it. Server-side late-join replay is
therefore strictly required, not merely a gap-filler. Conversely, advertising
a retention window on `perception.alerts` is an available lever if
relay-assisted reconnect is ever wanted; that would be a deliberate contract
change (an evidence-window decision), not a default.

This also explains the `priority-drain` SKIP **precisely**, on both relays:
with only the latest group retained per track, a metrics backlog cannot
accumulate at the relay, so there is nothing for a higher-priority alert to
overtake. The scenario is correct to withhold a verdict rather than pass.

## Runbook — moq.dev relay leg

```bash
git clone --depth 1 https://github.com/kixelated/moq.git
cd moq && cargo build -p moq-relay --release

./target/release/moq-relay \
    --server-bind '127.0.0.1:4444' \
    --client-bind '0.0.0.0:0' \
    --auth-public '' \
    --tls-cert /path/to/localhost.crt --tls-key /path/to/localhost.key
```

Two gotchas worth knowing:

- **Secure by default.** It refuses to start with *"nobody can authenticate"*
  unless one of `--auth-public`, `--auth-key`, `--auth-key-dir`, or a server
  TLS root is configured. `--auth-public ''` opens the root prefix for local
  testing only — the opposite posture from `moq-relay-ietf`, and the safer
  one.
- **`--client-bind` defaults to `[::]:0`.** On an IPv4-only host (many
  containers) it fails with *"Address family not supported"* from
  `Relay::load` even when `--server-bind` is IPv4; override it explicitly.
