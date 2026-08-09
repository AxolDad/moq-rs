# Cross-relay differential — telehealth conformance (#43)

Relays: ietf-local moqdev-head moqdev-prodpin

| Scenario | ietf-local | moqdev-head | moqdev-prodpin |
|---|---|---|---|
| setup-only | PASS | PASS | PASS |
| announce-only | PASS | PASS | PASS |
| subscribe-error | PASS | PASS | PASS |
| announce-subscribe | PASS | PASS | PASS |
| subscribe-before-announce | PASS | PASS | PASS |
| publish-namespace-done | PASS | PASS | PASS |
| telehealth-session-e2e | PASS | PASS | PASS |
| telehealth-path-secrecy | PASS | PASS | PASS |
| telehealth-control-integrity | PASS | PASS | PASS |
| telehealth-priority-drain | SKIP | SKIP | SKIP |
| telehealth-fault-garbage-stream | PASS | PASS | PASS |
| telehealth-fault-subscribe-churn | PASS | PASS | **FAIL** |
| telehealth-fault-abrupt-disconnect | PASS | PASS | PASS |

PASS / SKIP (inconclusive, e.g. priority-drain on a live-forwarding relay) / FAIL / n/a.

## Legs

- **ietf-local** — locally built `moq-relay-ietf` (this repo), unauthenticated.
- **moqdev-head** — `kixelated/moq` `moq-relay` **v0.14.9** (HEAD), JWT-gated
  with an Ed25519 JWK, exactly as production authenticates.
- **moqdev-prodpin** — the **same commit production runs**: upstream
  `45db108a` (2026-04-23), which builds `moq-relay` **v0.10.25**. JWT-gated
  identically. This is the production-faithful leg.
- **toq-gce** *(not run)* — the live ToQ relay
  (`moq-relay.outsideinsights.health`). Deliberately **not** targeted: the
  fault-injection and load scenarios are abusive by design and that host
  carries real clinical sessions. Run the read/write subset there only, on an
  isolated path prefix, with a short-TTL scoped token — or against a
  dedicated staging relay.

Regenerate (JWT-bearing URLs are redacted in this tool's logs and never
written to the report):

```
tools/relay-differential.sh --tls-disable-verify \
    ietf-local=https://127.0.0.1:4443 \
    "moqdev-head=https://127.0.0.1:4447/?jwt=$JWT" \
    "moqdev-prodpin=https://127.0.0.1:4446/?jwt=$JWT"
```

## Findings

### 1. The telehealth contract is portable across both MoQ families

The moq-rs (IETF-lineage) client completes SETUP against both moq.dev relays
and every non-fault scenario returns an identical verdict on all three legs.
Derived-path routing, multi-track sessions, path secrecy, and signed control
envelopes hold everywhere. Draft-version incompatibility — the risk this ring
existed to find — did not materialize.

### 2. Production runs a relay four minor versions behind, with a real defect

Production pins upstream `45db108a` from **2026-04-23** →
`moq-relay v0.10.25`. HEAD is **v0.14.9**. The pin predates the entire
2026-08-06 release train (retention, embedded relay, wasm fix,
subscribe-rejection hardening).

`telehealth-fault-subscribe-churn` **fails on the production pin and passes
on HEAD**, measured over 8 runs each, same client, same auth, only the relay
version differing:

| Relay | churn scenario |
|---|---|
| moqdev-prodpin (v0.10.25) | **1/8 pass** (7 failures) |
| moqdev-head (v0.14.9) | 8/8 pass |

The failure is a client-side decode error while reading a *burst* of relay
error responses ("Broadcast not found") produced by rapid subscribe/unsubscribe
churn against non-existent sibling paths. Multiple responses coalesce into one
read buffer and the IETF-lineage decoder mis-frames at the second message
(`invalid utf-8 … from index 8`). A **single** subscribe error decodes fine —
`subscribe-error` (T0.3) passes on every leg — so this is specific to
coalesced error bursts. Which side owns the framing bug (moq-lite v0.10.25's
encoding vs the IETF client's decoder) is not established here; what is
established is that upgrading the relay fixes it.

**Blast radius is limited — this is not a production availability finding.**
Two checks, both on the production pin:

- A real session run **concurrently with a churn storm** completes normally
  (`telehealth-session-e2e` PASS during three back-to-back churn runs).
- The relay stays healthy after a churn failure (`session-e2e` PASS
  immediately afterward).

So a client that churns subscriptions kills **its own** connection; it does
not disrupt other sessions or the relay. The practical exposure is a
perception ingest or clinician page that probes paths speculatively — it
should not, but on the current production relay such a client would be torn
down rather than merely refused.

**Recommendation:** this gives the `infra/moq-relay` upgrade evaluation a
concrete reason beyond the release notes. Upgrading to ≥ v0.14.9 removes a
reproducible interop defect and picks up the 2026-08-06 hardening. Owner call
— not performed here.

### 3. Latency: moq.dev is ~2× faster on this hardware

`moq-telehealth-bench`, 15 concurrent sessions × 12 s, loopback:

| Relay | Delivery | p50 | p95 | p99 |
|---|---|---|---|---|
| ietf-local | 100% | 2.4 ms | 3.9 ms | 4.1 ms |
| moqdev-head | 100% | 1.2 ms | 1.5 ms | 1.7 ms |

Both deliver every alert. Loopback numbers are a floor, not a WAN prediction.

### 4. Retention is per-track and *advertised*, not a blanket 30 s window

From `rs/moq-relay/src/cache.rs`:

- The relay caches **non-latest** groups until *that track's own advertised
  retention window* expires, clamped by `--cache-duration` and a byte budget.
- **The latest group of every track is always retained** (the live edge).
- `hang` **media** tracks declare a retention (that is where "30 s" comes
  from). A track advertising nothing gets live-edge-only.
- Expiry is evaluated when a track writes its *next* group, so a publisher
  that stops writing without disconnecting keeps whatever it had cached.

**Consequence for the perception contract:** our data tracks advertise no
retention, so a late-joining subscriber gets the live edge and **no history at
all** — not 30 s of it. Server-side late-join replay is strictly required.
Advertising a retention window on `perception.alerts` is an available lever,
but a deliberate evidence-window contract change.

This also explains the `priority-drain` SKIP **precisely**, on all three legs:
with only the latest group retained per track, a metrics backlog cannot
accumulate at the relay, so nothing exists for a higher-priority alert to
overtake. The scenario is correct to withhold a verdict rather than pass.

## Runbook — moq.dev relay legs

```bash
git clone https://github.com/kixelated/moq.git && cd moq

# HEAD
cargo build -p moq-relay --release

# The exact commit production runs
git worktree add ../moq-prodpin 45db108 && cd ../moq-prodpin
cargo build -p moq-relay --release
```

Authenticated (matches production, which passes `--auth-key` and no
`--auth-public`):

```bash
# One-time: a signing key + a token. Never commit either.
cargo build -p moq-token-cli --release
./target/release/moq-token generate --id testkey --out /tmp/toq-auth/testkey.jwk
./target/release/moq-token sign --key /tmp/toq-auth/testkey.jwk \
    --root "" --publish "" --subscribe "" > /tmp/toq-auth/test.jwt

./target/release/moq-relay \
    --server-bind '127.0.0.1:4446' --client-bind '0.0.0.0:0' \
    --auth-key /tmp/toq-auth/testkey.jwk \
    --tls-cert localhost.crt --tls-key localhost.key
```

The client carries the token in the URL — `https://host:port/?jwt=<token>` —
no client change needed; the full URL (path and query) is passed to the
WebTransport CONNECT.

Three gotchas worth knowing:

- **Secure by default.** The relay refuses to start with *"nobody can
  authenticate"* unless one of `--auth-public`, `--auth-key`,
  `--auth-key-dir`, or a server TLS root is set. Production uses
  `--auth-key`; `--auth-public ''` is local-testing-only.
- **`--client-bind` defaults to `[::]:0`.** On an IPv4-only host it fails
  with *"Address family not supported"* from `Relay::load` even when
  `--server-bind` is IPv4. Override it.
- **Never put a real token on a command line or in a log.** Pass it via a
  file or environment variable; this tool redacts `?jwt=` from its own
  output, and the report records relay *names* only.
