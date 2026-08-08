# Cross-relay differential — telehealth conformance (#43)

Relays: ietf-local

| Scenario | ietf-local |
|---|---|
| setup-only | PASS |
| announce-only | PASS |
| subscribe-error | PASS |
| announce-subscribe | PASS |
| subscribe-before-announce | PASS |
| publish-namespace-done | PASS |
| telehealth-session-e2e | PASS |
| telehealth-path-secrecy | PASS |
| telehealth-control-integrity | PASS |
| telehealth-priority-drain | SKIP |
| telehealth-fault-garbage-stream | PASS |
| telehealth-fault-subscribe-churn | PASS |
| telehealth-fault-abrupt-disconnect | PASS |

PASS / SKIP (inconclusive, e.g. priority-drain on a live-forwarding relay) / FAIL / n/a.

## Legs

- **ietf-local** — locally built `moq-relay-ietf` (this repo). Baseline above.
- **moqdev-local** *(pending)* — moq.dev `moq-relay` v0.14.8+ run locally.
  Expect a positive `telehealth-priority-drain` verdict there if it
  store-and-forwards, and a probe of its ~30 s `hang` retention window.
- **toq-gce** *(blocked)* — the ToQ GCE relay
  (`moq-relay.outsideinsights.health`). Needs the relay's auth/JWT; pass it
  through the client once available.

Regenerate: `tools/relay-differential.sh --tls-disable-verify ietf-local=https://127.0.0.1:4443`
