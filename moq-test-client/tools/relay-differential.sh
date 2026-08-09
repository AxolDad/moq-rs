#!/bin/bash
# SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Cross-relay differential runner (edge_emotion_engine #43).
#
# Runs the moq-test-client TAP suite against one or more relay endpoints and
# joins the results into a per-scenario × per-relay matrix (PASS / SKIP /
# FAIL / n/a). The telehealth-* scenarios exercise the same secured contract
# against every relay, so the matrix shows exactly where a relay diverges.
#
# Usage:
#   relay-differential.sh [--tls-disable-verify] [--out FILE] NAME=URL [NAME=URL ...]
#
# Example (local IETF baseline):
#   relay-differential.sh --tls-disable-verify ietf-local=https://127.0.0.1:4443
#
# Add more legs as they become available, e.g.:
#   ... moqdev-local=https://127.0.0.1:4444 toq-gce=https://moq-relay.example:4443
# The ToQ GCE relay leg needs the relay's auth/JWT — pass it via the client's
# env/flags once available (see docs). A relay that speaks a different MOQT
# draft will surface as failed handshakes in its column, which is itself a
# differential finding — not a runner error.

set -uo pipefail
# This script lives at <repo>/moq-test-client/tools/; cd to the repo root so
# `cargo` and `./target/debug/...` resolve.
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

TLS_FLAG=""
OUT=""
SPECS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tls-disable-verify) TLS_FLAG="--tls-disable-verify" ;;
    --out) OUT="$2"; shift ;;
    --out=*) OUT="${1#--out=}" ;;
    *=*) SPECS+=("$1") ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ "${#SPECS[@]}" -eq 0 ]; then
  echo "usage: relay-differential.sh [--tls-disable-verify] [--out FILE] NAME=URL ..." >&2
  exit 2
fi

echo "building moq-test-client..." >&2
cargo build -q -p moq-test-client --bin moq-test-client

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

NAMES=()
for spec in "${SPECS[@]}"; do
  name="${spec%%=*}"
  url="${spec#*=}"
  NAMES+=("$name")
  # Never echo the URL: an authenticated relay carries its token as `?jwt=…`,
  # and this line would put a live credential in logs and CI output. The
  # joined report prints relay NAMES only, for the same reason.
  echo "running against $name ($(printf '%s' "$url" | sed -E 's#(\?|&)jwt=[^&]*#\1jwt=REDACTED#g'))..." >&2
  ./target/debug/moq-test-client --relay "$url" --bind '0.0.0.0:0' $TLS_FLAG \
    >"$WORK/$name.tap" 2>/dev/null || true
done

# Build a long table (relay, scenario, status), then pivot to a matrix.
LONG="$WORK/long.tsv"
: >"$LONG"
for name in "${NAMES[@]}"; do
  awk -v relay="$name" '
    /^ok / || /^not ok / {
      line = $0
      status = "PASS"
      if (line ~ /^not ok/) status = "FAIL"
      if (line ~ / # SKIP/) status = "SKIP"
      sub(/^(ok|not ok) [0-9]+ - /, "", line)
      sub(/ #.*$/, "", line)
      printf "%s\t%s\t%s\n", relay, line, status
    }
  ' "$WORK/$name.tap" >>"$LONG"
done

emit() {
  echo "# Cross-relay differential — telehealth conformance (#43)"
  echo
  echo "Relays: ${NAMES[*]}"
  echo
  awk -v relays="${NAMES[*]}" '
    BEGIN {
      n = split(relays, R, " ")
      printf "| Scenario |"
      for (i = 1; i <= n; i++) printf " %s |", R[i]
      printf "\n|---|"
      for (i = 1; i <= n; i++) printf "---|"
      printf "\n"
    }
    {
      relay = $1; scen = $2; status = $3
      if (!(scen in seen)) { seen[scen] = ++ns; ord[ns] = scen }
      cell[scen, relay] = status
    }
    END {
      for (s = 1; s <= ns; s++) {
        nm = ord[s]
        printf "| %s |", nm
        for (i = 1; i <= n; i++) {
          key = nm SUBSEP R[i]
          printf " %s |", (key in cell) ? cell[key] : "n/a"
        }
        printf "\n"
      }
    }
  ' "$LONG"
  echo
  echo "PASS / SKIP (inconclusive, e.g. priority-drain on a live-forwarding relay) / FAIL / n/a."
}

if [ -n "$OUT" ]; then
  emit >"$OUT"
  echo "wrote $OUT" >&2
else
  emit
fi
