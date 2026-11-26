#!/usr/bin/env bash
# mass-resilient.sh - supervised mass scan with automatic resume.
#
# Survives VPN / internet cuts: progress is checkpointed, a stalled run exits
# by itself (--stall-exit), and this loop relaunches it with a gentler
# concurrency and rate until every host has been scanned.
#
# Env knobs (all optional):
#   TARGETS      input file                     (default hosts.txt)
#   OUT          output directory               (default hits)
#   CKPT         checkpoint file                (default <TARGETS>.ckpt)
#   CONCURRENCY  start concurrency              (default 3000)
#   RATE         requests/second cap            (default 3000)
#   TIMEOUT      per-request timeout seconds    (default 5)
#   SCHEME       auto|https|http                (default auto)
#   PATHS        comma separated paths          (default "/,/.env,/.git/HEAD,.git/config")
#   STALL        seconds without progress before giving up (default 90)
#   MAX_RETRIES  attempts                       (default 50)
#   BACKOFF      seconds between attempts       (default 30)
#   MIN_CONC     concurrency floor              (default 250)
#   BIN          scanner binary                 (default ./git-scanner)
#   SKIP_BUILD   1 = never run go build         (default 0)
#   EXTRA        extra mass flags               (default empty)
set -u
cd "$(dirname "$0")/.." || exit 1

TARGETS=${TARGETS:-hosts.txt}
OUT=${OUT:-hits}
CKPT=${CKPT:-$TARGETS.ckpt}
CONCURRENCY=${CONCURRENCY:-3000}
RATE=${RATE:-3000}
TIMEOUT=${TIMEOUT:-5}
SCHEME=${SCHEME:-auto}
PATHS=${PATHS:-"/,/.env,/.git/HEAD,.git/config"}
STALL=${STALL:-90}
MAX_RETRIES=${MAX_RETRIES:-50}
BACKOFF=${BACKOFF:-30}
MIN_CONC=${MIN_CONC:-250}
BIN=${BIN:-./git-scanner}
SKIP_BUILD=${SKIP_BUILD:-0}
EXTRA=${EXTRA:-}

[ -f "$TARGETS" ] || { echo "missing targets file: $TARGETS"; exit 1; }
ulimit -n 1048576 2>/dev/null || true

if [ "$SKIP_BUILD" != "1" ]; then
  go build -ldflags "-s -w" -o "$BIN" ./cmd/git-scanner || exit 1
fi
[ -x "$BIN" ] || { echo "missing binary: $BIN (set BIN= or build it)"; exit 1; }

conc=$CONCURRENCY
rate=$RATE
attempt=0

remaining() {
  if [ ! -f "$CKPT" ]; then wc -l < "$TARGETS"; return; fi
  comm -23 <(sort -u "$TARGETS" | tr -d '\r') <(sort -u "$CKPT" | tr -d '\r') | wc -l
}

while :; do
  attempt=$((attempt + 1))
  left=$(remaining)
  echo "=== attempt $attempt | remaining=$left concurrency=$conc rate=$rate stall=${STALL}s ==="
  if [ "$left" -eq 0 ]; then echo "all targets scanned"; break; fi

  "$BIN" mass "$TARGETS" \
    --checkpoint "$CKPT" --paths "$PATHS" --scheme "$SCHEME" --timeout "$TIMEOUT" \
    --concurrency "$conc" --rate "$rate" --stall-exit "$STALL" \
    -o "$OUT" --format jsonl $EXTRA
  rc=$?

  if [ "$rc" -eq 0 ]; then
    echo "=== finished (remaining=$(remaining)) ==="
    break
  fi
  echo "=== exit=$rc (likely a network cut) ==="
  if [ "$attempt" -ge "$MAX_RETRIES" ]; then echo "max retries reached"; break; fi

  # the link is probably saturated: back off and slow down
  conc=$((conc / 2)); [ "$conc" -lt "$MIN_CONC" ] && conc=$MIN_CONC
  rate=$((rate * 3 / 4)); [ "$rate" -lt 500 ] && rate=500
  echo "backing off ${BACKOFF}s, next attempt at concurrency=$conc rate=$rate"
  sleep "$BACKOFF"
done
echo "checkpoint: $CKPT (remove it to start over)"
