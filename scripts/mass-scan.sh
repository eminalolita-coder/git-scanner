#!/usr/bin/env bash
# mass-scan.sh - end-to-end wrapper: limits -> (optional) kernel tuning -> scan.
#
# Usage:
#   TARGETS=hosts.txt OUT=hits sudo -E ./scripts/mass-scan.sh
#
# Env knobs (all optional):
#   TARGETS      input file, one "host" or "host ip" per line   (default hosts.txt)
#   OUT          output directory                               (default hits)
#   CONCURRENCY  in-flight hosts                                (default 20000)
#   TIMEOUT      per-request timeout seconds                    (default 3)
#   SCHEME       https|http|auto                                (default http)
#   METHOD       get|head                                       (default get)
#   MAXBODY      max response body KB                           (default 256)
#   PROFILE      auto|small|vps|max                             (default vps)
#   ULIMIT       file descriptor soft limit                     (default 1048576)
#   TUNE         1 = also run tune-linux.sh (needs root)        (default 0)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=${TARGETS:-hosts.txt}
OUT=${OUT:-hits}
CONCURRENCY=${CONCURRENCY:-20000}
TIMEOUT=${TIMEOUT:-3}
SCHEME=${SCHEME:-http}
METHOD=${METHOD:-get}
MAXBODY=${MAXBODY:-256}
PROFILE=${PROFILE:-vps}
ULIMIT=${ULIMIT:-1048576}
TUNE=${TUNE:-0}

[ -f "$TARGETS" ] || { echo "targets file not found: $TARGETS"; exit 1; }

ulimit -n "$ULIMIT" 2>/dev/null || echo "warning: could not raise ulimit -n"
echo "ulimit -n = $(ulimit -n)   cpu = $(nproc)   targets = $(wc -l < "$TARGETS")"

if [ "$TUNE" = "1" ]; then
  echo "== kernel tuning =="
  sudo ./scripts/tune-linux.sh
fi

echo "== build =="
go build -ldflags "-s -w" -o git-scanner ./cmd/git-scanner

echo "== scan =="
exec ./git-scanner mass "$TARGETS" \
  --profile "$PROFILE" --concurrency "$CONCURRENCY" --timeout "$TIMEOUT" \
  --scheme "$SCHEME" --method "$METHOD" --max-body "$MAXBODY" \
  -o "$OUT" --format jsonl --progress 15
