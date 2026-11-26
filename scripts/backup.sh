#!/usr/bin/env bash
# backup.sh - snapshot every scan result (local + VPS) into a timestamped
# folder under BASE/backups. Run it after each pass; nothing is overwritten.
#
# Env:
#   BASE        root directory (default: this script's parent)
#   BACKUP_DIR  destination root (default: $BASE/backups)
#   VPS         user@host to pull from (default: empty = local only)
#   PORT        ssh port (default: 22)
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE=${BASE:-"$(cd "$SCRIPT_DIR/.." && pwd)"}
BACKUP_DIR=${BACKUP_DIR:-"$BASE/backups"}
TS=$(date +%Y%m%d-%H%M%S)
DEST="$BACKUP_DIR/$TS"
mkdir -p "$DEST"

echo "=== backup -> $DEST ==="

for d in hits hits-200k hits-cible hits-cible2 hits-git hits-git2 hits-forge hits-forge2 \
         hits-all hits-fresh hits-fresh2 hits-live hits-phase2 hits-verify hits-reverify \
         hits-reverify2 hits-reverify3 hits-buckets hits-buckets2 hits-buckets3 hits-test \
         hits-vps hits-100k; do
  src="$BASE/$d"
  [ -d "$src" ] || continue
  mkdir -p "$DEST/$d"
  cp -a "$src/." "$DEST/$d/" 2>/dev/null
done

# lists and checkpoints from the local WSL home (if present)
for f in fresh200k.txt live_hosts.txt t40.txt public_buckets.txt git_hosts.txt \
         buckets_live.txt sample_100000.txt; do
  [ -f "$HOME/$f" ] && cp "$HOME/$f" "$DEST/" 2>/dev/null
done
for ck in "$HOME"/*.ckpt; do
  [ -f "$ck" ] || continue
  cp "$ck" "$DEST/" 2>/dev/null
done

if [ -n "${VPS:-}" ]; then
  echo "=== VPS $VPS ==="
  if timeout 8 bash -c "cat < /dev/null > /dev/tcp/${VPS#*@}/22" 2>/dev/null; then
    mkdir -p "$DEST/vps-hits"
    scp -P "${PORT:-22}" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -q \
      -r "$VPS:gs/hits/*" "$DEST/vps-hits/" 2>/dev/null && echo "  hits rapatries"
    scp -P "${PORT:-22}" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -q \
      "$VPS:gs/run.log" "$DEST/vps-run.log" 2>/dev/null && echo "  run.log rapatrie"
    scp -P "${PORT:-22}" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -q \
      "$VPS:gs/lists/*.ckpt" "$DEST/" 2>/dev/null && echo "  checkpoints rapatries"
  else
    echo "  VPS injoignable, backup local uniquement"
  fi
fi

echo
echo "=== backup termine: $DEST ==="
du -sh "$DEST"
