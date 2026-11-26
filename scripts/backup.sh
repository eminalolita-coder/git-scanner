#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR=${BACKUP_DIR:-"$HOME/gs-backups"}
TS=$(date +%Y%m%d-%H%M%S)
DEST="$BACKUP_DIR/$TS"
mkdir -p "$DEST"

# Collect source directories: repo root + its parent (covers both layouts).
SRC_DIRS=("$REPO")
if [ -d "$REPO/.." ]; then
  SRC_DIRS+=("$(cd "$REPO/.." && pwd)")
fi

echo "=== backup -> $DEST ==="

# hits-* directories from any source dir
seen_dirs=""
for src in "${SRC_DIRS[@]}"; do
  for d in "$src"/hits*; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    case "$seen_dirs" in *" $name "*) continue ;; esac
    seen_dirs="$seen_dirs $name "
    mkdir -p "$DEST/$name"
    cp -a "$d/." "$DEST/$name/" 2>/dev/null
    echo "  $name <- $src ($(du -sh "$d" 2>/dev/null | cut -f1))"
  done
done

# lists and checkpoints from repo root, parent and WSL home
for src in "${SRC_DIRS[@]}" "$HOME"; do
  for f in fresh200k.txt live_hosts.txt t40.txt public_buckets.txt git_hosts.txt \
           buckets_live.txt sample_100000.txt; do
    [ -f "$src/$f" ] && cp "$src/$f" "$DEST/" 2>/dev/null
  done
  for ck in "$src"/*.ckpt; do
    [ -f "$ck" ] || continue
    cp "$ck" "$DEST/" 2>/dev/null
  done
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
