#!/usr/bin/env bash
# vps.sh - run the scan on a datacenter box instead of the local connection.
#
# The scanner is CPU/network bound, not disk bound: a small VPS handles
# thousands of requests per second without touching the residential link.
# This script cross-compiles a static binary, uploads it with the supervisor
# script, starts the scan under nohup (survives SSH disconnects) and pulls
# results back.
#
# Usage:
#   VPS=user@1.2.3.4 ./scripts/vps.sh deploy  [targets.txt]
#   VPS=user@1.2.3.4 ./scripts/vps.sh start
#   VPS=user@1.2.3.4 ./scripts/vps.sh status
#   VPS=user@1.2.3.4 ./scripts/vps.sh stop
#   VPS=user@1.2.3.4 ./scripts/vps.sh fetch   [local-dir]
#
# Env:
#   VPS          user@host (required)        PORT    ssh port (22)
#   DIR          remote directory (gs)       CONCURRENCY (4000)
#   RATE         requests/second (3000)      TIMEOUT (6)
#   ARCH         linux/amd64 or linux/arm64  (auto-detected)
#   SSH_OPTS     extra ssh options
set -u

VPS=${VPS:-}
PORT=${PORT:-22}
DIR=${DIR:-gs}
CONCURRENCY=${CONCURRENCY:-4000}
RATE=${RATE:-3000}
TIMEOUT=${TIMEOUT:-6}
SSH_OPTS=${SSH_OPTS:-}

cd "$(dirname "$0")/.." || exit 1
cmd=${1:-}
[ -n "$VPS" ] || { echo "set VPS=user@host"; exit 1; }

ssh_run() { ssh -p "$PORT" $SSH_OPTS "$VPS" "$@"; }

remote_arch() {
  ssh_run 'uname -m' | tr -d '\r' | sed 's/^x86_64$/amd64/; s/^aarch64$/arm64/; s/^arm64$/arm64/'
}

case "$cmd" in
deploy)
  TARGETS=${2:-hosts.txt}
  [ -f "$TARGETS" ] || { echo "missing targets file: $TARGETS"; exit 1; }
  ARCH=${ARCH:-$(remote_arch)}
  echo "== build linux/$ARCH"
  mkdir -p dist
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go build -trimpath -ldflags "-s -w" -o dist/git-scanner "./cmd/git-scanner" || exit 1

  echo "== upload to $VPS:$DIR"
  ssh_run "mkdir -p '$DIR/bin' '$DIR/lists' '$DIR/hits' '$DIR/scripts'"
  scp -P "$PORT" $SSH_OPTS -q dist/git-scanner "$VPS:$DIR/bin/git-scanner"
  scp -P "$PORT" $SSH_OPTS -q scripts/mass-resilient.sh scripts/tune-linux.sh "$VPS:$DIR/scripts/"
  scp -P "$PORT" $SSH_OPTS -q "$TARGETS" "$VPS:$DIR/lists/$(basename "$TARGETS")"
  ssh_run "chmod +x '$DIR/bin/git-scanner' '$DIR/scripts/'*.sh"

  echo "== start"
  NAME=$(basename "$TARGETS")
  ssh_run "cd '$DIR' && TARGETS='lists/$NAME' OUT=hits BIN='bin/git-scanner' SKIP_BUILD=1 \
    CONCURRENCY=$CONCURRENCY RATE=$RATE TIMEOUT=$TIMEOUT \
    setsid nohup ./scripts/mass-resilient.sh > run.log 2>&1 < /dev/null & sleep 1; echo started"
  echo
  echo "follow with: VPS=$VPS ./scripts/vps.sh status"
  ;;
start)
  NAME=${2:-$(ssh_run "ls '$DIR/lists' | head -1" | tr -d '\r')}
  ssh_run "cd '$DIR' && TARGETS='lists/$NAME' OUT=hits BIN='bin/git-scanner' SKIP_BUILD=1 \
    CONCURRENCY=$CONCURRENCY RATE=$RATE TIMEOUT=$TIMEOUT \
    setsid nohup ./scripts/mass-resilient.sh > run.log 2>&1 < /dev/null & sleep 1; echo started $NAME"
  ;;
status)
  ssh_run "cd '$DIR' && tail -6 run.log 2>/dev/null; echo '---'; \
    if pgrep -f 'git-scanner mass' >/dev/null; then echo 'etat: EN COURS'; else echo 'etat: ARRETE'; fi; \
    echo -n 'findings: '; cat hits/*.jsonl 2>/dev/null | wc -l; \
    echo -n 'checkpoint: '; wc -l < lists/*.ckpt 2>/dev/null || echo 0; \
    echo -n 'load: '; cat /proc/loadavg"
  ;;
stop)
  ssh_run "pkill -f 'mass-resilient' ; pkill -f 'git-scanner mass' ; sleep 1; echo stopped"
  ;;
fetch)
  LOCAL=${2:-hits-vps}
  mkdir -p "$LOCAL"
  scp -P "$PORT" $SSH_OPTS -q -r "$VPS:$DIR/hits/*" "$LOCAL/" || true
  scp -P "$PORT" $SSH_OPTS -q "$VPS:$DIR/lists/*.ckpt" "$LOCAL/" 2>/dev/null || true
  scp -P "$PORT" $SSH_OPTS -q "$VPS:$DIR/run.log" "$LOCAL/run.log" 2>/dev/null || true
  echo "results -> $LOCAL"
  ls -la "$LOCAL" | tail -5
  ;;
tune)
  scp -P "$PORT" $SSH_OPTS -q scripts/tune-linux.sh "$VPS:$DIR/scripts/"
  ssh_run "sudo bash '$DIR/scripts/tune-linux.sh' 2>/dev/null || bash '$DIR/scripts/tune-linux.sh'"
  ;;
*)
  sed -n '2,30p' "$0"
  exit 1
  ;;
esac
