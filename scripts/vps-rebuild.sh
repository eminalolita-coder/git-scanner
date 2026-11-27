#!/usr/bin/env bash
# Reconstruit le VPS de zero apres une reinstallation (le provider remet l'image
# et efface nos cles : voir scripts/vps-bootstrap.sh pour la remise en route ssh).
#
# A executer SUR le VPS, apres avoir pousse le repo et la liste :
#   bash scripts/vps-rebuild.sh /chemin/vers/hosts.txt
set -eu
cd "$(dirname "$0")/.."

LIST=${1:-lists/hosts.txt}

echo "=== 1) resolutif DNS (unbound) ==="
sudo cp scripts/vps-unbound.conf /etc/unbound/unbound.conf.d/gs.conf
sudo cp scripts/vps-unbound-control.conf /etc/unbound/unbound.conf.d/gs-control.conf
sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432 >/dev/null
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null
sudo unbound-checkconf
sudo systemctl restart unbound
sleep 4
systemctl is-active unbound
# sanity: une requete doit repondre
python3 - <<'PY'
import socket, struct, time
tid = 1
pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
t = time.time(); s.sendto(pkt, ("127.0.0.1", 53)); d, _ = s.recvfrom(2048)
print("  dns ok en %.0f ms" % ((time.time()-t)*1000))
PY

echo "=== 2) ulimits ==="
grep -q "gs limits" /etc/security/limits.conf 2>/dev/null || sudo tee -a /etc/security/limits.conf >/dev/null <<'EOF'
# gs limits
* soft nofile 1048576
* hard nofile 1048576
EOF

echo "=== 3) build ==="
export PATH=$PATH:/usr/local/go/bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/git-scanner ./cmd/git-scanner
./bin/git-scanner version

echo "=== 4) liste ==="
wc -l "$LIST" || { echo "liste absente: $LIST"; exit 1; }

echo "=== 5) campagne ciblee (3 chemins + crawl js, 9 regles) ==="
RULES="anthropic-token-strict,aws-ses-smtp-endpoint,aws-ses-smtp-password,aws-ses-smtp-username,mailjet-key,openai-token-strict,sendgrid-token-strict,smtp-credential,smtp-endpoint"
mkdir -p hits-cible
ulimit -n 1048576 || true
TARGETS="$LIST" OUT=hits-cible BIN=bin/git-scanner SKIP_BUILD=1 \
CONCURRENCY=${CONCURRENCY:-40000} RATE=0 TIMEOUT=6 STALL=200 PATHS='/,/.env,/.git/HEAD' \
EXTRA="--crawl-js --js-max 3 --max-body 256 --resolvers 127.0.0.1 --gogc 200 --memlimit 250000 --keep-alive --progress 15 --decode=false --rules $RULES" \
setsid nohup ./scripts/mass-resilient.sh > campagne2.log 2>&1 < /dev/null &
sleep 4
echo "scan: $(pgrep -cf '[g]it-scanner mass') process"
echo "suivre: tail -f campagne2.log"
