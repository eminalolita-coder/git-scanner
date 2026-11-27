#!/usr/bin/env bash
# vps-bootstrap.sh - prepare a fresh Ubuntu box to run the scanner at scale.
#
# Bakes in every tuning step that was needed on the previous host:
#   - unbound as a local recursive resolver (the public resolvers throttle,
#     and only local resolution gets anywhere near the needed rate)
#   - no search domain in resolv.conf (Go otherwise queries
#     <host>.<searchdomain> for every single host, ~2x the DNS load)
#   - unbound pointed at 127.0.0.1 directly, with the fd limit raised for its
#     socket count
#   - kernel socket/buffer tuning
#
# Run it ON the new box (needs sudo). Then, from the workstation:
#   VPS=user@NEW_IP ./scripts/vps.sh deploy ~/domaines.txt
set -eu

# always go through sudo: with an empty $SUDO, bash stops treating a following
# VAR=value as an assignment prefix and tries to run it as a command
SUDO=sudo

# unbound threads: enough to keep many recursions in flight, capped so the
# socket count stays sane (threads x outgoing-range fds)
NUM_THREADS=${NUM_THREADS:-$(nproc)}
[ "$NUM_THREADS" -gt 64 ] && NUM_THREADS=64
echo "== threads unbound: $NUM_THREADS (nproc=$(nproc))"

echo "== 1. paquets"
$SUDO apt-get update -qq
$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unbound curl python3 >/dev/null

echo "== 2. noyau (sockets, buffers)"
$SUDO tee /etc/sysctl.d/99-gs.conf >/dev/null <<'EOF'
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=4194304
net.core.wmem_default=4194304
net.core.netdev_max_backlog=250000
net.core.somaxconn=65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
fs.file-max=2097152
EOF
$SUDO sysctl -q --system

echo "== 3. limites de fichiers"
$SUDO tee /etc/security/limits.d/99-gs.conf >/dev/null <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

echo "== 4. unbound (resolver local recursif)"
$SUDO mkdir -p /etc/systemd/system/unbound.service.d
$SUDO tee /etc/systemd/system/unbound.service.d/override.conf >/dev/null <<'EOF'
[Service]
LimitNOFILE=4194304
EOF
$SUDO tee /etc/unbound/unbound.conf.d/gs.conf >/dev/null <<'EOF'
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    num-threads: 48
    msg-cache-size: 1g
    rrset-cache-size: 2g
    cache-max-ttl: 7200
    cache-min-ttl: 300
    prefetch: yes
    so-reuseport: yes
    so-rcvbuf: 16m
    so-sndbuf: 16m
    outgoing-range: 8192
    num-queries-per-thread: 8192
    verbosity: 1
    do-daemonize: yes
    hide-identity: yes
    hide-version: yes
EOF
$SUDO sed -i "s/^    num-threads: .*/    num-threads: $NUM_THREADS/" /etc/unbound/unbound.conf.d/gs.conf
$SUDO systemctl daemon-reload
$SUDO systemctl restart unbound
sleep 4
echo "   unbound: $($SUDO systemctl is-active unbound)"

echo "== 5. resolv.conf statique (sans domaine de recherche)"
$SUDO cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
$SUDO rm -f /etc/resolv.conf
$SUDO tee /etc/resolv.conf >/dev/null <<'EOF'
# static: unbound local, pas de search domain (sinon Go double les requetes)
nameserver 127.0.0.1
options ndots:1 timeout:5 attempts:2
EOF

echo "== 6. verification"
python3 - <<'PY'
import socket, time
for h in ('google.com', 'github.com', 'cloudflare.com'):
    t = time.time()
    try:
        ip = socket.gethostbyname(h)
        print('   %-18s -> %s (%.0f ms)' % (h, ip, (time.time()-t)*1000))
    except Exception as e:
        print('   %-18s ECHEC %s' % (h, e))
PY

cat <<'EOF'

== pret. Depuis la machine locale :
   VPS=user@IP ./scripts/vps.sh deploy ~/domaines.txt
   VPS=user@IP CONCURRENCY=15000 TIMEOUT=4 \
     PATHS='/,/.env,/.git/HEAD' \
     EXTRA='--max-body 128 --resolvers 127.0.0.1 --gogc 300 --memlimit 120000 --progress 15' \
     ./scripts/vps.sh start
EOF
