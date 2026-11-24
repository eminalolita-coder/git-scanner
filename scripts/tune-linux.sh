#!/usr/bin/env bash
# tune-linux.sh - kernel/limits tuning for git-scanner mass mode.
# Targets a datacenter host (many concurrent connections, 10Gb/s NIC).
# Idempotent. Run as root (or with sudo).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "root required (use sudo)"; exit 1
fi

SYSCTL_FILE=/etc/sysctl.d/99-git-scanner.conf

echo "== before =="
sysctl net.core.somaxconn net.ipv4.ip_local_port_range fs.file-max 2>/dev/null || true
echo "ulimit -n (soft) = $(ulimit -Sn)"

cat >"$SYSCTL_FILE" <<'EOF'
# git-scanner mass scanning: many short-lived concurrent connections
fs.file-max = 2097152
fs.nr_open = 2097152

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.optmem_max = 134217728

net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2097152
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rmem = 4096 1048576 134217728
net.ipv4.tcp_wmem = 4096 1048576 134217728
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1

# conntrack (only meaningful when a firewall/NAT is active)
net.netfilter.nf_conntrack_max = 2097152
EOF

# drop keys missing on this kernel (netfilter module not loaded, etc.)
while read -r key _; do
  case "$key" in \#*|"") continue;; esac
  if ! sysctl -n "$key" >/dev/null 2>&1; then
    sed -i "\|^$key|d" "$SYSCTL_FILE"
    echo "  skip (absent): $key"
  fi
done <"$SYSCTL_FILE"

sysctl -p "$SYSCTL_FILE" >/dev/null

# BBR congestion control if available
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
  sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null || true
  sysctl -w net.core.default_qdisc=fq >/dev/null || true
  echo "  congestion control: bbr"
fi

# raise the fd limit for future logins
LIMITS=/etc/security/limits.d/99-git-scanner.conf
cat >"$LIMITS" <<'EOF'
*  soft  nofile  1048576
*  hard  nofile  1048576
EOF
echo "wrote $LIMITS"

echo "== after =="
sysctl net.core.somaxconn net.ipv4.ip_local_port_range net.ipv4.tcp_tw_reuse fs.file-max
echo
echo "Now, in your shell:  ulimit -n 1048576"
echo "Then run, e.g.:"
echo "  git-scanner mass hosts.txt --profile vps --scheme http --method get \\"
echo "    --concurrency 20000 --timeout 3 -o hits"
