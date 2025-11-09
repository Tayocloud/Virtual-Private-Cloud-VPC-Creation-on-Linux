#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./cleanup.sh
echo "Running cleanup.sh (best-effort). You must run as root."

# 1) remove namespaces matching vpc naming convention
for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
  if [[ "$ns" =~ ^.*-.* ]]; then
    echo "Deleting namespace: $ns"
    ip netns delete "$ns" || true
  fi
done

# 2) remove bridges that look like br-*
for br in $(ip -o link show | awk -F': ' '{print $2}' | grep '^br-' || true); do
  echo "Deleting bridge: $br"
  ip link set "$br" down 2>/dev/null || true
  ip link del "$br" 2>/dev/null || true
done

# 3) remove orphaned veths (best-effort: those not in namespaces)
for v in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^[a-z0-9-]{2,}' || true); do
  # skip host lo
  if [[ "$v" == "lo" ]]; then continue; fi
  # skip physical interfaces by checking /sys/class/net/<name>/ifindex
  if [[ -d "/sys/class/net/$v" ]] && [[ -z "$(cat /sys/class/net/$v/iflink 2>/dev/null)" ]]; then
    continue
  fi
done

# 4) flush iptables rules added by vpcctl (match on comment 'vpcctl:')
# Remove NAT rules
iptables -t nat -S | grep 'vpcctl:' | while read -r line; do
  delline="${line/-A/-D}"
  echo "Removing iptables (nat) rule: $delline"
  iptables -t nat $delline || true
done

# Remove filter table rules
iptables -S | grep 'vpcctl:' | while read -r line; do
  delline="${line/-A/-D}"
  echo "Removing iptables (filter) rule: $delline"
  iptables $delline || true
done

# 5) flush iptables (optional: only if you accept resetting host firewall)
# echo "Flushing all iptables rules (be careful)..."
# iptables -F || true
# iptables -t nat -F || true

echo "Cleanup complete. Verify with: ip netns list ; ip link show ; iptables -S"
