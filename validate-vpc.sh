#!/usr/bin/env bash
# Usage: sudo ./validate-vpc.sh <vpc-name> <public-ip> <private-ip>
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <vpc> <public-ip> <private-ip>"
  exit 2
fi

VPC=$1
PUB_IP=$2
PRIV_IP=$3

echo "Testing connectivity for VPC=$VPC"
echo "1) public -> private (expect PASS)"
if sudo ip netns exec ${VPC}-public ping -c 2 ${PRIV_IP} >/dev/null 2>&1; then
  echo "  [PASS] public -> private"
else
  echo "  [FAIL] public -> private"
fi

echo "2) public -> internet (8.8.8.8) (expect PASS)"
if sudo ip netns exec ${VPC}-public ping -c 2 8.8.8.8 >/dev/null 2>&1; then
  echo "  [PASS] public -> internet"
else
  echo "  [FAIL] public -> internet"
fi

echo "3) private -> internet (8.8.8.8) (expect FAIL)"
if sudo ip netns exec ${VPC}-private ping -c 2 8.8.8.8 >/dev/null 2>&1; then
  echo "  [FAIL] private -> internet (should not have outbound)"
else
  echo "  [PASS] private -> internet blocked"
fi

echo "4) curl public http (expect PASS)"
if curl -s --max-time 5 http://${PUB_IP} >/dev/null 2>&1; then
  echo "  [PASS] curl to public webserver"
else
  echo "  [FAIL] curl to public webserver"
fi

echo "Validation complete."
