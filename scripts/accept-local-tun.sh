#!/usr/bin/env bash
set -euo pipefail

# scripts/accept-local-tun.sh: End-to-end acceptance test for Subnetra TUN device mode
# using Linux network namespaces (ns-hub, ns-a, ns-b).
#
# Topology:
#   [ns-a]  rove-hop (spoke, 10.0.0.2/24) via veth-a (192.168.188.2)
#     \
#      --> [ns-hub] rove (hub, 10.0.0.1/24) via veth-hub (192.168.188.1:18020)
#     /
#   [ns-b]  rove-hop (spoke, 10.0.0.3/24) via veth-b (192.168.188.3)
#
# Requires: Linux, root (CAP_NET_ADMIN), ip, ping, python3.

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: accept-local-tun.sh requires Linux network namespaces (current OS: $(uname -s))"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "SKIP: accept-local-tun.sh requires root privileges (e.g. sudo)"
  exit 0
fi

for cmd in ip ping python3 cargo; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: missing required command: $cmd" >&2
    exit 1
  fi
done

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rove-tun-accept.XXXXXX")"

ROVE_BIN="${ROVE_BIN:-$ROOT_DIR/target/debug/rove}"
ROVE_HOP_BIN="${ROVE_HOP_BIN:-$ROOT_DIR/target/debug/rove-hop}"

# Build debug binaries if missing
if [[ ! -x "$ROVE_BIN" || ! -x "$ROVE_HOP_BIN" ]]; then
  echo "==> Building rove and rove-hop binaries..."
  cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --bin rove --bin rove-hop
fi

if [[ ! -x "$ROVE_BIN" || ! -x "$ROVE_HOP_BIN" ]]; then
  echo "ERROR: binaries not found: $ROVE_BIN or $ROVE_HOP_BIN" >&2
  exit 1
fi

NS_HUB="ns-rove-hub"
NS_A="ns-rove-a"
NS_B="ns-rove-b"
BRIDGE="br-rove-test"

HUB_PID=""
HOP_A_PID=""
HOP_B_PID=""
TCP_SRV_PID=""

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM

  echo "==> Cleaning up acceptance test resources..."
  for pid in "$TCP_SRV_PID" "$HOP_A_PID" "$HOP_B_PID" "$HUB_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done

  ip link del "$BRIDGE" 2>/dev/null || true
  ip netns del "$NS_HUB" 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true

  rm -rf "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

echo "==> Setting up network namespaces and bridge..."
ip netns add "$NS_HUB"
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up

# Setup veth pairs for each namespace
ip link add veth-hub type veth peer name veth-hub-br
ip link set veth-hub netns "$NS_HUB"
ip link set veth-hub-br master "$BRIDGE"
ip link set veth-hub-br up

ip link add veth-a type veth peer name veth-a-br
ip link set veth-a netns "$NS_A"
ip link set veth-a-br master "$BRIDGE"
ip link set veth-a-br up

ip link add veth-b type veth peer name veth-b-br
ip link set veth-b netns "$NS_B"
ip link set veth-b-br master "$BRIDGE"
ip link set veth-b-br up

# Configure underlay IPs in namespaces
ip netns exec "$NS_HUB" ip addr add 192.168.188.1/24 dev veth-hub
ip netns exec "$NS_HUB" ip link set veth-hub up
ip netns exec "$NS_HUB" ip link set lo up

ip netns exec "$NS_A" ip addr add 192.168.188.2/24 dev veth-a
ip netns exec "$NS_A" ip link set veth-a up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add 192.168.188.3/24 dev veth-b
ip netns exec "$NS_B" ip link set veth-b up
ip netns exec "$NS_B" ip link set lo up

# Verify underlay connectivity
ip netns exec "$NS_A" ping -c 1 -W 2 192.168.188.1 >/dev/null
ip netns exec "$NS_B" ping -c 1 -W 2 192.168.188.1 >/dev/null

PSK_HUB_A="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PSK_HUB_B="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

# Generate hub config
cat > "$TMP_DIR/hub.toml" <<EOF
[subnetra]
enable = true
mode = "hub"
device = "tun"
local_id = 1
listen = "192.168.188.1:18020"
overlay_cidr = "10.0.0.1/24"
obfuscate = false
keepalive_secs = 25
mtu = 1400

[subnetra.tun]
name = "rove0"
manage = true

[[subnetra.peers]]
id = 2
psk = "$PSK_HUB_A"
allowed_src = "10.0.0.2/32"
name = "spoke-a"

[[subnetra.peers]]
id = 3
psk = "$PSK_HUB_B"
allowed_src = "10.0.0.3/32"
name = "spoke-b"
EOF

# Generate spoke A config
cat > "$TMP_DIR/spoke-a.toml" <<EOF
[subnetra]
enable = true
mode = "spoke"
device = "tun"
local_id = 2
listen = "0.0.0.0:0"
overlay_cidr = "10.0.0.2/24"
obfuscate = false
keepalive_secs = 2
mtu = 1400

[subnetra.tun]
name = "rove0"
manage = true

[[subnetra.peers]]
id = 1
psk = "$PSK_HUB_A"
allowed_src = "10.0.0.0/24"
endpoint = "192.168.188.1:18020"
name = "hub"
EOF

# Generate spoke B config
cat > "$TMP_DIR/spoke-b.toml" <<EOF
[subnetra]
enable = true
mode = "spoke"
device = "tun"
local_id = 3
listen = "0.0.0.0:0"
overlay_cidr = "10.0.0.3/24"
obfuscate = false
keepalive_secs = 2
mtu = 1400

[subnetra.tun]
name = "rove0"
manage = true

[[subnetra.peers]]
id = 1
psk = "$PSK_HUB_B"
allowed_src = "10.0.0.0/24"
endpoint = "192.168.188.1:18020"
name = "hub"
EOF

echo "==> Starting hub in $NS_HUB..."
RUST_LOG=info ip netns exec "$NS_HUB" "$ROVE_BIN" --config "$TMP_DIR/hub.toml" > "$TMP_DIR/hub.log" 2>&1 &
HUB_PID=$!

wait_for_tun() {
  local ns="$1"
  local ifname="$2"
  local pid="$3"
  local attempt=0
  while [[ "$attempt" -lt 50 ]]; do
    attempt=$((attempt + 1))
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "ERROR: process $pid in $ns died unexpectedly" >&2
      return 1
    fi
    if ip netns exec "$ns" ip link show "$ifname" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "ERROR: timed out waiting for $ifname in $ns" >&2
  return 1
}

wait_for_tun "$NS_HUB" "rove0" "$HUB_PID" || {
  cat "$TMP_DIR/hub.log" >&2
  exit 1
}
echo "PASS: rove hub started and created rove0 (10.0.0.1/24)"

echo "==> Starting spoke A in $NS_A..."
RUST_LOG=info ip netns exec "$NS_A" "$ROVE_HOP_BIN" --subnetra-config "$TMP_DIR/spoke-a.toml" > "$TMP_DIR/spoke-a.log" 2>&1 &
HOP_A_PID=$!
wait_for_tun "$NS_A" "rove0" "$HOP_A_PID" || {
  cat "$TMP_DIR/spoke-a.log" >&2
  exit 1
}
echo "PASS: rove-hop spoke A started and created rove0 (10.0.0.2/24)"

echo "==> Starting spoke B in $NS_B..."
RUST_LOG=info ip netns exec "$NS_B" "$ROVE_HOP_BIN" --subnetra-config "$TMP_DIR/spoke-b.toml" > "$TMP_DIR/spoke-b.log" 2>&1 &
HOP_B_PID=$!
wait_for_tun "$NS_B" "rove0" "$HOP_B_PID" || {
  cat "$TMP_DIR/spoke-b.log" >&2
  exit 1
}
echo "PASS: rove-hop spoke B started and created rove0 (10.0.0.3/24)"

# Give keepalive packets 1-2 seconds to establish sessions with hub
sleep 2

echo "==> Testing ICMP echo from spoke A (10.0.0.2) to hub (10.0.0.1)..."
if ! ip netns exec "$NS_A" ping -c 3 -W 2 10.0.0.1 >/dev/null; then
  echo "ERROR: ping from spoke A to hub failed" >&2
  cat "$TMP_DIR/hub.log" >&2
  cat "$TMP_DIR/spoke-a.log" >&2
  exit 1
fi
echo "PASS: spoke A -> hub (10.0.0.1) ping successful"

echo "==> Testing ICMP echo from spoke A (10.0.0.2) to spoke B (10.0.0.3) relayed via hub..."
if ! ip netns exec "$NS_A" ping -c 3 -W 2 10.0.0.3 >/dev/null; then
  echo "ERROR: ping from spoke A to spoke B failed" >&2
  cat "$TMP_DIR/hub.log" >&2
  cat "$TMP_DIR/spoke-a.log" >&2
  cat "$TMP_DIR/spoke-b.log" >&2
  exit 1
fi
echo "PASS: spoke A -> spoke B (10.0.0.3) ping successful"

echo "==> Testing bidirectional TCP data transfer over overlay (spoke A <-> spoke B)..."
# Start a simple Python TCP echo server in ns-b on 10.0.0.3:2222
ip netns exec "$NS_B" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.3", 2222))
s.listen(1)
conn, addr = s.accept()
data = conn.recv(1024)
conn.sendall(data)
conn.close()
s.close()
' > "$TMP_DIR/tcp_srv.log" 2>&1 &
TCP_SRV_PID=$!

sleep 0.5

# Connect and verify echo from spoke A
ECHO_RESP=$(ip netns exec "$NS_A" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5.0)
s.connect(("10.0.0.3", 2222))
s.sendall(b"HELLO_SUBNETRA_TUN_MESH")
resp = s.recv(1024)
s.close()
print(resp.decode("utf-8", errors="replace"))
')

if [[ "$ECHO_RESP" != "HELLO_SUBNETRA_TUN_MESH" ]]; then
  echo "ERROR: unexpected TCP echo response: $ECHO_RESP" >&2
  cat "$TMP_DIR/tcp_srv.log" >&2
  exit 1
fi
echo "PASS: TCP echo transfer between spoke A and spoke B matched payload"

echo "==> Verifying managed TUN device teardown upon process exit..."
kill "$HOP_A_PID"
wait "$HOP_A_PID" 2>/dev/null || true
HOP_A_PID=""

if ip netns exec "$NS_A" ip link show rove0 >/dev/null 2>&1; then
  echo "ERROR: rove0 should be automatically removed when rove-hop exits" >&2
  exit 1
fi
echo "PASS: managed TUN device rove0 was automatically destroyed on process exit"

echo "==> ALL SUBNETRA TUN ACCEPTANCE TESTS PASSED SUCCESSFULLY!"
exit 0
