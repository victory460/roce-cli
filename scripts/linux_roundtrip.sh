#!/usr/bin/env bash
# Run as root on Linux. Creates only isolated namespaces/veth, no physical NIC traffic.
set -euo pipefail
BIN="${1:-./bin/roce-cli}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
OUT="${2:-$(mktemp -d /tmp/roce-cli-roundtrip.XXXXXX)}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[[ $(id -u) == 0 ]] || { echo 'Run as root on Linux (network namespace permissions required).' >&2; exit 2; }
command -v ip >/dev/null
command -v timeout >/dev/null
[[ -x "$BIN" ]] || { echo "Missing executable: $BIN" >&2; exit 2; }
TX="roce-tx-$$"
RX="roce-rx-$$"
RX_PID=""
cleanup() {
  if [[ -n "$RX_PID" ]]; then kill "$RX_PID" 2>/dev/null || true; wait "$RX_PID" 2>/dev/null || true; fi
  ip netns del "$TX" 2>/dev/null || true
  ip netns del "$RX" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$TX"
ip netns add "$RX"
ip -n "$TX" link add tx0 type veth peer name rx0
ip -n "$TX" link set rx0 netns "$RX"
ip -n "$TX" link set tx0 address 02:00:00:00:00:01
ip -n "$RX" link set rx0 address 02:00:00:00:00:02
ip -n "$TX" address add 192.0.2.1/24 dev tx0
ip -n "$RX" address add 192.0.2.2/24 dev rx0
ip -n "$TX" link set tx0 up
ip -n "$RX" link set rx0 up

run_case() {
  local name="$1" expected="$2"
  shift 2
  [[ ! -e "$OUT/$name.pcap" && ! -e "$OUT/$name.jsonl" && ! -e "$OUT/$name.log" ]] || { echo "Output already exists: $name" >&2; exit 2; }
  ip netns exec "$RX" timeout 10 "$BIN" receive --interface rx0 --count 3 --strict --json \
    --pcap "$OUT/$name.pcap" >"$OUT/$name.jsonl" 2>"$OUT/$name.log" &
  RX_PID=$!
  local ready=0
  for ((i=0;i<100;i++)); do
    if grep -q '^ready ' "$OUT/$name.log"; then ready=1; break; fi
    kill -0 "$RX_PID" 2>/dev/null || break
    sleep 0.05
  done
  [[ "$ready" == 1 ]] || { cat "$OUT/$name.log" >&2; echo 'Receiver did not become ready.' >&2; exit 1; }
  ip netns exec "$TX" "$BIN" send --interface tx0 \
    --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
    --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 --count 3 --interval 20ms "$@"
  local code=0
  wait "$RX_PID" || code=$?
  RX_PID=""
  [[ "$code" == "$expected" ]] || { cat "$OUT/$name.log" >&2; echo "Unexpected receive status $code for $name" >&2; exit 1; }
  grep -q '^received frames=3 ' "$OUT/$name.log"
  code=0
  "$BIN" inspect --pcap "$OUT/$name.pcap" --strict >/dev/null || code=$?
  [[ "$code" == "$expected" ]] || { echo "Unexpected inspect status $code for $name" >&2; exit 1; }
  echo "PASS: $name"
}
run_case send 0 --payload-hex deadbeef
run_case write 0 --template write-only --remote-addr 0x1000 --rkey 0x1234 --payload-hex 010203
run_case cnp 0 --template cnp
run_case vlan 0 --vlan-id 100 --pcp 3
run_case bad-icrc 1 --bad-icrc
run_case vxlan 0 --encap vxlan --vni 100 \
  --outer-src-mac 02:00:00:00:00:01 --outer-dst-mac 02:00:00:00:00:02 \
  --outer-src-ip 192.0.2.1 --outer-dst-ip 192.0.2.2 --outer-dscp 24 --outer-ecn 3 --ecn 2
printf 'Captures and logs: %s\n' "$OUT"
