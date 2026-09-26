# Linux 隔离实发验收

状态：当前 macOS 开发环境未执行实发步骤，Docker daemon 不可用。所有步骤只在两个隔离 network namespace 之间发送，不连接物理网卡。

## 使用 roce-cli 完成收发闭环

需要 Linux、root、iproute2 和 coreutils 的 timeout。构建本机版本后运行：

```bash
make build
sudo bash scripts/linux_roundtrip.sh ./bin/roce-cli
```

脚本启动 receive 后等待 ready，再执行 send，验证 SEND/WRITE/CNP/VLAN/坏 ICRC/VXLAN 六类报文各三帧，并用 inspect 检查捕获 PCAP。正常场景退出码 0，坏 ICRC 场景预期为 1；所有场景通过才打印全部 PASS。脚本自动清理 namespace，保存 PCAP、逐帧 JSON 和统计日志，结果路径在末尾输出。

当前只验证了脚本语法及使用的离线 CLI 参数，尚未在 Linux 上运行。虚拟 veth 收发也不能替代 RNIC/VTEP 的硬件验收。

## 使用 tcpdump 提供独立接收证据

下面的附加步骤需要 Linux、root、iproute2、tcpdump、Python 3，避免仅用同一工具的收发结果相互证明。

先在 Linux 上构建 `make build`（或选用匹配架构的交叉编译产物），进入仓库根目录。在 root 的 Bash 中执行：

```bash
set -euo pipefail
BIN="$(pwd)/bin/roce-cli"
CAP="$(pwd)/capture.pcap"
TX="roce-tx-$$"
RX="roce-rx-$$"
CAP_PID=""
cleanup() {
  if [ -n "$CAP_PID" ]; then kill "$CAP_PID" 2>/dev/null || true; fi
  ip netns del "$TX" 2>/dev/null || true
  ip netns del "$RX" 2>/dev/null || true
}
# 不覆盖已有抓包。
test ! -e "$CAP"
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
ip netns exec "$RX" timeout 10 tcpdump -U -ni rx0 -c 5 -w "$CAP" 'udp dst port 4791' &
CAP_PID=$!
# 等待 tcpdump 输出 listening on rx0；一秒足够常规环境，慢机器应延长。
sleep 1
ip netns exec "$TX" "$BIN" send --interface tx0 \
  --dst-mac 02:00:00:00:00:02 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --psn-list 100,101,101,103,102 --interval 100ms --payload-hex deadbeef
wait "$CAP_PID"
CAP_PID=""
```

预期：本地摘要 `submitted frames=5 status=complete`（摘要中有其他字段），tcpdump 捕获恰好 5 帧，进程退出码为 0。
如果捕获超时，先确认 tcpdump 已 ready；不要将“submitted=5”作为抓包成功的替代。

用独立 Scapy 环境检查（可以将 capture.pcap 拷回 macOS）：

```bash
.venv/bin/python - <<'PY'
from scapy.all import rdpcap, IP, UDP
from scapy.contrib.roce import BTH
p = rdpcap('capture.pcap')
assert len(p) == 5
assert [x[BTH].psn for x in p] == [100, 101, 101, 103, 102]
assert all(x[IP].src == '192.0.2.1' and x[UDP].dport == 4791 and x[BTH].dqpn == 0x123 for x in p)
print('veth count and sequence verified')
PY
```

后续实发验收：

1. 对照相同参数的 build PCAP，比较收到的帧字节（抓包环境可能剥离 VLAN 或最小以太网 padding，需说明差异）。
2. 在上述 namespace 内测试 `--duration 100ms --interval 1h`，确认约 100ms 结束；使用 `--continuous --interval 1h` 后发 SIGTERM，确认退出码 130，停止后没有追加帧。
3. 设置 tx0 MTU=68，再用超过 68 字节 IP 的 payload，确认零帧且返回错误。
4. 分别测试 VLAN、VXLAN、WRITE、CNP 和坏 ICRC，按字段和校验核对抓包。抓取 VXLAN 时将过滤端口改为 4789；若测试 VLAN，应去除原有 BPF 或加入对应的 VLAN 过滤条件。

真实设备验收另行记录交换机转发/QoS/ECN、VTEP 解封装、RNIC 丢弃/错误计数；需要真实 RDMA 完成证明时使用配套连接与完成队列工具。本项目不提供这些端点状态。
