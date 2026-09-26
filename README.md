# RoCE CLI

面向网络调试的 RoCEv2 报文构造、发送、接收与校验工具，命令为 `roce-cli`（原 `roce-sender`）。
支持 RC SEND_ONLY、RC RDMA_WRITE_ONLY、CNP、802.1Q VLAN、VXLAN、DSCP/ECN、PSN/端口序列和 ICRC 异常注入。
默认直接构造 RoCEv2（`--encap none`）。VXLAN 是针对隧道网络验证的可选封装，不是 RoCE 的协议依赖。

`build` 离线导出 PCAP 或十六进制，macOS/Linux 均可运行，不需要 root 或 RDMA 网卡。
`send` 在 Linux 上通过 AF_PACKET 提交以太帧，需要 root 或 CAP_NET_RAW。
`receive` 在 Linux 上捕获入方向报文，解析字段、验证校验和，并可保存 PCAP；`inspect` 在 macOS/Linux 上离线检查 PCAP。
工具不建立 RDMA 连接或 QP，也不发送 ACK；`generated` 表示已生成，`submitted` 表示本机成功提交，`received` 表示在该接收接口观察到并成功解析，均不表示 RDMA 操作完成。

## 命令速查

| 命令 | 用途 | 平台与权限 |
| --- | --- | --- |
| `roce-cli build` | 从参数生成 PCAP/hex | macOS/Linux，无需 root |
| `roce-cli send` | 发送原始以太帧 | Linux，root 或 CAP_NET_RAW |
| `roce-cli receive`（别名 `recv`） | 捕获、解析、校验，可保存 PCAP | Linux，root 或 CAP_NET_RAW |
| `roce-cli inspect` | 流式解析经典 Ethernet PCAP | macOS/Linux，无需 root |
| `roce-cli version` | 查看构建版本 | 无需 root |

使用 `roce-cli help receive` 或 `roce-cli receive --help` 查看相应命令的有效参数。旧发送参数保留，产物和 Go module 已改为 `roce-cli`；工作目录不自动改名，旧二进制不作为兼容入口。

## 用途与适用场景

适用于交换机、DPU、网卡研发和网络交付排障：把需要验证的 RoCE 报文固定下来，先离线检查，再在测试网络中注入，结合抓包与设备计数器复现问题。
发送端可以使用普通以太网卡；仅检查网络转发时，不需要先准备完整 RDMA 应用。

| 场景 | 如何使用 | 需要观察的结果 |
| --- | --- | --- |
| 连通性、ACL 与分类规则 | 固定源/目的 IP 和 UDP 目的端口，按少量 count 发送；更改一个匹配字段作对照 | 接收侧/出口抓包、ACL 命中与丢弃计数；本机 submitted 不证明放行 |
| QoS 队列分类 | 改变 `--dscp` 或 `--vlan-id/--pcp`，对比数据模板和 CNP | 对应队列/策略计数与出口标记；DSCP、PCP 到队列的映射由设备配置决定 |
| ECMP/LAG 流哈希 | 使用 `--src-port-step 1 --count 16 --psn-step 0`，只改变 RoCE UDP 源端口 | 各出口抓包或端口计数；路径是否改变取决于设备哈希字段，不能预设为均匀分布 |
| VTEP 的 VXLAN 封装 | 使用默认 `--encap none`，从接入侧发送普通 RoCE，由被测 VTEP 封装 | 对照接入侧和隧道侧抓包，核对设备生成的 VNI、外层字段及 QoS 映射 |
| VXLAN 隧道转发与解封装 | 使用 `--encap vxlan`，独立设置内外层 DSCP/ECN、VNI、VLAN | 在隧道侧输入与解封装出口抓包，核对转发、内层标记和封装长度；本工具不执行解封装 |
| 重复、跳号、乱序复现 | `--psn-list 100,101,101,103,102` 或 `--psn-step 0` | 抓包检查精确序列；观察 RNIC 响应时还需匹配的 QP 状态，本工具不接收或判断 ACK/NAK |
| ICRC 异常处理 | 以相同字段分别构造正常报文与 `--bad-icrc` 报文 | 比较 RNIC/DPU 校验错误与丢弃计数；普通交换机可能仅转发而不检查 ICRC |
| 报文样本与问题交接 | 用 build 导出 PCAP，保存命令及设备配置，作为解析器测试或工单附件 | 对照字段、校验和、报文长度；固定参数与 interval 可生成相同 PCAP |

上述流哈希示例在直接模式下改变线上 UDP 源端口。VXLAN 模式的 `--src-port-step` 只改变内层端口，外层源端口固定；测试隧道外层哈希时，应分次改变 `--outer-src-port` 并观察设备行为。

### 如何选择模板

- **send-only**：默认的 RC 数据报文模板，用于常规转发、分类、序列与异常校验测试。真实 SEND 接收需要对端 QP 和已投递的接收缓冲区。
- **write-only**：构造带 RETH 的报文，用于检查地址、rkey、长度字段及相关解析路径。填写 remote-addr/rkey 只是在编码报文字段，不会注册内存或创建远端访问权限。
- **cnp**：构造拥塞通知报文，用于验证 CNP 的识别、优先级和转发路径。测试其是否使发送端降速，需要活动的 RDMA 流、匹配的 QP 与外部速率观测。

### RoCE 为什么支持 VXLAN？应该选哪种模式？

普通 RoCE 网络测试使用默认模式即可。支持 VXLAN，是为了在需要隧道承载的测试环境中，直接生成完整的 RoCE over VXLAN 样本，验证隧道转发、解封装、内外层 QoS/ECN 和 MTU 边界。

两种模式的报文结构如下，Ethernet 层均可按需带 VLAN：

```text
--encap none（默认）
Ethernet / IPv4 / UDP / RoCE

--encap vxlan
外层 Ethernet / IPv4 / UDP / VXLAN / 内层 Ethernet / IPv4 / UDP / RoCE
```

选择的关键是**要测试哪台设备的哪一步处理**，而不只是网络中有没有 VXLAN：

| 测试目标 | sender 模式 | 由谁添加 VXLAN 头 |
| --- | --- | --- |
| 普通 RoCE 网络的转发、ACL、QoS | `--encap none` | 不需要添加 |
| 接入侧 VTEP 是否正确封装 RoCE | `--encap none` | 被测 VTEP |
| 已封装流量的隧道转发或远端 VTEP 解封装 | `--encap vxlan` | sender |

```text
验证设备封装：
sender --encap none → 普通 RoCE → 被测 VTEP → VXLAN 隧道 → 远端 VTEP
观察位置：接入侧（封装前）、隧道侧（封装后）

验证隧道转发/解封装：
sender --encap vxlan → 已封装 RoCE → 隧道网络/被测 VTEP → 普通 RoCE 出口
观察位置：隧道侧（解封装前）、出口侧（解封装后）
```

例如，验证设备如何生成外层 DSCP/ECN，应发送普通 RoCE，让设备完成封装；验证收到“外层 CE、内层 ECT(0)”时的解封装处理，则可由 sender 直接构造这组内外层字段。
把已经封装的报文发到普通接入端口，并不能替代对 VTEP 封装能力的测试。

使用 `--encap vxlan` 时，还需按实际拓扑准备以下配置：

- `--outer-dst-ip` 指向接收隧道报文的 VTEP，`--outer-dst-mac` 使用当前链路的目标/下一跳 MAC；外层源地址需符合测试网络配置。
- `--vni` 与被测设备配置对应；无 `outer-` 前缀的地址和 QoS 参数始终描述内层 RoCE 报文。
- 被测设备的隧道、VNI 和转发配置由实验环境提供；sender 不创建 VTEP、不配置控制平面，也不自动发现这些参数。
- `--mtu` 限制最外层 IP 长度，隧道头和内层 VLAN 都占用空间；相同 payload 在直接模式下能构包，不代表加上 VXLAN 后仍能通过该 MTU 检查。

### 一次实验的推荐流程

1. **确定观察点**：选定发送接口、目标/下一跳 MAC、接收侧或交换机出口抓包位置，记录相关 ACL、QoS、VNI 和 MTU 配置。
2. **先生成基线**：用 build 保存少量正常 PCAP，核对字段与封装；build 不访问网络接口，也不会把文件注入网络。
3. **先接收再发送**：在接收端启动 receive，看到 stderr 的 `ready` 后，再在发送端运行 send。send 从参数重新构包，不读取 PCAP 文件。
4. **再做单变量对照**：固定其他参数，每次只改变 DSCP、PCP、端口、PSN 或 ICRC，从有限 count 开始，比较 receive 的逐帧结果和设备计数。
5. **保存观测证据**：记录完整命令、版本、本机摘要、接收侧 PCAP 和设备计数器增量；用 inspect 复查保存的 PCAP。将正常组与异常组对照，避免仅凭发送成功判断网络或端点正常。

| 已有证据 | 能得出的结论 |
| --- | --- |
| `generated frames=N` | N 个完整报文记录已写到指定输出；未发生网络发送 |
| `submitted frames=N` | N 帧已由本机发送调用成功提交；不保证已经上链路或到达对端 |
| `received frames=N` | 在指定接收接口捕获并解析到 N 个匹配帧；结合 valid/invalid 判断捕获字节的校验状态 |
| 对端/出口抓包与设备计数器 | 支持判断对应观察点的转发、标记与丢弃行为 |
| 端点完成事件、内存内容或业务结果 | 才能支持真实 RDMA 操作完成的结论；需配套端点工具提供 |

### 能力边界

注入 CE 标记用于验证标记传递或端点反应；验证交换机 ECN 阈值、PFC 行为或拥塞控制闭环，还需要外部负载与观测系统。
此工具逐帧构包和发送，不提供线速、微突发、带宽/延迟测量，也不创建 QP、处理重传或维护 RC 连接。
需要真实 RDMA 吞吐、时延或读写完成测试时，应使用配套 RDMA 应用/端点测试工具；网络包样本不能替代端点验收。

## 构建与测试

需要 Go 1.24.2 或更新版本。产品只使用 Go 标准库。

```bash
make build
./bin/roce-cli --help
./bin/roce-cli build --help
make check
make cross
```

`make cross` 生成 `bin/roce-cli-linux-amd64` 和 `bin/roce-cli-linux-arm64`，关闭 CGO。
`make build VERSION=v0.2.0` 可注入版本，使用 `--version` 查看。

## 完整案例：从生成到检查

以下流程不发送网络流量，适合先在 macOS/Linux 上验证工具：

```bash
make build
./bin/roce-cli build \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --psn-list 100,101,101,103,102 --payload-hex deadbeef --pcap demo.pcap
./bin/roce-cli inspect --pcap demo.pcap --strict
./bin/roce-cli inspect --pcap demo.pcap --json > demo.jsonl
```

预期：build 报告 `generated frames=5`，inspect 报告 `inspected frames=5 valid=5 invalid=0`，PSN 顺序为 `100,101,101,103,102`。inspect 与 receive 复用解析器；这一流程证明离线报文字节可解析，不证明真实网络接收。

## 完整案例：Linux 双机发送与接收

假设测试网络中 A 为 `192.0.2.1`，B 为 `192.0.2.2`，两端接口均为 `eth0`。先在两端 `make build`，或将相应架构的交叉编译产物复制为 `roce-cli`。下列 IP、接口和目标 MAC 必须替换为实际环境值；路由场景的目标 MAC 使用发送端下一跳 MAC。

**先在 B 启动接收**，看到 stderr 的 `ready interface=eth0 ...` 后再启动 A：

```bash
sudo ./bin/roce-cli receive --interface eth0 --duration 15s \
  --dqpn 0x123 --strict --pcap received.pcap --json > received.jsonl
```

**在 A 发送五帧**：

```bash
sudo ./bin/roce-cli send --interface eth0 \
  --dst-mac 02:00:00:00:00:02 --src-ip 192.0.2.1 --dst-ip 192.0.2.2 \
  --dqpn 0x123 --psn-list 100,101,101,103,102 \
  --payload-hex deadbeef --interval 100ms
```

**B 接收结束后复查**：

```bash
./bin/roce-cli inspect --pcap received.pcap --strict
```

在没有其他匹配流量且帧均到达的实验中，A 应报告 `submitted frames=5`，B 报告 `received frames=5 valid=5 invalid=0 saved=5`，复查时可看到相同 PSN 顺序。如果 B 收到零帧，strict 返回 1；不要据 A 的 submitted 推断 B 已接收。

异常对照：将接收文件改为新的路径，重启接收，再给 A 的发送命令增加 `--bad-icrc`。若五帧均被捕获，预期 B 的 `invalid=5`，ICRC 为 invalid 而 UDP checksum 仍为 valid；receive/inspect 的 strict 都返回 1。这是预期异常结果，不是程序崩溃。

接收端不会回应 RC ACK/NAK，不需要配置 QP；这套案例验证报文观察与校验，不完成真实 RDMA SEND/WRITE。

## 完整案例：单机隔离网络验证

Linux root 环境可运行以下脚本，自动创建两个 namespace 和 veth，不触碰物理网卡。每个场景先等待接收端 ready，再发三帧，并复查接收 PCAP：

```bash
make build
sudo bash scripts/linux_roundtrip.sh ./bin/roce-cli
```

覆盖 SEND、WRITE、CNP、VLAN、坏 ICRC 和 VXLAN。脚本结束清理 namespace，保留 PCAP/JSON/日志并打印目录；坏 ICRC 场景的预期退出码为 1。VXLAN 场景验证封装字节的接收与解析，不创建真实 VTEP，也不验证设备解封装。

该脚本需要 `ip`、`timeout` 和创建 network namespace 的权限；当前 macOS 环境未实际运行。详见 [Linux 验收说明](docs/linux-validation.md)。

## 离线示例

输出文件默认拒绝覆盖；重新执行时删除自己的旧文件或显式添加 `--overwrite`。
报文摘要写 stderr，PCAP/hex 内容不会混入日志。`--pcap -` 将二进制写 stdout。

重复、跳号与乱序 PSN：

```bash
./bin/roce-cli build \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --psn-list 100,101,101,103,102 --interval 100ms \
  --dscp 24 --ecn 2 --payload-hex deadbeef --pcap sequence.pcap
```

构造 16 个不同 UDP 源端口、固定 PSN 的流哈希样本，同时指定 VLAN/PCP 分类字段：

```bash
./bin/roce-cli build \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --src-port 49152 --src-port-step 1 --psn-step 0 --count 16 \
  --vlan-id 100 --pcp 3 --dscp 24 --pcap flow-hash.pcap
```

这里的 16 帧仅用于产生不同流键，不代表持续的 16 路业务流。要观察实际路径，将同样的报文字段用于 send，并在各出口抓包。

直接构造 VXLAN 外层 CE、内层 ECT(0)，用于隧道侧注入后观察 VTEP 解封装时的 ECN 处理：

```bash
./bin/roce-cli build --encap vxlan --vni 100 \
  --outer-src-mac 02:00:00:00:01:01 --outer-dst-mac 02:00:00:00:01:02 \
  --outer-src-ip 198.51.100.1 --outer-dst-ip 198.51.100.2 \
  --outer-dscp 24 --outer-ecn 3 \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --dscp 24 --ecn 2 --pcap vxlan-ecn.pcap
```

这条命令仅生成已封装的离线样本。实际注入时使用 send，并选择通向被测 VTEP 隧道侧的接口和外层地址。若目标是验证 VTEP 自己的封装行为，则使用普通 RoCE 示例（`--encap none`），由设备生成外层头。

WRITE_ONLY：RETH 长度从 payload 自动计算，三字节数据自动增加一字节协议填充。

```bash
./bin/roce-cli build --template write-only \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --remote-addr 0x1000 --rkey 0x1234 --payload-hex 010203 --pcap write.pcap
```

CNP：固定 PSN=0、BECN=1、16 字节零保留区，默认 UDP 源端口为 0。DSCP 48 仅为示例，应按网络配置选择。

```bash
./bin/roce-cli build --template cnp \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --dscp 48 --count 2 --pcap cnp.pcap
```

故意损坏 ICRC，同时保留正确的 IPv4/UDP 校验和：

```bash
./bin/roce-cli build \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --bad-icrc --payload-hex deadbeef --pcap bad-icrc.pcap
```

将示例中的 `--pcap FILE` 换为 `--hex`，可逐帧输出一行十六进制。增加 `--vlan-id 0 --pcp 7` 可构造优先级标签；VLAN 0 与未指定 VLAN 不同。

## Linux 发送

将下面地址、下一跳 MAC 和接口替换为测试环境配置：

```bash
sudo ./bin/roce-cli-linux-amd64 send --interface eth0 \
  --dst-mac 02:00:00:00:00:02 --dst-ip 192.0.2.2 --dqpn 0x123 \
  --count 10 --interval 100ms
```

直接模式省略源地址时，从接口取得源 MAC 和唯一可用全局单播 IPv4；地址不唯一时需显式指定。
VXLAN 模式只补全最外层源地址，内层四个地址必须显式指定。目标 MAC 总是必填，不自动 ARP。

`--count N`、`--duration 10s`、`--continuous` 互斥。省略时发送一次。
`--psn-list` 按列表发送一次，不循环，不能与显式 count/PSN/step/duration/continuous 组合。
Ctrl+C/SIGTERM 能打断发送间隔与 socket 背压等待；信号退出码为 130，duration 到期为 0。

## 参数规则

### build / send

| 参数 | 默认与约束 |
| --- | --- |
| `--template` | `send-only` / `write-only` / `cnp`，默认 send-only |
| `--dqpn` | 必填，0～0xffffff |
| `--psn` / `--psn-step` | 默认 0 / 1；按 24 位回绕，step=0 为固定值 |
| `--src-port` / `--src-port-step` | 默认 49152 / 0；CNP 源端口默认 0；按 16 位回绕 |
| `--dst-port` / `--pkey` | 默认 4791 / 0xffff |
| `--dscp` / `--ecn` / `--ttl` | 默认 0 / 0 / 64，范围 0～63 / 0～3 / 1～255 |
| `--vlan-id` / `--pcp` | VLAN 0～4094；未指定时无标签，PCP 必须与 VLAN 一起指定 |
| `--remote-addr` / `--rkey` | 仅 WRITE 必填，64/32 位，显式零值合法 |
| `--payload-hex` | 偶数位十六进制，默认空；CNP 禁止指定 |
| `--udp-checksum` | `auto` 或 `zero`，默认 auto |
| `--mtu` | 默认 1500，范围 68～65535，限制最外层 IP 长度；send 还受接口 MTU 限制 |
| `--interval` | 非负 Go duration；build 要求整微秒；send 为两次提交之间的最小间隔 |
| `--encap` / `--vni` | 默认 none；vxlan 时 VNI 必填，1～0xffffff |
| `--outer-*` | VXLAN 独立的外层 MAC/IP/UDP/QoS/VLAN；默认源/目的端口 55000/4789 |

整数接受十进制和 `0x` 十六进制，前导零仍按十进制解释。重复参数、未知参数、越界数值和无效参数组合均报错。
`--outer-*` 仅用于 VXLAN；内外层 QoS 不自动复制。CNP 拒绝显式 payload、PSN 相关参数和 ack-request，包括空值或 `false`。
不支持 IPv6、分片、任意 opcode、RC 建连、ACK 接收、重传或线速压测。

build 不实际等待，PCAP 时间戳从 0 开始按 interval 递增；超过经典 PCAP 的 32 位秒字段会在创建文件前拒绝。
帧含协议 pad 和 ICRC，不含 Ethernet FCS；只对最外层 Ethernet 补齐到至少 60 字节。
发生写入错误或取消时，已生成的部分 PCAP 保留，摘要给出完整记录数；最后一条记录可能不完整。
Linux/macOS 下，build 的管道输出在下游停止读取时也可由 Ctrl+C/SIGTERM 取消。第一次信号触发清理；若 stderr 的下游也停止读取，或外部文件系统 I/O 无法及时返回，可再次发送信号强制退出，此时摘要可能不完整。
错误退出码：参数错误 2，构包/文件/发送错误 1，正常完成 0，信号中断 130。

### receive / inspect

| 参数 | 规则 |
| --- | --- |
| `--interface` | receive 必填，仅 Linux Ethernet 接口；只取入方向，不启用混杂模式 |
| `--pcap FILE` | inspect 必填输入；receive 可选输出；均不接受 `-`，inspect 输入必须是普通文件 |
| `--overwrite` | 仅 receive 的 PCAP 文件输出可用；默认拒绝覆盖 |
| `--port` / `--vxlan-port` | 默认 4791 / 4789，过滤 RoCE UDP 目的端口与 VXLAN 外层目的端口；两者必须不同 |
| `--dqpn` | 可选，按解析后的目标 QPN 过滤，0 合法；不要求接收端创建这个 QP |
| `--count` | receive 默认 1，达到 N 个成功解析的匹配帧后结束，含校验失败帧；inspect 默认读完文件 |
| `--duration` / `--continuous` | 仅 receive；与显式 count 互斥，duration 到期可正常结束 |
| `--json` | stdout 每行一个 JSON 结果，包含 timestamp 和 packet 或 error；统计写 stderr |
| `--strict` | 存在校验错误、malformed、unsupported，或零匹配帧时返回 1；持续收集到正常结束后判定 |

输出包含内外层地址、UDP 端口、DSCP/ECN/VLAN/PCP、QPN/PSN、数据长度、WRITE 的地址/rkey，以及 IPv4/UDP/ICRC 状态。`UDP checksum=disabled` 表示线上为零，未执行 UDP 校验；它不单独导致 strict 失败。PSN 按捕获顺序显示，不据此自动推断重传、丢包或 RDMA 完成。

`frames=valid+invalid` 只统计支持模板的成功解析帧；无关报文计入 ignored，截断/布局损坏计入 malformed，未支持的格式计入 unsupported。后两者单独显示 error，不计入 count，也不保存到 receive PCAP；因此诊断未知流量时建议用 duration 限制等待。QPN 过滤只作用于成功解析的报文，无法解析的输入仍计入错误统计。

receive 保存的是匹配帧的捕获字节（含校验错误帧），时间戳取本机读取时刻；恢复 Linux 辅助数据中提供的 VLAN 标签。解析范围为单层 VLAN、无 options/无分片的 IPv4、标准 VXLAN、现有三个模板；不支持其他 opcode、IPv6、PCAPNG、Linux cooked capture。inspect 支持经典 PCAP 大小端与微秒/纳秒时间戳，纳秒按微秒截断；截短记录直接报错。

校验结论针对捕获字节。网卡硬件过滤、卸载和抓包位置可能影响能看到的帧及字段；这里没有通用抓包器的内核丢包统计，不能据 receive 数量计算精确丢包率。默认不启用混杂模式，也不改变接口/VTEP 配置。

## 验证与边界

Go 测试读取仓库中的 22 组 Scapy 2.6.1 固定向量，无需 Python。
独立检查 CLI 导出的六种示例（包括 IPv4/UDP/ICRC、VLAN、端口递增和 PSN 字段）：

```bash
python3 -m venv .venv
.venv/bin/pip install scapy==2.6.1
.venv/bin/python scripts/verify_examples.py ./bin/roce-cli
# 仅在有意更新参考向量时运行：
.venv/bin/python scripts/generate_vectors.py
```

验证覆盖离线协议、CLI、模拟发送/接收与取消、PCAP 流式读取、畸形输入、decoder fuzz、race、vet 和 Linux 双架构静态编译。
Linux 实际 AF_PACKET 发包、veth 抓包和真实 RNIC/VTEP 验收尚未执行；交叉编译不能替代这些验证。
可按 [Linux 隔离验证步骤](docs/linux-validation.md) 完成实发验收。

构包优化的测量方法及本轮修复见 [代码评审记录](docs/code-review.md)。

[设计及评审决策](docs/superpowers/specs/2026-09-26-roce-cli-design.md) · [实现计划](docs/superpowers/plans/2026-09-26-roce-cli-implementation.md) · [测试向量来源](testdata/README.md)
