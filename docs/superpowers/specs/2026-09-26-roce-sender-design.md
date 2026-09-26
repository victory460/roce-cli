# RoCE Sender v0.1 设计

日期：2026-09-26
状态：待用户评审；本文描述拟实现行为，尚无产品代码。
项目：`/Users/victory/vibe_prj/roce-sender`

## 1. 目标与已知约束

用户希望将 vxlan-sender 的可控构包、单端发包能力迁移到 RDMA 网络验证，并要求在与原工程平级的新目录开展设计与研发。

已接受的方向：聚焦 RoCEv2 报文级网络调试，提供 PCAP 和可复现场景，后续再考虑配套 RDMA 端点。
本设计提出的首版边界：IPv4、三个报文模板、可选 VXLAN 封装；IPv6 和完整端点连接另行设计。

主要用户是交换机、DPU、网卡研发与网络交付人员。成功标准是：能在不搭建完整 RDMA 应用的情况下，生成字段明确、校验正确、可被独立解析的报文，并在 Linux 上按指定序列发送。

首版结果只陈述已生成或已提交发送的帧数。网络送达需要远端抓包或设备计数器证明；RDMA 操作完成需要端点状态与完成事件证明。

## 2. 方案选择

| 方案 | 优点 | 代价 | 决策 |
| --- | --- | --- | --- |
| 独立 Go 原始报文工具 | 延续现有项目风格；标准库即可构包、PCAP 和 Linux 发包；易部署 | 自行处理 ICRC、协议布局和验证 | 推荐，作为 v0.1 |
| Scapy CLI 包装 | 协议探索快，已有 RoCE 支持 | 需要 Python/Scapy 部署，单二进制体验不同 | 用作独立验证参考 |
| 基于 verbs 的端点工具 | 能建立 QP 并观测真实 RDMA 完成 | 引入 rdma-core、设备与连接管理；无法同样自由控制线上字段 | 后续独立阶段 |

新项目不通过相对路径依赖 vxlan-sender，也不修改原工程。复用其设计经验，按新协议的字段与校验需求独立实现。

## 3. 首版范围

### 包含

- Ethernet、可选单层 802.1Q VLAN、IPv4、UDP、RoCEv2。
- 模板 `send-only`、`write-only`、`cnp`。
- MAC、IP、UDP 源端口、DSCP、ECN、TTL、VLAN PCP、目标 QPN、PSN、P_Key 控制。
- 默认正确 ICRC，以及明确指定的 ICRC 损坏模式。
- PSN 递增、固定值、显式序列；UDP 源端口递增用于流哈希测试。
- 可选外层 Ethernet/IPv4/UDP/VXLAN，可独立配置内外层 DSCP/ECN。
- 离线 PCAP 导出、十六进制输出、字段摘要。
- Linux AF_PACKET 发送：数量、时长、连续模式、发送间隔、信号退出。
- macOS/Linux 离线构包与测试；Linux amd64/arm64 静态交叉编译。

### 后续阶段

- IPv6、RoCEv1、InfiniBand、iWARP。
- RC 连接管理、内存注册、ACK/NAK 接收、自动重传、真实读写完成判定。
- READ/Atomic、分段 FIRST/MIDDLE/LAST、UD、任意 opcode 与任意头部拼装。
- PFC 帧构造、线速压测、微突发、拥塞控制闭环与性能测量。
- 自动抓包分析、交换机计数器采集、报文回放导入。

制造拥塞并验证 ECN 阈值与注入 CE 标记是不同实验。v0.1 支持后者，以及配合外部流量源开展前者；不将低速原始发包宣传为拥塞压力工具。

## 4. 协议模板与封装

直接模式：

```text
Ethernet / [802.1Q] / IPv4 / UDP / BTH / [RETH 或 CNP 保留区] / Payload / Pad / ICRC
```

VXLAN 模式：

```text
Outer Ethernet / [Outer 802.1Q] / Outer IPv4 / UDP / VXLAN
  / Inner Ethernet / [Inner 802.1Q] / Inner IPv4 / UDP / BTH / ... / ICRC
```

### 模板约束

| 模板 | Opcode | BTH 之后 | 限制 |
| --- | --- | --- | --- |
| send-only | 0x04 | 数据 + 0～3 字节零填充 | 用户负责目标 QP 与接收资源 |
| write-only | 0x0a | 16 字节 RETH + 数据 + 填充 | 必须显式提供 remote-addr、rkey；RETH 长度从数据长度计算 |
| cnp | 0x81 | 16 字节零保留区 | BECN=1，PSN=0，AckReq=0，PadCount=0；拒绝 payload、PSN 序列和 WRITE 参数 |

BTH 长度为 12 字节；除 CNP 的 BECN 外，首版 FECN/BECN 均为 0，版本及保留位为 0。
P_Key 默认 0xffff；数据模板 PSN 默认 0，AckReq 默认关闭，可显式开启；CNP 不提供数据模板专用开关。
RC 数据模板不自动建立或推断连接状态。WRITE 参数只是报文字段，不代表持有有效远端权限。

### 校验与长度

- IPv4 固定 20 字节，无 options，无 IP 分片；DF=1，ID=0，TTL 默认 64。
- UDP 目的端口默认 4791，允许覆盖以验证分类规则；覆盖后解析器可能需要显式指定协议。
- IPv4 UDP 校验和默认计算，也提供 `--udp-checksum zero`；VXLAN 外层有独立的同名 outer 参数。
- UDP 校验计算值为 0 时在线上写入 0xffff；主动禁用校验时才写入 0。
- 按最终长度构造 IP/UDP；长度字段包含最终 4 字节 ICRC。
- ICRC 以 RoCE 所属 IP/UDP/BTH 和后续数据为范围，包含协议填充；排除 Ethernet/VLAN、VXLAN 外层和 ICRC 自身。
- ICRC 前置 8 字节全 0xff 的虚拟 LRH；屏蔽 IPv4 TOS、TTL、头校验和、UDP 校验和与 BTH QPN 高 8 位；采用 IEEE CRC32，结果按 RoCE 线上字节序写入。
- `--bad-icrc` 对正确 ICRC 的固定一位取反，然后基于损坏后的内容计算 UDP 校验，以隔离 ICRC 错误因素。
- 最终 Ethernet 帧至少补到 60 字节（不含 FCS）；链路层补齐不计入 IP/UDP 长度或 ICRC。
- Ethernet FCS 由发包硬件处理，PCAP 不附加 FCS。
- `--mtu` 默认 1500，表示线上最外层 IP 包上限；VXLAN 开销和内层 VLAN 必须计入。
- send 模式还受实际接口 MTU 限制，取二者较小值。超限在发送前报错，不截断，不隐式分片。
- 此 MTU 不代表 RDMA QP 的 Path MTU；模板是否被真实端点接受还受对端配置限制。

## 5. CLI 与默认值

使用两个子命令，避免离线导出与网络发送混淆：

```text
roce-sender build [报文字段] [序列参数] --pcap FILE
roce-sender build [报文字段] [序列参数] --hex
roce-sender send  [报文字段] [序列参数] --interface IFACE [发送控制]
```

build 的 `--pcap` 与 `--hex` 必须且只能指定一个；不访问网络接口，不需要 root。
PCAP 为经典微秒格式、DLT_EN10MB，流式写入；默认拒绝覆盖已有文件，可显式 `--overwrite`。
build 使用固定起始时间戳 0，以 interval 递增；interval=0 时同一时间戳。输出可重复，不真实等待。
hex 输出每帧一行纯十六进制，摘要输出 stderr；PCAP 路径为 `-` 时写 stdout，保证二进制流不混入日志。
send 首版不同时保存 PCAP，避免将本地构造、提交发送和线上捕获混淆。

### 字段参数

| 参数组 | 参数及规则 |
| --- | --- |
| 基础 | `--template send-only\|write-only\|cnp`，默认 send-only；`--encap none\|vxlan`，默认 none |
| Ethernet/IP | `--src-mac`、`--dst-mac`、`--src-ip`、`--dst-ip`；build 均必填 |
| QoS | `--dscp` 0～63，默认 0；`--ecn` 0～3，默认 0；`--ttl` 1～255，默认 64 |
| VLAN | `--vlan-id` 0～4094；省略表示无标签，0 表示优先级标签；`--pcp` 0～7，默认 0，仅有 VLAN 时有效 |
| UDP | `--src-port` 默认 49152（CNP 默认 0）；`--dst-port` 默认 4791；端口范围 0～65535；`--udp-checksum auto\|zero` 默认 auto |
| BTH | `--dqpn` 必填，0～0xffffff；`--psn` 默认 0，0～0xffffff；`--pkey` 默认 0xffff，16 位；`--ack-request` 仅数据模板可用 |
| 数据 | `--payload-hex` 默认空，允许任意长度有效偶数位十六进制；CNP 禁止该参数 |
| WRITE | `--remote-addr` 64 位、`--rkey` 32 位，仅 write-only 可用，且必须显式给出；零值合法 |
| 异常/长度 | `--bad-icrc` 默认关闭；`--mtu` 默认 1500，合法范围 68～65535 |
| VXLAN | `--vni` 1～0xffffff，VXLAN 模式必填；`--outer-src-mac/ip`、`--outer-dst-mac/ip`；外层目的端口默认 4789，源端口默认 55000 |
| 外层 QoS | `--outer-dscp/ecn/ttl/vlan-id/pcp/udp-checksum` 与基础层规则相同；省略使用各自默认值，不隐式复制内层字段 |

无 outer 前缀的参数始终描述承载 RoCE 的 Ethernet/IP/UDP；VXLAN 模式下即内层。
VXLAN I 标志置位，其余保留位为 0。仅 VXLAN 模式允许 outer/vni 参数，拼写错误或无效组合一律报错。
字段整数接受十进制和 `0x` 十六进制；十进制前导零不触发八进制解析。
所有输入先按足够宽的类型解析、校验范围，再转换；不静默溢出。

send 需要显式 interface，不猜测默认路由。直接模式可从接口补全源 MAC/IPv4；VXLAN 模式仅补全最外层源 MAC/IPv4，内层四个地址均须显式给出。
自动源 IPv4 选择要求接口只有一个可用全局单播 IPv4；无地址或多个地址则要求指定。源地址覆盖允许模拟报文身份。
目标 MAC 必须显式给出；路由场景使用下一跳 MAC。首版不自动 ARP、不使用隐式广播。

### 序列与运行控制

- `--count` 默认为 1，必须大于 0。
- `--psn-step` 默认为 1，可为 0，用于重复 PSN；范围 0～0xffffff，递增按 24 位回绕。
- `--psn-list 100,101,101,103,102` 表示精确发包顺序；与显式 psn/psn-step/count/duration/continuous 冲突。包数取列表长度，发送一次，不循环。
- CNP PSN 固定为 0，拒绝显式 psn/psn-step/psn-list；允许 count/interval。
- `--src-port-step` 默认为 0，范围 0～65535，按 16 位回绕，只作用于 RoCE UDP 源端口。
- 序列索引从 0 开始，每帧先计算字段再构包与校验；不会通过复制旧帧遗漏 ICRC 更新。
- `--interval` 使用 Go duration 格式，例如 100ms，必须非负；含义为两次提交发送之间的最小间隔，不承诺精确定时。
- send 的 `--count`、`--duration`、`--continuous` 三种显式模式互斥；duration 必须大于 0；未指定时 count=1。
- build 只支持有限 count 或 psn-list；拒绝 duration/continuous/interface。
- send 在首包构造与 MTU 校验通过后打开 socket；发送失败立即退出，报告已成功提交的帧数。
- 间隔等待可被 Ctrl+C、SIGTERM 或到期计时打断；不使用不可取消的长 sleep。
- 正常完成返回 0，参数/文件/发送错误返回非零；信号退出释放资源并打印中断状态和计数。
- 摘要包含模板、封装、帧数、字节数、主要字段和 ICRC 模式；措辞使用 generated/submitted，不使用 delivered 或 RDMA completed。

## 6. 命令示例（设计草案）

离线生成重复与乱序 PSN 的样本：

```bash
roce-sender build --template send-only \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 \
  --dqpn 0x123 --psn-list 100,101,101,103,102 \
  --dscp 24 --ecn 2 --payload-hex deadbeef --pcap sequence.pcap
```

生成外层 CE、内层 ECT(0) 的 VXLAN 样本，用于配合 VTEP 验证解封装后的标记：

```bash
roce-sender build --encap vxlan --vni 100 \
  --outer-src-mac 02:00:00:00:01:01 --outer-dst-mac 02:00:00:00:01:02 \
  --outer-src-ip 198.51.100.1 --outer-dst-ip 198.51.100.2 \
  --outer-dscp 24 --outer-ecn 3 \
  --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 \
  --src-ip 192.0.2.1 --dst-ip 192.0.2.2 \
  --dqpn 0x123 --dscp 24 --ecn 2 --pcap vxlan-ecn.pcap
```

Linux 单端发送；示例地址与 MAC 需替换为测试环境配置：

```bash
sudo roce-sender send --interface eth0 \
  --dst-mac 02:00:00:00:00:02 --dst-ip 192.0.2.2 \
  --dqpn 0x123 --count 10 --interval 100ms
```

## 7. 模块划分

| 模块 | 职责与边界 |
| --- | --- |
| main.go | 调用应用入口，处理进程退出码与版本注入 |
| internal/cli | 子命令、flag 解析、帮助信息；错误返回调用者，不在解析器内 os.Exit |
| internal/config | 参数存在性、范围、组合校验，生成不可变配置 |
| internal/packet | 纯函数构造 Ethernet/VLAN/IP/UDP/RoCE/VXLAN，校验与摘要；不访问网卡、时钟或文件 |
| internal/sequence | 根据配置与帧索引生成 PSN、端口等；显式序列只存字段，不缓存全部帧 |
| internal/pcap | PCAP 编码、记录写入、短写与错误传播 |
| internal/netutil | 接口状态、MAC、IPv4、MTU 查询 |
| internal/sender | Linux AF_PACKET socket；其他平台返回明确不支持发送错误 |
| internal/app | 串联配置、序列、输出和取消；依赖可替换 writer/sender 进行集成测试 |

依赖方向：CLI → config → app → sequence/packet → pcap 或 sender。
netutil 只在 send 的配置补全过程使用。Go 1.24.2 与现有开发环境一致；产品运行时只使用标准库，关闭 CGO。

## 8. 验证与验收

协议正确性不能只用同一实现的编码器与解码器互证。

1. 独立参考样本：使用 Scapy 构造 SEND_ONLY/CNP，以及手工 RETH 的 WRITE_ONLY，固定版本与生成脚本，保存帧字节和预期字段。Go 测试读取固定样本，不依赖 Python。
2. ICRC：与独立样本逐字节比较；TTL、DSCP/ECN 改变应保持 ICRC 不变，PSN/地址/负载改变应更新 ICRC；坏 ICRC 样本仍须具有有效 UDP 校验。
3. 协议边界：0～3 字节填充、空负载、24 位最大 PSN 与回绕、最大字段值、WRITE 长度、VLAN 0 与省略标签、VXLAN 内外层长度和校验。
4. CLI 与调度：无效参数不能生成文件或发送；psn-list 精确顺序；超 MTU 拒绝；计数、时长与信号取消；发送错误不计入成功数。
5. 离线集成：运行全部 README 示例对应的 build 命令，独立解析 PCAP 层次、DSCP/ECN、QPN、PSN、ICRC，确认输出可重复。
6. 编译：go test ./...、go test -race ./...、go vet ./...，以及 Linux amd64/arm64 的 CGO_ENABLED=0 构建。
7. Linux 发送：在隔离 network namespace/veth 环境抓包，核对数量、字段与序列。需要可用 Linux 环境及权限；当前开发机为 macOS，交叉编译不能替代此验证。
8. 设备验证：在真实 VTEP/RNIC 上验证转发、ECN 传播和异常计数，属于环境验收；无硬件时应明确记录未执行，不宣称端点兼容通过。

报文参考以公开实现交叉核对，不能仅凭 Wireshark 显示协议名就判定协议全部正确。
参考代码仅作行为核对与测试样本来源；不直接复制第三方实现，保留来源、版本和生成方法。

## 9. 研发顺序与交付物

本节是阶段依赖概览；详细实现任务与执行方式在设计评审后确定。

1. 协议核心与独立测试向量：正确构造三个模板、校验与序列。
2. 离线 CLI 与 PCAP：在当前 macOS 环境即可完整验证。
3. VLAN 与 VXLAN：覆盖内外层 QoS/ECN 与 MTU 边界。
4. Linux sender 与运行控制：加入可取消发送、错误统计和跨平台构建。
5. 使用文档与实验步骤：明确构包、提交发送、网络送达、RDMA 完成四种证据。

交付包括源代码、中文 README、设计文档、测试向量及来源、Makefile、离线示例和 Linux 集成验证说明。
首版不依赖外部服务，不创建 GitHub 仓库、不发布包或部署站点。

## 10. 参考资料

访问日期：2026-09-26。研发时固定测试参考版本，避免随 master 漂移。

- [Scapy RoCE 实现：BTH、CNP、ICRC](https://github.com/secdev/scapy/blob/master/scapy/contrib/roce.py)
- [Linux RXE ICRC 实现](https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_icrc.c)
- [Linux RXE opcode 布局](https://github.com/torvalds/linux/blob/master/drivers/infiniband/sw/rxe/rxe_opcode.c)
- [rdma-core RC 连接示例](https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/examples/rc_pingpong.c)
- [perftest](https://github.com/linux-rdma/perftest)
- [NVIDIA RoCE QoS 与拥塞配置](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-57/Layer-1-and-Switch-Ports/Quality-of-Service/RDMA-over-Converged-Ethernet-RoCE/)
- [Cisco RoCE over VXLAN 部署](https://www.cisco.com/c/en/us/td/docs/dcn/whitepapers/roce-storage-implementation-over-nxos-vxlan-fabrics.pdf)
