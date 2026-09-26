# RoCE CLI 升级设计

用户已确认：接收指原始报文接收、解析和校验，不建立 RDMA QP。产品名升级为 RoCE CLI，命令为 `roce-cli`；当前工作目录保留，旧设计文档作为历史记录。

## 命令与行为

- `build`、`send` 保留已有参数语义，帮助按子命令展示有效参数。
- `receive --interface IFACE [--count N | --duration D | --continuous]`：Linux AF_PACKET 入方向接收，不启用混杂模式，不接收本机发出的帧；默认等待一个匹配的 RoCE 帧。
- `receive --pcap FILE [--overwrite]` 可选保存匹配帧，真实接收时间戳；逐帧解析结果写 stdout，运行统计与 ready 提示写 stderr。保存文件不支持 `-`，避免混入文本。
- `inspect --pcap FILE`：流式读取经典 Ethernet PCAP（微秒/纳秒、大小端），离线复用相同解析器，不需要权限。首版仅接受普通文件，不接受 stdin/FIFO，避免未完成的输入流等待语义。
- receive/inspect 共用 `--port 4791`、`--vxlan-port 4789`、可选 `--dqpn` 过滤、`--json` JSON Lines、`--strict`。两端口必须不同；支持自定义 RoCE 目的端口。
- count 统计匹配端口且可识别为支持模板的帧，含校验错误帧；无关报文不占 count。解析截断/布局错误单独计入 malformed，不假装校验通过；格式不支持计入 unsupported。
- strict 在结束时如有匹配帧校验失败、malformed 或 unsupported 返回 1；不停止在首个坏帧。零匹配帧同样返回 1，避免空观察被当作验证通过。参数错误 2，I/O 错误 1，首次信号取消 130。

## 协议解析边界

Ethernet/单 VLAN/IPv4（无 options、无分片）/UDP；可选标准 VXLAN 后再解码内层。SEND_ONLY、WRITE_ONLY、CNP；其他 opcode 明确 unsupported。输出内外 MAC/IP、端口、DSCP/ECN/VLAN、模板/QPN/PSN、RETH、payload 长度、IPv4/UDP/ICRC 状态。UDP checksum=0 标记 disabled，不当成校验成功或失败。ICRC 被掩码字段与现有构包保持一致；任何长度读取前先验证边界，不对截断内容猜测。

接收 socket 非阻塞、可取消；通过 PACKET_AUXDATA 恢复硬件剥离的外层 VLAN。只接收发给本接口/广播/组播的包，非通用镜像抓包工具。校验以捕获字节为准，硬件卸载与抓包位置影响须记录；不主动配置网卡/VTEP/RNIC。

## 实现与验证

1. 重命名 Go module、二进制、CLI 帮助和当前文档/脚本。
2. packet.Decode + 固定 Scapy 向量、坏校验、畸形/截断、未知协议、fuzz 种子测试。
3. PCAP Reader + 字节序/纳秒/短记录/超长声明测试，限制分配大小。
4. Linux receiver + 非 Linux明确报错；分离 VLAN 辅助数据重建，离线可测。
5. app receive/inspect + 替换接收源测试计数、过滤、错误、取消、PCAP 保存、JSON、strict。
6. 中文 README 与完整离线/双机/namespace 案例；自动运行离线案例，Go test/race/vet、Linux双架构静态构建。

实际 Linux 收发与硬件验收需 Linux 环境；若不可用，明确标注未执行，并提供可运行的隔离验证脚本。独立代码 review 后修复重要问题再交付，不创建远端发布或移动用户工作目录。

## Linux 接收参考

- [packet(7)：AF_PACKET、方向类型、PACKET_AUXDATA](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Linux 6.12 if_packet.h：辅助数据布局与状态位](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_packet.h)

Go 标准库 syscall 在 amd64 上缺少 PACKET_AUXDATA 常量，使用已核对的 Linux UAPI 值 8；不因此引入第三方运行时依赖。

## 实现与评审记录

已完成命名更新、receive/recv/inspect、按命令帮助、流式 PCAP 读取、共享解析器、捕获保存、JSON/strict 和收发案例。独立 review 后修复：

1. 接收 socket 以 protocol=0 创建，绑定目标接口后才开始接收，并再次核对 Ifindex，避免 setup 窗口混入其他接口的帧。
2. duration 等待到期可成功结束，但中断正在输出的记录仍报告 I/O 错误，不能把不完整 JSON 当成成功。
3. 安全可读的非目标 UDP 端口先过滤，普通 UDP 带 IPv4 options 不会污染 RoCE strict 结果；无法安全确定端口的畸形输入仍明确报告。
4. 解析 VXLAN 时为外层字段保存独立副本，避免内层解析覆盖外层 QoS/地址。

对应回归测试已加入 packet、pcap、receiver、cli、app；新增 decoder fuzz 测试。Linux 实发环境未就绪，隔离脚本提供六类收发场景，尚未运行实发；不将静态编译或模拟测试称作实机验收。

最终检查：`go test ./...`、`go test -race ./...`、`go vet ./...` 通过；Linux amd64/arm64 产物确认为静态 ELF；六类 26 帧通过 Scapy 与 inspect 对照；最终 decoder fuzz 运行 156294 次无失败。隔离脚本 `bash -n` 语法检查通过，Linux 实收发未执行。
