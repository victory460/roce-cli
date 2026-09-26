# RoCE Sender v0.1 Implementation Plan

执行方式：当前会话原生实现。用户已授权继续评审、完善设计和实现；不重复设置确认门槛，不自动串联技能。

**Goal:** 交付可离线验证的 RoCEv2 构包 CLI 和 Linux 原始帧发送实现。

**Architecture:** config 保存类型与语义约束；cli 处理参数存在性；packet 为纯构包函数；sequence 按索引产生字段；app 串联可替换接口、输出与取消。

**Tech Stack:** Go 1.24.2 标准库；Scapy 2.6.1 仅用于生成固定参考样本。

**Spec:** ../specs/2026-09-26-roce-sender-design.md

## Global Constraints

- IPv4，SEND_ONLY / WRITE_ONLY / CNP，单层 VLAN，可选 VXLAN。
- 产品无第三方运行时依赖；Linux amd64/arm64 CGO_ENABLED=0。
- 不修改 vxlan-sender；不发送真实网络流量作为本机测试。
- generated/submitted 仅表示生成或提交，不表示 RDMA 完成。

## Review Focus

1. 显式零值、false 和省略参数区别：模板/封装/输出冲突按参数存在性校验。
2. ICRC 小端输出、屏蔽范围与坏 ICRC 后 UDP 重算：以 Scapy 固定字节验证。
3. VXLAN 内层以太帧补齐与 IP MTU 区别：内层不携带链路 padding，最终帧才补 60 字节。
4. PCAP 时间戳乘法溢出、微秒精度、短写、关闭错误：预检时间范围并传播 I/O 错误。
5. 长 interval、duration 到期和 socket 背压：可取消等待，Linux 非阻塞 socket，失败不增加提交数。

## Task 1: 协议核心与序列

文件：go.mod、internal/config/config.go、internal/packet/{packet.go,packet_test.go}、internal/sequence/{sequence.go,sequence_test.go}、scripts/generate_vectors.py、testdata/vectors.json。

接口：packet.Build(config.Config, sequence.Fields) ([]byte,error)；sequence.At(config.Config,uint64) Fields。

- [x] 创建独立 Scapy 向量和测试：三个模板、padding 0..3、VLAN/VXLAN、ICRC 不变量、异常 ICRC、MTU。
- [x] 实现类型、纯构包、16/24 位回绕；长度先校验后转换；ICRC little endian。
- [x] 运行 go test ./internal/packet ./internal/sequence，固定样本逐字节相等。

## Task 2: CLI 与离线输出

文件：internal/cli/{cli.go,cli_test.go}、internal/pcap/{pcap.go,pcap_test.go}、internal/app/{app.go,app_test.go}、main.go。

接口：cli.Parse([]string,io.Writer) (config.Config,error)；pcap.New(io.Writer) (*Writer,error)；Writer.WriteFrame(uint64,[]byte) error；app.Run(context.Context,[]string,io.Writer,io.Writer,Dependencies) int。

- [x] 添加参数冲突、边界、未知参数、重复参数、stdout 隔离、文件不覆盖、确定性输出测试。
- [x] 实现参数解析与存在性校验、PCAP 微秒时间戳、流式输出、错误摘要。
- [x] 运行 go test ./internal/cli ./internal/pcap ./internal/app。

## Task 3: 接口补全与 Linux 发送

文件：internal/netutil/{netutil.go,netutil_test.go}、internal/sender/{sender.go,sender_linux.go,sender_other.go}、internal/app/send_test.go。

接口：netutil.Resolve(config.Config) (config.Config,net.Interface,error)；sender.Open(net.Interface) (sender.Sender,error)；Sender.Send(context.Context,[]byte) error；Sender.Close() error。

- [x] 添加模拟发送测试：首包 MTU 错误不开 socket、count/list 顺序、失败计数、取消长等待、到期退出、关闭资源。
- [x] 实现接口解析、非阻塞 AF_PACKET、可取消调度，非 Linux 明确报错。
- [x] 运行全套测试、race、vet 和 Linux 两架构构建。

## Task 4: 使用说明与最终 review

文件：README.md、Makefile、.gitignore、docs/linux-validation.md、设计文档。

- [x] 更新设计：记录评审决策、错误/信号语义和时间戳边界。
- [x] 跑 README 离线示例并用 Scapy 独立解析生成的 PCAP。
- [x] review 全部代码、修复发现的问题，记录已执行与环境受限验收项。

不自动提交或发布；保留完整工作区 diff 供用户 review。

## 执行结果（2026-09-26）

- 四项任务全部完成，按上述接口实现，无新增产品运行时依赖。
- 全部 Go 测试、race、vet 通过；Linux amd64/arm64 静态编译通过。
- 22 个 Scapy 完整帧向量匹配，五类 CLI 示例共 10 帧独立解析通过。
- 评审额外修正 `--hex=false` 与 PCAP 同时指定的冲突，并添加回归测试。
- Linux 实发与硬件验收因本机为 macOS 未执行，已提供隔离验证步骤；这不影响离线交付，但不代表设备兼容通过。
- 工作区保留未提交源码和文档供用户 review。
