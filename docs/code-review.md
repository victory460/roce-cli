# 代码评审与优化记录

日期：2026-09-26。范围：现有 v0.1 源码、用途文档、测试与示例；工作区仍保留未提交改动。

## 修复

### P2：管道背压使 build 无法响应退出信号

复现条件：`build --pcap - --count 1000000` 的 stdout 接到不再读取的管道。原实现阻塞在输出调用中，无法再执行循环内的 context 检查，SIGINT/SIGTERM 持续被 signal.NotifyContext 接收而不能使进程退出。

Linux/macOS 的管道输出现在使用独立拥有的非阻塞文件描述符，并通过 Go 的写 deadline 响应取消。结束时停止并等待取消回调、恢复共享的原始文件状态标志、关闭复制的描述符；不关闭调用者的 stdout。只有完整写出的帧计入 generated。主进程在首次信号后恢复默认信号处理，重复信号可以强制退出。

回归测试使用真实管道检查 PCAP/hex 取消与完整记录数，并通过子进程覆盖继承的 stdout、SIGINT/SIGTERM 和退出码 130。普通文件系统的阻塞 I/O 不保证可由 deadline 解除，重复信号是其强制退出兜底。

独立 reviewer 复查确认文件描述符所有权、原始标志恢复、取消回调同步和错误传播正确，重复运行管道/信号测试三次通过。剩余边界：如果 stderr 同样堵塞（例如 stdout/stderr 合并到同一停止读取的管道），最终诊断仍可能阻塞；第二次信号可以退出，但不保证摘要完整。

### 输出错误不能报告成功

`--version` 原来忽略写入返回值；短写或管道关闭时仍返回 0。现在版本和 hex 输出共用完整写入检查，输出失败返回 1，并保留错误说明。

## 构包优化

- ICRC 仅复制 48 字节的虚拟 LRH/IP/UDP/BTH 头，对 RETH/数据/填充增量计算 CRC，避免整段负载复制。
- UDP 校验直接累加固定伪首部和已有 UDP 数据，避免复制完整 UDP 包。
- 在分配报文缓冲区和计算校验前检查最终外层 IP 长度，包含内层 VLAN 与 VXLAN 开销。
- CLI 参数注册抽离到 `internal/cli/flags.go`，使帮助文本、默认值与语义校验更容易分别维护。

本机测量：Go 1.24.2，darwin/amd64，Intel Core i7-9750H，1024 字节 payload；每项执行三次。

| 模式 | 优化前 B/op | 优化后 B/op | 优化前 allocs/op | 优化后 allocs/op |
| --- | ---: | ---: | ---: | ---: |
| 直接 RoCE | 5760 | 3504 | 5 | 4 |
| VXLAN | 10368 | 6960 | 9 | 7 |

直接模式分配字节减少约 39%，VXLAN 约 33%。本轮构包耗时分别约 1.4～1.5μs 和 2.6～2.8μs；计时受机器状态影响，仅用于同机对照，不能推导真实发包吞吐或线速能力。

复现当前基准：

```bash
go test ./internal/packet -run '^$' -bench BenchmarkBuild -benchmem -count=3
```

## 验证范围

- 22 个 Scapy 固定帧向量保持逐字节一致。
- 增补接近 IPv4 长度上限的大包、内外层校验和和调用者 payload 不被修改的测试。
- 六类 README 离线示例共 26 帧由 Scapy/zlib 独立检查，新增 VLAN/PCP、源端口递增和固定 PSN 场景。
- 全套 Go 测试、race、vet 和 Linux amd64/arm64 静态编译全部通过。
- 独立 reviewer 检查了当前源码及测试，未发现其他需要修复的协议布局、ICRC、MTU、序列或发送调度问题。

未实测：Linux AF_PACKET 实际发送/背压、网卡 VLAN/offload、VTEP/RNIC 接受行为及 RDMA 完成。当前 macOS 的离线验证、交叉编译与模拟测试不能替代这些环境验收。
