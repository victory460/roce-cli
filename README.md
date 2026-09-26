# RoCE Sender

面向网络调试的 RoCEv2 报文构造与发送工具，作为 `vxlan-sender` 的平级独立项目。

当前状态：设计评审阶段，尚未实现 CLI；设计中的命令示例不是现成可执行命令。

目标是用可重复的报文验证转发、ACL、QoS、ECN 标记传递，以及 RoCE over VXLAN 的封装行为。
首版采用 Go 标准库，提供离线 PCAP 导出和 Linux 原始以太网发送，不要求发送端具有 RDMA 网卡。

设计范围包括 RC SEND_ONLY、RC RDMA_WRITE_ONLY、CNP、VLAN、DSCP/ECN、PSN 序列与 ICRC 异常注入。
原始报文发送不建立 RDMA 连接，也不保证接收端完成 RDMA 操作。

详见 [v0.1 设计](docs/superpowers/specs/2026-09-26-roce-sender-design.md)。
