# 独立报文参考

`vectors.json` 由 `scripts/generate_vectors.py` 使用 **Scapy 2.6.1** 生成，共 22 组完整以太帧：

- SEND_ONLY / WRITE_ONLY，各覆盖 payload 长度 0、1、2、3、4。
- CNP 空数据及 16 字节保留区。
- 每组分别覆盖直接封装和双 VLAN 的 VXLAN 封装（内 VLAN 0，外 VLAN 4094）。

生成方式：在独立 Python venv 中安装 `scapy==2.6.1`，从仓库根目录运行 `python scripts/generate_vectors.py`。
参考样本使用 Scapy 原有 BTH/ICRC/IP/UDP/VXLAN 编码；WRITE 的 RETH 用 Python `struct.pack("!QII", ...)` 编码，填充由脚本显式提供。
Go 测试比较全部帧字节，运行时与正常测试均不依赖 Scapy。第三方源代码未复制到项目。

行为来源：

- [Scapy 2.6.1 RoCE](https://github.com/secdev/scapy/blob/v2.6.1/scapy/contrib/roce.py)
- [Linux 6.12 RXE ICRC](https://github.com/torvalds/linux/blob/v6.12/drivers/infiniband/sw/rxe/rxe_icrc.c)

`scripts/verify_examples.py` 另行运行本工具 CLI，用 Scapy 检查生成 PCAP 的层次、校验和、CNP/RETH、QoS、PSN 和时间戳，并用 Python zlib 验证 ICRC 与单比特异常模式。
这些验证证明报文字节与公开软件参考一致，不证明任意 RNIC 接收或 RDMA 操作完成。
