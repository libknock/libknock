# 平台支持

状态值：

- `stable`：核心 SDK 路径稳定，并由常规测试覆盖。
- `experimental`：已有实现，但部署依赖平台权限、抓包驱动或额外验证。
- `compile-only`：源码应可为该平台编译，但仓库自动化不证明运行行为。
- `not supported`：仓库没有支持的运行路径。

| 平台 | Auth-only TCP SDK | Relay | UDP knock | UDP passive | TCP SYN knock | TCP SYN sequence | Firewall backend |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | stable | stable | stable | experimental | experimental | experimental | experimental：nftables、ipset-iptables、iptables；需要手工验证 |
| Windows | stable | stable | stable | compile-only / 依赖驱动 | compile-only / 需要 WinDivert 或 Npcap | compile-only / 需要 WinDivert 或 Npcap | not supported |
| macOS | stable | stable | stable | compile-only / 需要 BPF 或 pcap | compile-only / 需要 BPF 或 pcap | compile-only / 需要 BPF 或 pcap | not supported |

这里的 `stable` 表示库路径稳定，不表示所有主机拓扑都完成了实机验证。声明部署已验证前，应查看 [验证矩阵](validation-matrix.md)、[已知限制](known-limitations.md) 和 [验证模板](validation-template.md)。
