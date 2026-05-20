# 已知限制

本页是英文 [Known limitations](../known-limitations.md) 的中文入口。发布判断以英文主文档为准。

当前边界：

- nftables / ipset-iptables / iptables 尚未由仓库自动化完成真实主机验证。
- UDP passive 尚未完成真实 DROP 行为验证。
- Windows WinDivert / Npcap 路径尚未实机验证。
- macOS BPF / pcap 路径尚未实机验证。
- 长时间 fuzz 和生产性能画像仍是后续发布工程任务。


> 中文文档当前为部分同步；发布、兼容性、限制与验证矩阵的权威来源仍是英文文档。中文侧会持续补齐，但不得覆盖英文发布说明中的保守验证边界。
