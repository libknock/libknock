# 验证矩阵

本页是英文 [Validation matrix](../validation-matrix.md) 的中文入口。发布判断以英文主文档为准；中文文档用于说明状态含义和阅读路径。

状态使用：`verified by unit test`、`verified by integration test`、`compiled only`、`not validated on real host`、`planned validation`。

重点：Linux firewall、UDP passive、Windows WinDivert/Npcap、macOS BPF/pcap 必须单独记录状态；没有真实主机证据时，不能把 mock、dry-run 或编译通过写成实机验证。


> 中文文档当前为部分同步；发布、兼容性、限制与验证矩阵的权威来源仍是英文文档。中文侧会持续补齐，但不得覆盖英文发布说明中的保守验证边界。
