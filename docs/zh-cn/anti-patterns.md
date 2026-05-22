# libknock 中文反模式

适用版本：v0.1.0-rc3。

- 不要从 `protocol/` 直接实现普通业务集成；优先使用根包或 `auth`。
- 不要创建每连接 replay cache；replay 状态必须跨连接共享。
- 不要在 SDK core 中读取 YAML/JSON/TOML 业务配置；配置解析属于调用方或 `cmd/knock-proxy`。
- 不要把 `cmd/knock-proxy` 当成 SDK 架构模板；它是兼容命令，不是库边界。
- 不要把 auth-only / knock-auth-only 描述成端口隐藏；它们是预应用认证模式，扫描表现取决于网络与防火墙模式。
- 不要阻塞 `OnAuthenticated`；该回调运行在认证路径中，必须快速返回。需要异步处理时使用调用方自有 bounded queue。
- 不要声称 nftables、iptables、ipset、Windows WinDivert/Npcap、macOS BPF/pcap 已生产验证，除非当前 release notes 有真机证据。
- 不要修改 wire format 而不更新 `MIGRATION.md`、`COMPATIBILITY.md` 和 API/协议文档。
