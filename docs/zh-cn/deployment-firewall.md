# 防火墙部署

防火墙模式具有平台相关性。仓库测试覆盖配置、命令生成、dry-run 行为和 cleanup 形状；它们不证明真实主机防火墙已接受并执行规则。

## 后端选择

可用时按以下顺序优先选择：

1. `nftables`：推荐的 Linux 后端，支持带超时的 set，规则所有权更清晰。
2. `ipset-iptables`：nftables 不可用时的可接受 fallback，使用 ipset timeout 管理 allow 条目。
3. `iptables`：最后 fallback。普通 iptables 规则没有原生逐规则过期；libknock 调度 revoke 并执行托管链 cleanup。
4. `script`：仅在操作者自行拥有并测试外部脚本时使用。
5. `noop`：用于不修改防火墙的 auth-only 或 knock-auth-only 模式。

## iptables fallback 风险

如果进程或主机在调度 revoke 前退出，`iptables` 后端可能留下临时 ACCEPT 规则。启动/关闭 cleanup 会降低风险，但不能替代目标主机验证或外部防火墙策略控制。

## Dry-run 与真实验证

fake runner 测试能验证命令形状、端口绑定检查、cleanup 幂等和错误传播。它不能证明内核模块可用、nftables family/table 语义、iptables 变体行为、容器 namespace 策略、主机防火墙规则顺序、NAT 交互或抓包权限。
