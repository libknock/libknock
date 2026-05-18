# 模式

| 模式 | TCP 端口可见性 | 是否修改防火墙 | 应用协议准入 |
| --- | --- | --- | --- |
| `auth-only` | TCP listener 开放 | 否 | 应用收到连接前必须通过 TCP auth |
| `knock-auth-only` | TCP listener 开放 | 否 | 必须先 knock，再通过 TCP auth |
| `knock-firewall-auth` | 防火墙在 knock 前阻断 | 是 | 必须先 knock，再通过 TCP auth |
| `knock-firewall-only` | 防火墙在 knock 前阻断 | 是 | 必须先 knock；gate 不执行 TCP auth |

`knock-auth-only` 不是端口隐藏。SYN 扫描看到 TCP 端口 open 是预期行为。它的价值是：未认证连接不能进入应用协议，除非先提交有效 knock 并通过 TCP authentication。
