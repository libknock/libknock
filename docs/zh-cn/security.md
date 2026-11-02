# 安全

中文版本用于保持文档入口同步；当前详细内容以英文对应文档 `../security.md` 为准。发布前应逐步补齐完整翻译。

## Multipath TCP（MPTCP）

Go 1.24 起，Linux 上 `net.Listen` 默认接受 MPTCP。MPTCP 连接可以通过 `MP_JOIN` 从其它源地址加入子流，这些子流不经过 `Accept`，不受认证来源、敲门会话绑定、Policy、封禁和单源上限约束；`MP_JOIN` 密钥以明文 TCP 选项传输，链路上的观察者可以从自己的地址加入已认证连接。

- libknock 自己创建的监听（`gate.Listen`、`relay.Gateway`、兼容命令行）默认关闭 MPTCP，可通过 `EnableMPTCP` / `server.mptcp: true` 开启，且只应配合会丢弃未放行来源的防火墙模式使用。
- `netx.WrapListener` 与 `gate.Wrap` 使用调用方的监听：请用 `ListenConfig.SetMultipathTCP(false)` 创建，或设置 `GODEBUG=multipathtcp=0`。
