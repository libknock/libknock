# libknock 中文 Agent 指南

适用版本：v0.1.0-rc3。

## 先读

- `llms.txt`
- `COMPATIBILITY.md`
- `MIGRATION.md`
- `docs/api-surface.md`
- `docs/agents/task-matrix.yaml`

## 稳定集成面

普通应用优先从根包开始：`libknock.NewListener`、`libknock.Dialer`、`libknock.ServerConfig`、`libknock.ClientConfig`。需要自定义认证、事件、replay cache 或 knock session 时，再进入 `auth` 包。

`protocol/` 是线级实现与互操作测试面，不是普通集成入口。不要为了“更底层”而直接拼帧；这样会绕过 replay cache、时间窗、candidate 限制和默认安全策略。

## ReplayCache 生命周期

服务端 replay cache 必须跨连接共享。禁止在每个连接或每次 `ServerAuth` 调用里新建 replay cache。内置 `auth.NewMemoryReplayCache` 是有界 fail-closed 缓存；打满时返回 `ErrReplayCacheFull`，应通过事件和指标排障，而不是静默放行。

## SDK 与配置边界

SDK 不读取业务配置文件，不提供 `RunServer(configPath)` 这类产品入口。`cmd/knock-proxy` 是兼容命令和调用方示例，负责读取旧配置、转换到 SDK struct、组装 runtime；不要把命令行配置解析逻辑写回 SDK core。

## 必跑验证

常规改动：`scripts/check.sh`、`go test ./...`、`go vet ./...`。发布前：`scripts/release-check.sh`、`scripts/check-api.sh`、`scripts/package-release.sh --with-vendor <VERSION> dist/`。改协议或公开 API 必须更新 `MIGRATION.md`、`COMPATIBILITY.md`、`docs/api-surface.md`。
