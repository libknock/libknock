# 发布检查清单

本检查清单用于候选版本和稳定标签。

## 1. 源码树检查

```sh
go mod download
go mod tidy
scripts/check.sh
go test -count=1 ./...
go vet ./...
go build ./...
go test -race -count=1 ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay
```

## 2. 嵌套模块

```sh
go -C observability/prometheus test -count=1 ./...
go -C observability/prometheus vet ./...
go -C test/integration/grpc test -count=1 ./...
go -C test/integration/grpc vet ./...
go test -count=1 ./examples/grpc-client/... ./examples/grpc-server/...
```

## 3. Fuzz 冒烟测试

在 RC 前运行短时 fuzz 检查，在稳定发布前运行更长时间的检查。

```sh
go test ./protocol -run=^$ -fuzz=FuzzDecodePayload -fuzztime=60s
go test ./protocol -run=^$ -fuzz=FuzzReadFrame -fuzztime=60s
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=60s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=60s
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=60s
go test ./knock -run=^$ -fuzz=FuzzSequenceTracker -fuzztime=60s
```

`scripts/release-check.sh` 运行代表性的短时 fuzz 冒烟；完整 protocol/knock/auth fuzz 集使用 `scripts/fuzz-long.sh`。对于稳定标签，根据项目策略增加 fuzz 时间。

## 4. 跨平台构建

```sh
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done
```

记录发布所用的 Go 版本。

## 5. Linux 防火墙环境检查

为以下内容运行特权测试或手动验证：

- `nftables` 后端
- `ipset-iptables` 后端
- `iptables` 后端
- IPv4 allow/revoke
- 支持时的 IPv6 allow/revoke
- 清理幂等性
- 模拟不干净退出后的启动清理
- 受保护端口绑定校验
- 被动 UDP 方法的 `drop_udp_knock_port`

每个后端的最低手动流程：

```text
1. Start listener/gateway with backend configured.
2. Confirm Init creates expected rules or sets.
3. Send valid knock.
4. Confirm Allow creates a rule or set entry for the source.
5. Complete TCP authentication when applicable.
6. Confirm Revoke or timeout cleanup removes the entry.
7. Stop service.
8. Confirm Cleanup is idempotent.
```

## 6. UDP 和序列检查

验证：

- `udp`
- `udp-seq`
- `udp-passive`
- `udp-passive-seq`
- 缺少序列部分时失败
- 重复序列部分处理
- 配置允许时乱序序列成功
- 序列超时
- 与后续 TCP 认证的会话绑定

## 7. TCP SYN 平台检查

在发布目标支持的地方，验证：

- `tcp-syn`
- `tcp-syn-seq`
- Linux 原始套接字能力路径
- Windows WinDivert 路径
- Windows Npcap 回退路径
- macOS raw/BPF/pcap 路径

如果某个平台路径未针对本次发布验证，请在发布说明中记录该边界。

## 8. 协议兼容性检查

验证：

- client v1 -> server accepting v1
- client v2 -> server accepting v2
- server accepting both v1 and v2
- client/server mismatch failure
- unknown TCP flags rejection
- unknown UDP flags rejection
- envelope v2 route hint mode
- envelope v2 no-hint mode with candidate limits
- server proof enabled
- server proof required by client

## 9. 文档检查

确认文档覆盖：

- 当前安装路径
- 最小监听器和拨号器示例
- `ServerAuth` 重放缓存要求
- v1/v2 协议选择，且不暗示只有一种有效路径
- 默认 TCP 认证协议
- TCP 方法优先的 knock 方法表
- 防火墙后端选择
- iptables 由进程管理清理的注意事项
- UDP 被动要求
- Windows/macOS 平台边界
- 发布测试矩阵

## 10. 产物检查

对于源码归档：

- 无绝对路径
- 无 `../` 路径穿越
- 无不需要的二进制文件
- 顶层目录符合预期
- 存在 `LICENSE`
- 存在 `README.md`
- 存在 `docs/`
- 存在模块文件
- 标准归档不包含 `vendor/`
- `with-vendor` 归档包含 `vendor/modules.txt` 并可用 `-mod=vendor` 构建
- SHA-256 文件与上传归档一致

最小归档审计命令：

```sh
version=<VERSION>
zipinfo -1 "dist/libknock-${version}.zip" | grep -Ev "^libknock-${version}/" && exit 1 || true
zipinfo -1 "dist/libknock-${version}.zip" | grep -E "(^/|(^|/)\.\./)" && exit 1 || true
zipinfo -1 "dist/libknock-${version}.zip" | grep -q "^libknock-${version}/vendor/" && exit 1 || true
zipinfo -1 "dist/libknock-${version}-with-vendor.zip" | grep -q "^libknock-${version}/vendor/modules.txt"
sha256sum -c "dist/libknock-${version}.zip.sha256"
sha256sum -c "dist/libknock-${version}-with-vendor.zip.sha256"
```

## 11. 发布决策

RC 的推荐阈值：

```text
unit tests pass
vet passes
build passes
race smoke tests pass
nested modules pass
docs are internally consistent
api snapshot passes
```

稳定标签的推荐阈值：

```text
RC threshold
+ Linux firewall environment checks complete
+ UDP passive checks complete if documented as supported
+ platform boundaries documented for Windows/macOS
+ fuzz smoke or longer fuzz run complete
+ release notes written
```


依赖模型：为普通 Go module 用户发布标准源码归档，同时发布 companion `with-vendor` 归档，用于离线审查、可复现本地审计、LLM 辅助集成和受限 CI。vendored 归档必须包含 `vendor/`、`vendor/modules.txt`、`go.work` 和 `go.work.sum`。

## Vendored 归档验证

发布 `with-vendor` 归档前运行：

```sh
go work vendor
go test -mod=vendor ./...
go vet -mod=vendor ./...
go test -mod=vendor ./observability/prometheus/...
go test -mod=vendor ./test/integration/grpc/...
go test -mod=vendor ./examples/grpc-client/... ./examples/grpc-server/...
```

## 未运行 / 原因 / 风险 / 后续

发布说明必须正式记录未运行项，例如 nftables/iptables/ipset 真机验证、UDP passive DROP、Windows WinDivert/Npcap、macOS BPF/pcap、长时间 fuzz、生产吞吐基线。不要把环境限制只写在口头说明里。
