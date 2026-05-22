# Release checklist

This checklist is intended for release candidates and stable tags.

## 1. Source tree checks

```sh
scripts/check.sh
```

The script works both inside a git checkout and from a release source zip. Publish both `libknock-VERSION.zip` for normal Go module users and `libknock-VERSION-with-vendor.zip` for offline review, reproducible local audit, LLM-assisted integration, and restricted CI. The vendored archive must include `vendor/`, `vendor/modules.txt`, `go.work`, and `go.work.sum`.

Package archives from a git checkout with:

```sh
scripts/package-release.sh --with-vendor VERSION dist/
```

Use `--standard-only` or `--with-vendor-only` only for re-running one side of the packaging gate. The packaging script uses `git archive` when run in the repository so generated or untracked files do not accidentally enter release zips. If you must create archives from an exported source tree without `.git`, do not hand-roll a zip silently: first run the same source checks, vendor generation, path-traversal audit, and SHA-256 audit listed below, and record the non-git packaging reason in the release validation record. Prefer restoring a clean git checkout whenever possible.

Expanded core commands, if running steps manually:

```sh
go mod download
go mod tidy
scripts/check.sh
go test -count=1 ./...
go vet ./...
go build ./...
go test -race -count=1 ./auth ./firewall ./gate ./knock ./netx ./policy ./protocol ./relay
```

## 2. Nested modules

```sh
go -C observability/prometheus test -count=1 ./...
go -C observability/prometheus vet ./...
go list -m all | grep 'github.com/libknock/libknock <VERSION>'
go -C observability/prometheus list -m all | grep 'github.com/libknock/libknock <VERSION>'
go -C test/integration/grpc test -count=1 ./...
go -C test/integration/grpc vet ./...
go test -count=1 ./examples/grpc-client/... ./examples/grpc-server/...
go build ./examples/tcp-echo-client ./examples/tcp-echo-server
go build ./examples/tls-client ./examples/tls-server
go build ./examples/custom-binary-protocol/client ./examples/custom-binary-protocol/server
```

## 3. Fuzz smoke tests

Run short fuzz checks before RC and longer runs before stable release.

```sh
go test ./protocol -run=^$ -fuzz=FuzzDecodePayload -fuzztime=60s
go test ./protocol -run=^$ -fuzz=FuzzReadFrame -fuzztime=60s
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=60s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=60s
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=60s
go test ./knock -run=^$ -fuzz=FuzzSequenceTracker -fuzztime=60s
```

`scripts/release-check.sh` runs a representative short fuzz smoke; use `scripts/fuzz-long.sh` for the full protocol/knock/auth fuzz set. For stable tags, increase fuzz time according to project policy.

## 4. Cross-platform build

```sh
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done
```

Record the Go version used for the release.

## 5. Linux firewall environment checks

These checks are Linux-only and require a controlled host with the required privileges. On Windows/macOS, skip them and record `platform-specific / not validated on current host`; the skip is not a core SDK failure.

Suggested opt-in environment flags for automation:

```text
LIBKNOCK_RUN_PRIVILEGED_TESTS=1
LIBKNOCK_RUN_LINUX_FIREWALL_TESTS=1
LIBKNOCK_RUN_PACKET_TESTS=1
```

Run privileged tests or manual validation for:

- `nftables` backend
- `ipset-iptables` backend
- `iptables` backend
- IPv4 allow/revoke
- IPv6 allow/revoke where supported
- cleanup idempotency
- startup cleanup after simulated unclean exit
- protected port binding validation
- `drop_udp_knock_port` with passive UDP methods

Minimum manual flow for each backend:

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

## 6. UDP and sequence checks

Validate:

- `udp`
- `udp-seq`
- `udp-passive`
- `udp-passive-seq`
- missing sequence part failure
- duplicate sequence part handling
- out-of-order sequence success when configured
- sequence timeout
- session binding with subsequent TCP auth

## 7. TCP SYN platform checks

Where supported by the release target, validate:

- `tcp-syn`
- `tcp-syn-seq`
- Linux raw socket capability path
- Windows WinDivert path
- Windows Npcap fallback path
- macOS raw/BPF/pcap path

If a platform path is not verified for the release, document that boundary in release notes.

## 8. Protocol compatibility checks

Validate:

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

## 9. Documentation checks

Confirm docs cover:

- current install path
- minimal listener and dialer examples
- `ServerAuth` replay-cache requirement
- v1/v2 protocol selection without implying only one valid path
- default TCP auth protocol
- knock method table with TCP methods first
- firewall backend selection
- iptables process-managed cleanup caveat
- UDP passive requirements
- Windows/macOS platform boundaries
- release test matrix
- `llms.txt`, `docs/llms.md`, and agent recipes point IDE assistants at the root SDK path and current release boundaries

## 10. Artifact checks

For source archives:

- no absolute paths
- no `../` path traversal
- no unwanted binaries
- expected top-level directory
- `LICENSE` present
- `README.md` present
- `docs/` present
- module files present
- standard archive excludes `vendor/`
- `with-vendor` archive includes `vendor/modules.txt` and builds with `-mod=vendor`
- SHA-256 files correspond to the uploaded archives

Minimal archive audit commands:

```sh
version=<VERSION>
zipinfo -1 "dist/libknock-${version}.zip" | grep -Ev "^libknock-${version}/" && exit 1 || true
zipinfo -1 "dist/libknock-${version}.zip" | grep -E "(^/|(^|/)\.\./)" && exit 1 || true
zipinfo -1 "dist/libknock-${version}.zip" | grep -q "^libknock-${version}/vendor/" && exit 1 || true
zipinfo -1 "dist/libknock-${version}-with-vendor.zip" | grep -q "^libknock-${version}/vendor/modules.txt"
sha256sum -c "dist/libknock-${version}.zip.sha256"
sha256sum -c "dist/libknock-${version}-with-vendor.zip.sha256"
```


## 11. Not run / Reason / Risk / Follow-up

Record environment-limited checks as formal release data instead of verbal caveats. At minimum, fill this table in the release notes or `docs/validation/<VERSION>.md`:

| Area | Status | Reason | Risk | Follow-up |
| --- | --- | --- | --- | --- |
| nftables real-host mutation | not run / tested |  |  |  |
| iptables real-host mutation | not run / tested |  |  |  |
| ipset-iptables real-host mutation | not run / tested |  |  |  |
| UDP passive DROP behavior | not run / tested |  |  |  |
| Windows WinDivert/Npcap | not run / tested |  |  |  |
| macOS BPF/pcap | not run / tested |  |  |  |
| long fuzz | not run / tested |  |  |  |
| production throughput | not run / tested |  |  |  |

## 12. Release decision

Recommended threshold for RC:

```text
unit tests pass
vet passes
build passes
race smoke tests pass
nested modules pass
docs are internally consistent
api snapshot passes
```

Recommended threshold for stable tag:

```text
RC threshold
+ Linux firewall environment checks complete
+ UDP passive checks complete if documented as supported
+ platform boundaries documented for Windows/macOS
+ fuzz smoke or longer fuzz run complete
+ release notes written
```


Dependency model: publish a standard source archive for normal Go module users and a companion `with-vendor` archive for offline review, reproducible local audit, LLM-assisted integration, and restricted CI. The vendored archive must include `vendor/`, `vendor/modules.txt`, `go.work`, and `go.work.sum`.


## Vendored archive validation

Before publishing the `with-vendor` archive, run:

```sh
go work vendor
go test -mod=vendor ./...
go vet -mod=vendor ./...
go test -mod=vendor ./observability/prometheus/...
go test -mod=vendor ./test/integration/grpc/...
go test -mod=vendor ./examples/grpc-client/... ./examples/grpc-server/...
go build -mod=vendor ./examples/tcp-echo-client ./examples/tcp-echo-server ./examples/tls-client ./examples/tls-server ./examples/custom-binary-protocol/client ./examples/custom-binary-protocol/server
```
