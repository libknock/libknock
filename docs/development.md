# Development guide

This guide describes the internal package layout, test workflow, and extension rules for `libknock` contributors.

## Repository layout

```text
protocol/       TCP auth and UDP knock wire formats, codec, crypto helpers
auth/           server/client auth state machines, replay cache, secret resolvers
netx/           authenticated listener and dialer wrappers
gate/           SDK listener composition modes
relay/          TCP relay gateway and knock session store
knock/          knock senders, listeners, sequence tracking
firewall/       firewall backend interface and implementations
policy/         limiter and ban policy adapters
observability/  event interfaces and optional metrics adapters
cmd/knock-proxy command entrypoint
examples/       runnable integration examples
```

## Package boundaries

`protocol` owns byte-level formats. It should remain free of network listener logic.

`auth` owns authentication state machines. It can depend on `protocol`, replay caches, secret resolvers, and event interfaces.

`netx` owns `net.Listener` and `net.Dialer` integration.

`gate` composes listener, knock, firewall, and auth behavior for SDK-embedded applications.

`relay` composes auth, optional knock/firewall, and TCP forwarding.

`knock` owns knock packet send/listen behavior and sequence aggregation.

`firewall` owns firewall backends and command execution boundaries.

`cmd/knock-proxy` wires product config into SDK structs and command behavior.

## Core invariants

Keep these invariants stable:

1. Successful server authentication returns a clean `net.Conn`.
2. Bytes read beyond the auth frame remain available to the application protocol through buffered connection handling.
3. Replay protection is scoped to a logical server lifetime.
4. Public input paths enforce explicit size limits.
5. Firewall backends that install system rules are bound to one protected port.
6. SDK packages accept typed Go values and interfaces.
7. Optional adapters stay outside the core dependency path.
8. Public network failure behavior does not expose detailed authentication reasons.
9. Secrets, raw frames, and sealed payload bytes are not logged by SDK code.

## Test workflow

Core module:

```sh
scripts/check.sh
```

For a shorter local loop while editing:

```sh
go test ./...
go vet ./...
go build ./...
go test -race ./auth ./firewall ./knock ./netx ./policy ./protocol ./relay
```

Prometheus module:

```sh
go -C observability/prometheus test ./...
go -C observability/prometheus vet ./...
```

gRPC integration module:

```sh
go -C test/integration/grpc test ./...
go -C test/integration/grpc vet ./...
```

Short fuzz checks:

```sh
go test ./protocol -run=^$ -fuzz=FuzzDecodePayload -fuzztime=30s
go test ./protocol -run=^$ -fuzz=FuzzReadFrame -fuzztime=30s
go test ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=30s
```

Cross-platform build matrix:

```sh
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done
```

## Examples

Examples should stay runnable with minimal setup:

```text
examples/custom-binary-protocol/
examples/http-client/
examples/tls-client/
examples/tls-server/
examples/grpc-client/
examples/grpc-server/
```

Keep example code focused on one integration pattern at a time.

## Adding a protocol field

When adding authenticated metadata:

1. Define the byte-level representation in `protocol`.
2. Add encode/decode round-trip tests.
3. Add malformed input tests.
4. Bind the field into AEAD payload or AAD according to its semantics.
5. Add server validation.
6. Add client construction.
7. Update `PeerInfo` only when applications need to observe the field.
8. Update documentation and examples.

## Adding a knock method

When adding a knock method:

1. Add method constants and sender/listener implementations in `knock`.
2. Add client dispatch in `SendMethod`.
3. Add platform-specific build tags if needed.
4. Add event fields needed by `gate` and `relay`.
5. Add replay and sequence tests.
6. Update [Knock methods](knock-methods.md).

Use this display order in docs and UI:

```text
tcp-syn
tcp-syn-seq
udp
udp-seq
udp-passive
udp-passive-seq
```

## Adding a firewall backend

When adding a firewall backend:

1. Implement the `firewall.Backend` interface.
2. Validate protected port binding.
3. Validate command/object names before privileged operations.
4. Make `Init`, `Allow`, `Revoke`, `IsAllowed`, and `Cleanup` idempotent where practical.
5. Add dry-run or fake-runner tests where applicable.
6. Add real-environment test notes to release checks.
7. Update [Firewall backends](firewall.md).

## Updating public API

Before changing public API:

1. Keep the root package limited to common SDK entry points unless there is a strong compatibility reason.
2. Put advanced capabilities in subpackages such as `auth`, `gate`, `relay`, `firewall`, `knock`, or `observability`.
3. Add tests through the root package only for root-package behavior.
4. Update [API reference](api.md).
5. Update examples if the change affects common integration paths.
6. Keep optional adapters outside the core dependency path.

## Release checks

Before tagging a release candidate:

```sh
scripts/check.sh
go -C observability/prometheus test ./...
go -C test/integration/grpc test ./...
```

Recommended environment checks before a stable tag:

```text
Linux nftables backend
Linux ipset-iptables backend
Linux iptables backend
UDP sequence methods
UDP passive methods
TCP SYN sequence methods on available platforms
Prometheus adapter module
Example programs
```

Use [Release checklist](release-checklist.md) as the authoritative release checklist.
