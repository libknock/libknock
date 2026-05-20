# Protocols

`libknock` has three wire-level components:

1. TCP auth protocol v1: `tcp-auth-frame-v1`
2. TCP auth protocol v2: `tcp-auth-envelope-v2`
3. UDP knock frame v1

All three use authenticated cryptographic framing and bounded input sizes. The default AEAD is ChaCha20-Poly1305. HKDF-SHA256 is used for frame-specific key derivation.

## TCP auth protocol v1

`tcp-auth-frame-v1` is a compact binary frame used immediately after TCP connect and before the application protocol starts.

```text
fixed header:
  version[1]
  flags[1]
  reserved[1]
  nonce[16]
  key_hint[8]
  sealed_len[2]

sealed payload:
  AEAD(client_id_hash, timestamp_unix_ms, server_port, method, session_id, extensions)

AAD:
  version || flags || reserved || nonce || key_hint || sealed_len
```

Properties:

- `nonce` is random per authentication attempt.
- `key_hint` helps the server select candidate secrets.
- `sealed_len` is bounded by `MaxFrameSize`.
- `reserved` must be zero.
- Unknown TCP flags are rejected.
- The currently valid TCP flag is `FlagServerProof`.

Client identity is represented by `client_id_hash` inside the sealed payload. The server maps the verified hash back to the resolved client identity. Frame v1 uses `nonce || key_hint` as the XChaCha20-Poly1305 nonce and also authenticates `key_hint` in AAD; this is retained as wire-compatible v1 behavior and must not be changed in v0.1.x release candidates.

## TCP auth protocol v2

`tcp-auth-envelope-v2` is a sealed envelope format used immediately after TCP connect and before the application protocol starts.

```text
wire:
  prefix_random[24]
  route_hint[0 or 8]
  sealed_envelope[remaining bucket bytes]

bucket_size:
  one of 128, 192, 256, 384, 512 by default

sealed_envelope:
  AEAD(version, flags, timestamp_unix_ms, client_id_hash, server_port,
       method, session_id, extensions, padding_len, random_padding)
```

Route hint:

```text
route_hint = Trunc64(HMAC(client_secret,
  "libknock tcp-auth hint v2" || prefix_random || server_port))
```

Key derivation:

```text
K_auth = HKDF-SHA256(
  secret = client_secret,
  salt   = prefix_random,
  info   = "libknock tcp-auth envelope v2"
)
```

AAD with route hints:

```text
prefix_random || route_hint || bucket_size || server_port || "tcp-auth-envelope-v2"
```

AAD without route hints:

```text
prefix_random || bucket_size || server_port || "tcp-auth-envelope-v2"
```

The server selects candidate secrets with the route hint when enabled, opens the envelope with AEAD, validates timestamp and replay state, then returns a clean `net.Conn` to the caller. Route hints are the default and recommended mode. `HintModeNone` forces the resolver to return broader candidate sets and is intended only for small client populations or custom resolvers that impose deterministic limits. Built-in map-backed resolvers sort candidates by `client_id`; if a no-hint candidate set exceeds `ServerConfig.MaxAuthAttempts`, the server returns `auth.ErrTooManyCandidates` rather than failing nondeterministically.

AAD rationale:

- `prefix_random` binds the sealed body to its per-connection nonce and key-derivation context.
- `route_hint` is authenticated when present so a sealed envelope cannot be moved between resolver buckets.
- `bucket_size` is authenticated so padding cannot be stripped or expanded without AEAD failure.
- `bucket_size` must not exceed the server `MaxFrameSize`. Tightening `ServerConfig.MaxFrameSize` requires tightening client `EnvelopeV2.FrameSizeBuckets` as well; a client that can randomly choose `384` or `512` will fail against a server capped at `256`.

Server/client sizing example:

```go
serverCfg.MaxFrameSize = 256
clientCfg.EnvelopeV2.FrameSizeBuckets = []int{128, 192, 256}
```

Do not deploy `FrameSizeBuckets: []int{128, 192, 256, 384, 512}` against a server capped at `256`; some otherwise valid authentication attempts will be rejected whenever the client chooses a larger bucket.
- `server_port` is authenticated for NAT and forwarding deployments where the socket port can differ from the protected service port.
- `tcp-auth-envelope-v2` domain-separates the envelope from other libknock AEAD uses.

## Protocol selection

```go
type AuthProtocol string

const (
    AuthProtocolFrameV1    AuthProtocol = "tcp-auth-frame-v1"
    AuthProtocolEnvelopeV2 AuthProtocol = "tcp-auth-envelope-v2"
    DefaultAuthProtocol                 = AuthProtocolEnvelopeV2
)
```

Client selection:

```go
clientCfg.Protocol = auth.AuthProtocolEnvelopeV2
```

Server selection:

```go
serverCfg.Protocol = auth.AuthProtocolEnvelopeV2
serverCfg.AcceptProtocols = []auth.AuthProtocol{
    auth.AuthProtocolEnvelopeV2,
}
```

A listener can accept both TCP auth protocols if `AcceptProtocols` includes both values:

```go
serverCfg.AcceptProtocols = []auth.AuthProtocol{
    auth.AuthProtocolFrameV1,
    auth.AuthProtocolEnvelopeV2,
}
```

Keep client and server protocol settings aligned during rollout and test every accepted protocol path in CI.

## TCP SYN sequence namespace

The default SYN sequence namespace is `libknock/tcp-syn-seq/v1`. The legacy `knock-proxy/tcp-syn-seq/v1` namespace is retained only as an explicit compatibility layer through `SequenceOptions.AllowLegacySYNSeq`; it is not part of the default verification surface for new SDK deployments. Migration guidance should keep this compatibility flag visible instead of silently accepting old wire material.

## UDP knock frame v1

UDP knock uses a datagram-sized binary frame.

```text
fixed header:
  nonce[16]
  key_hint[8]
  sealed_len[2]
  flags[1]
  reserved[1]

sealed payload:
  AEAD(frame_type, client_id_hash, timestamp_unix_ms, method, server_port,
       session_id, sequence_id, sequence_index, sequence_total,
       client_random, extensions)

AAD:
  nonce || key_hint || sealed_len || flags || reserved || protocol_version || dst_port
```

Route key:

```text
key_hint = Trunc64(HMAC(client_secret,
  "libknock udp-knock hint v1" || nonce || server_port))
```

Identity hash:

```text
client_id_hash = Trunc128(HMAC(client_secret,
  "libknock client-id v1" || client_id))
```

Key derivation:

```text
K_knock = HKDF-SHA256(
  secret = client_secret,
  salt   = nonce,
  info   = "libknock udp-knock frame v1"
)
```

The frame supports single-packet methods and sequence methods. Sequence fields are carried in the sealed payload.

## Sessions

A knock can carry a random `session_id`. With `RequireKnock`, the server records the session with:

- remote address
- client identity
- protected port
- expiration time
- remaining uses
- session ID

The following TCP auth frame must carry the matching `session_id`. A successful TCP authentication consumes one use. `RemoveAfterAuth` can revoke the firewall lease and clear the stored session immediately after authentication.

## Server proof

Server proof is optional. When enabled, the server returns an authenticated proof after validating the client auth frame. Clients set `RequireServerProof` to require that response before starting the application protocol.

Server proof adds one response step before the application protocol begins. If the application already uses TLS with server authentication, keep this disabled unless the deployment specifically needs the additional check.

## Defaults

| Setting | Default |
| --- | --- |
| TCP auth protocol | `tcp-auth-envelope-v2` |
| `AuthTimeout` | `3s` |
| `TimeWindow` | `30s` |
| `MaxFrameSize` | `1024` |
| `MaxAuthAttempts` | `64` |
| envelope v2 hint mode | `route-hint` |
| envelope v2 padding policy | `random-bucket` |
| envelope v2 buckets | `128`, `192`, `256`, `384`, `512` |
| UDP sequence window | `5s` |
| UDP sequence max parts | `8` |
| minimum secret size | `16` bytes |

## Failure behavior

On authentication failure, public network behavior is intentionally simple: the connection is closed. Applications can observe structured error classes internally through `EventSink` and normal Go errors.

Do not write raw secrets, complete frame bytes, or sealed payload bytes to logs.
