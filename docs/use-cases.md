# Use cases

`libknock` is an embeddable TCP pre-application authentication SDK for Go applications.

It provides authenticated `net.Listener` and `net.Dialer` wrappers. The SDK verifies a binary authentication frame before the application protocol starts. After successful authentication, the caller receives a clean `net.Conn`.

`libknock` does not parse, modify, or own the application protocol. Applications can continue to use TLS, HTTP, gRPC, private RPC, custom TCP protocols, long-lived agent connections, or other protocols running on top of TCP.

## Private management endpoints

`libknock` can be used to protect private management endpoints, operation APIs, diagnostic ports, and internal administration services.

```text
admin client
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS / HTTP / gRPC / custom protocol
  -> management service
```

This keeps unauthenticated connections away from the application protocol parser.

## Agent and collector systems

`libknock` is suitable for monitoring agents, log collectors, backup agents, inventory agents, maintenance agents, and edge node clients.

```text
agent
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS / gRPC stream / custom TCP
  -> collector or control server
```

The server can verify client identity, timestamp window, nonce replay state, and client secret before handing the connection to the application layer.

## Private RPC and gRPC services

`libknock` can be integrated into private RPC, gRPC, or internal service-to-service communication paths.

```text
service A
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS
  -> gRPC / private RPC
  -> service B
```

It can be used together with TLS or mTLS. TLS still provides transport security and certificate-based authentication, while `libknock` adds an earlier TCP-level admission step.

## Custom TCP protocols

`libknock` is protocol-agnostic and can protect custom TCP protocols, binary RPC protocols, device protocols, push gateways, game gateways, or other long-lived TCP services.

```text
net.Listener
  -> libknock.WrapListener()
  -> custom TCP protocol handler
```

```text
libknock Dialer
  -> clean net.Conn
  -> custom TCP protocol starts
```

This is useful when the application protocol itself should not be exposed directly to unauthenticated TCP connections.

## Edge node and device gateway control planes

`libknock` can be used for edge nodes, branch nodes, industrial gateways, private cloud nodes, and device control-plane services.

```text
edge node
  -> libknock Dialer
  -> TCP pre-authentication
  -> control-plane API
```

For maintenance scenarios, it can also be combined with optional knock and firewall gate support to create short-lived access windows.

## Partner integration endpoints

For private partner-facing TCP services, `libknock` can be used as an additional admission layer before TLS and application authentication.

```text
partner client
  -> TCP pre-authentication
  -> TLS / mTLS
  -> application authentication
  -> business API
```

This does not replace TLS, mTLS, API tokens, or business-level authorization. It adds an earlier TCP-level authentication step.

## Database proxy or audit gateway frontends

`libknock` can be integrated into custom database proxies, SQL audit gateways, or data access middleware.

```text
client
  -> libknock Dialer
  -> TCP pre-authentication
  -> database proxy / audit gateway
  -> database
```

This is intended for software that integrates the SDK directly. If the protected upstream is a separate binary service, use `relay.Gateway` or another gateway component.

## Software update, license, and configuration channels

Client software, enterprise agents, and private deployment products can use `libknock` before connecting to license servers, update services, or configuration distribution endpoints.

```text
client
  -> libknock Dialer
  -> TCP pre-authentication
  -> TLS
  -> update / license / configuration API
```

This can reduce unauthenticated traffic reaching application services and provide replay-resistant client admission.

## Temporary maintenance access

When combined with optional knock and firewall gate support, `libknock` can be used for temporary maintenance windows.

```text
operator
  -> knock
  -> temporary firewall allow
  -> TCP pre-authentication
  -> maintenance service
```

This is useful for emergency maintenance, diagnostic services, and controlled administrative access.

## Application protocol shielding

Some services do not need to expose their application protocol parser to arbitrary TCP connections. `libknock` can act as a small pre-authentication layer before the application starts processing input.

Unauthenticated connections can be rejected before reaching:

```text
TLS handshake
HTTP parser
gRPC stack
custom binary protocol parser
business authentication logic
```

## Choosing an integration mode

| Mode | Requires SDK integration | TCP pre-authentication | Relay required | Suitable for |
|---|---:|---:|---:|---|
| Authenticated Listener | Yes | Yes | No | Go applications and custom services |
| Authenticated Dialer | Yes | Yes | No | Go clients and agents |
| Knock + Firewall + Auth | Yes | Yes | No | Services needing both gate and pre-auth |
| Knock + Firewall Only | Optional | No | No | Native services that cannot send auth frames |
| Relay Gateway | No | Yes | Yes | Separate upstream TCP services |

## Non-goals

`libknock` is not a VPN.

`libknock` does not replace TLS, mTLS, application authentication, authorization, auditing, or access control.

`libknock` does not parse or modify application protocol payloads.

`libknock` does not manage upstream application binaries.

`libknock` only authenticates the TCP connection before the application protocol starts and then returns a clean `net.Conn` to the caller.

## Building from source packages

Source release archives use Go modules and do not include `vendor/`. Normal users can build with the standard Go toolchain; offline or enterprise environments should provide a populated module cache or dependency mirror before running the build/check scripts.
