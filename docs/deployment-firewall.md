# Firewall deployment

Firewall-backed modes are platform-specific. Repository tests cover configuration, command generation, dry-run behavior, and cleanup shape; they do not prove that a real host firewall accepted and enforced rules.

## Backend selection

Prefer backends in this order when available:

1. `nftables`: preferred Linux backend. It supports timeout-oriented sets and cleaner rule ownership.
2. `ipset-iptables`: acceptable fallback when nftables is unavailable. It uses ipset timeouts for client allow entries.
3. `iptables`: last-resort fallback. Plain iptables rules do not have native per-rule expiry; libknock schedules revoke operations and performs managed-chain cleanup.
4. `script`: use only when the operator owns and tests the external scripts.
5. `noop`: for auth-only or knock-auth-only modes that must not mutate firewall rules.

## iptables fallback risk

The `iptables` backend can leave temporary ACCEPT rules behind if the process or host exits before scheduled revocation. Startup/shutdown cleanup reduces this risk by deleting managed jump/drop rules and flushing the managed chain, but it is not a substitute for target-host validation or external firewall policy controls.

## Dry-run versus real validation

Fake runner tests validate command shape, port binding checks, cleanup idempotency, and error propagation. They cannot prove kernel module availability, nftables family/table semantics, iptables variant behavior, container namespace policy, host firewall ordering, NAT interaction, or packet capture privileges.

Before production use, run the validation scripts on a disposable or recoverable host and record results using [Validation template](validation-template.md).

## Knock frames are not bound to the sender's IP

In `knock-firewall-only` mode the firewall is opened for the source address the
knock packet *arrived from*; the encrypted knock payload does not carry an
authorised client IP. An on-path attacker who captures a valid knock can race
the legitimate client by re-sending it from their own address before it is
delivered (the replay cache then rejects the real one). This is the classic
single-packet-authorisation caveat; fwknop mitigates it by embedding the
allowed IP in the payload.

Recommendations:

- Prefer `knock-firewall-auth` (or `proxy`) so the opened port still requires a
  full TCP authentication handshake; a stolen knock then only exposes the auth
  endpoint, not the service.
- Keep `firewall.allow_seconds` short and `remove_after_auth: true`.
- Do not use `knock-firewall-only` across untrusted shared links (public Wi-Fi,
  hostile transit) for services without their own authentication.

## Per-source auth limits

`limits.max_pending_auth_per_source` (library: `MaxPendingAuthPerSource` on
`netx.ListenerConfig` / `relay.Config`) caps how many connections from one
source may be queued or mid-authentication at once. IPv4 is counted per
address and IPv6 per `/64`. It is off by default because many legitimate
clients can share one NAT address; set it below `max_auth_workers` (for example
half) when slow or idle connections from a single source could otherwise
occupy the whole auth worker pool. Policy rate-limit keys use the same
grouping, so IPv6 clients are rate-limited per `/64`.
