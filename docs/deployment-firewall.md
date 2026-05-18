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
