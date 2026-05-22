# Add a firewall backend test

## Modify

- `firewall/*`
- `firewall/dryrun_test.go` or a focused backend test file
- `docs/firewall.md`, `docs/production.md`, or validation docs when behavior or support status changes

## Do not modify

- Real host firewall state in unit tests.
- Release notes to claim privileged validation unless a controlled host command log exists.

## Required commands

```sh
go test -mod=vendor ./firewall
go test -race -mod=vendor ./firewall
scripts/check-doc-links.py
```

Privileged host checks are opt-in only:

```sh
LIBKNOCK_RUN_PRIVILEGED_TESTS=1 LIBKNOCK_RUN_LINUX_FIREWALL_TESTS=1 scripts/validate-nftables.sh
```

## Completion report

Describe dry-run coverage, any privileged validation skipped or run, cleanup/idempotency behavior, and exact commands run.
