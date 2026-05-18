# CI and local release gates

The GitHub workflow runs the main module tests, vet, selected race tests, nested module tests, example builds, and cross-platform compile checks.

Local release gates should run:

```sh
scripts/check.sh
scripts/release-check.sh
```

Optional longer gates:

```sh
go test ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=5m
go test ./knock -run=^$ -fuzz=FuzzOpenKnockFrame -fuzztime=5m
go test -run=^$ -bench=. ./auth ./protocol ./knock ./policy ./gate
```

Docs link checks and license/dependency checks are intentionally included in the release script as lightweight static checks. They do not replace manual review of generated release archives.
