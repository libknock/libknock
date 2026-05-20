# CI and local release gates

The GitHub workflow runs the main module tests, vet, selected race tests, nested module tests, example builds, and cross-platform compile checks. Local release gates add short fuzz smoke, benchmark smoke, documentation link checks, duplication checks, and license/dependency checks. Do not describe these local-only gates as enforced by CI unless the workflow invokes `scripts/release-check.sh`.

## CI checks vs maintainer release checks

GitHub Actions are a CI signal, not the complete release gate. Strict duplication, package artifact audit, benchmark smoke, long fuzz campaigns, and real-host firewall/passive/platform validation are maintainer responsibilities unless the workflow explicitly invokes those checks.

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


## Optional strict duplication gate

`DUPL_THRESHOLD=120 STRICT=1 scripts/check-duplication.sh` is a release-maintainer gate and requires `dupl`:

```sh
go install github.com/mibk/dupl@latest
```

Normal contributors may run the script without `STRICT=1`; missing `dupl` is then warning-only.
