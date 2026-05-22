# Add a protocol fuzz seed

## Modify

- `protocol/*_test.go` or `auth/*_test.go` fuzz seed corpus setup
- `docs/validation-matrix.md` or release validation records if fuzz policy changes

## Do not modify

- Wire format constants or compatibility behavior unless the task explicitly includes a migration.
- `MIGRATION.md` claims without a real compatibility decision.

## Required commands

```sh
go test -mod=vendor ./protocol ./auth
go test -mod=vendor ./protocol -run=^$ -fuzz=FuzzEnvelopeV2Open -fuzztime=30s -parallel=1
go test -mod=vendor ./auth -run=^$ -fuzz=FuzzServerAuthMalformedInput -fuzztime=30s -parallel=1
```

## Completion report

Describe the malformed/edge case covered, expected error class, whether bytes are wire-compatible, and exact commands run.
