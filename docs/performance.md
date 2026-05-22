# Performance notes

This page records benchmark dimensions and reproduction commands. It does not claim universal throughput across kernels, CPU families, packet capture drivers, or firewall backends.

## Benchmark dimensions

Current benchmark coverage includes:

- protocol frame encode/decode
- Envelope v2 seal/open
- Envelope v2 open with route hints
- Envelope v2 no-hint open across multiple candidates
- replay cache check-and-mark
- UDP knock frame build/open
- UDP sequence tracker aggregation
- gate auth-only accept path

## Reproduction command

```sh
go test -run=^$ -bench=. ./auth ./protocol ./knock ./policy ./gate
```

For release notes, record:

```text
Go version: go version
OS/arch:    uname -a or equivalent
CPU:        lscpu / sysctl / system profiler summary
Command:    exact go test -bench command
```

## Interpretation

Benchmarks isolate library-level operations. They do not include Internet latency, kernel firewall update cost on every platform, packet capture driver overhead, or application protocol work after authentication. Treat results as regression signals first and capacity-planning inputs only after validating on the target deployment host.

## rc3 microbenchmark baseline

Environment-limited baseline captured during current mainline preparation:

```text
Go version: go1.24.10 linux/arm64
OS/arch:    Linux 6.1.0-47-arm64 arm64
Command:    go test -run=^$ -bench='Benchmark(EnvelopeV2OpenWithRouteHint|EnvelopeV2OpenWithHintNoneManyCandidates|ReplayCacheCheckAndMark|KnockFrameBuildOpen|SequenceTracker)' -benchtime=100x ./auth ./protocol ./knock
Scope:      microbenchmarks only; no production throughput claim.
```

Record benchstat output in release notes when comparing this baseline against future commits. Do not extrapolate these numbers to firewall mutation throughput, passive-capture overhead, or Internet latency without target-host measurements.
