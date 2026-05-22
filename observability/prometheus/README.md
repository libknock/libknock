# Prometheus adapter

The optional `observability/prometheus` module maps libknock event sinks into bounded-label Prometheus metrics.

Use `New` when constructing sinks in tests, dynamic registries, plugin systems, or any path where descriptor conflicts should be returned as errors:

```go
sink, err := prometheus.New(prometheus.Config{Registerer: reg})
if err != nil {
    return err
}
```

Use `MustNew` only during process startup wiring where a metrics descriptor or registration conflict is a local configuration bug and fail-fast panic is preferable to serving with a broken metrics surface. Do not call `MustNew` from request paths or runtime-created tenant/plugin registries.
