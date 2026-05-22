# Relay gateway


## Preferred constructor

Use `relay.NewGateway(relay.Config{...})` for new code. Direct `relay.Gateway{...}` construction remains compatible in v0.1.x but is not the preferred pattern because defaults are easier to audit through `Config.WithDefaults()`.

```go
gw := relay.NewGateway(relay.Config{
    Listen:   ":9000",
    Upstream: "127.0.0.1:19000",
    Auth:     authCfg,
    Firewall: firewall.Noop{},
})
err := gw.Run(ctx)
```
