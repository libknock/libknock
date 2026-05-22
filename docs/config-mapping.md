# Configuration mapping

`libknock` is an SDK. It does not read application YAML/JSON/TOML files and should not grow APIs such as `RunServer(configPath)`.

`cmd/knock-proxy` is the compatibility caller that reads legacy command configuration, maps it into SDK structs, and starts the selected mode. Embedding applications should perform the same mapping in their own configuration layer.

| Product/legacy concept | SDK target |
| --- | --- |
| protected listen address | `gate.Config.Listen` or application `net.Listen` passed to `libknock.NewListener` |
| upstream relay address | `relay.Config.Upstream` |
| client secrets | `auth.StaticSecrets`, custom `auth.SecretResolver`, or `knock.ClientSecret` list for knock listeners |
| TCP auth protocol | `auth.ServerConfig.Protocol` / `auth.ClientConfig.Protocol` |
| knock method | `gate.Config.KnockMethod`, `relay.Config.KnockMethod`, or `knock.SendOptions.Method` |
| replay window/cache | shared `auth.ReplayCache` on `auth.ServerConfig` |
| firewall backend | `firewall.New(firewall.Config{...})` passed to `gate.Config.Firewall` / `relay.Config.Firewall` |
| observability sink | `auth.ServerConfig.Events`, `gate.Config.Events`, or `relay.Config.Events` |

Keep parsing, validation of product-specific files, secret storage, and service lifecycle outside SDK core packages.
