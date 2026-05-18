# Modes

| Mode | TCP port visibility | Firewall mutation | Application admission |
| --- | --- | --- | --- |
| `auth-only` | TCP listener is open | no | TCP auth required before application bytes are accepted |
| `knock-auth-only` | TCP listener is open | no | prior knock plus TCP auth required |
| `knock-firewall-auth` | firewall blocks until knock succeeds | yes | prior knock plus TCP auth required |
| `knock-firewall-only` | firewall blocks until knock succeeds | yes | prior knock required; TCP auth is not performed by gate |

`knock-auth-only` is not port hiding. A SYN scan can still report the TCP port as open. Its value is that an unauthenticated connection cannot enter the application protocol unless it first presents a valid knock and then passes TCP authentication.
