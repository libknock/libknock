# Manual validation template

Use this template when validating firewall or packet-capture behavior on a real host. Do not fill it with simulated or dry-run results.

```text
Date:
Operator:
Repository commit:
Host / VM:
OS / distribution:
Kernel / version:
Architecture:
Container / namespace context:
Privileges:
  root:
  CAP_NET_ADMIN:
  CAP_NET_RAW:
Backend / method:
Config file:
Commands run:
Expected result:
Actual result:
Logs:
Firewall rules before:
Firewall rules after init:
Firewall rules after allow:
Firewall rules after cleanup:
Packet capture notes:
Rollback / cleanup performed:
Reproducible:
Conclusion:
```

Attach command output or rule snapshots to the release evidence bundle when possible.
