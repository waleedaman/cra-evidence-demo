# Demo certificates

`make certs` creates a **demo-only** certificate authority and a certificate for the
local Mosquitto broker in `certs/generated/` (git-ignored):

| File | Used by | Notes |
| --- | --- | --- |
| `demo-ca.der` | firmware (embedded at build time) | the only CA the device trusts |
| `demo-ca.crt` | `mosquitto_sub` in `make run` | same CA, PEM |
| `demo-ca.key` | `make certs` only | private, never committed |
| `server.crt` / `server.key` | Mosquitto | SAN `mosquitto`, `localhost` |

All keys are ECDSA P-256, matching the single TLS cipher suite the firmware enables
(TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256). The device has no clock source, so
certificate validity dates are not checked on the device.

The CA certificate is compiled into the firmware. Regenerating it (`make certs FORCE=1`)
changes the firmware hash. Every clone generates its own CA, so firmware hashes are
only comparable between builds that use the same `certs/generated/`.

These certificates protect nothing. They exist so the demo shows a real TLS
handshake with server verification.
