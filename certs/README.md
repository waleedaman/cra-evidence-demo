# Demo certificates

`make certs` creates a **demo-only** certificate authority and a certificate for the
local Mosquitto broker in `certs/generated/`. Everything except the CA private key is
committed:

| File | Used by | Notes |
| --- | --- | --- |
| `demo-ca.der` | firmware (embedded at build time) | the only CA the device trusts |
| `demo-ca.crt` | `mosquitto_sub` in `make run` | same CA, PEM |
| `demo-ca.key` | `make certs` only | private, git-ignored, stays on the machine that ran `make certs` |
| `server.crt` / `server.key` | Mosquitto | SAN `mosquitto`, `localhost`; the broker key is committed (demo only, protects nothing) |

All keys are ECDSA P-256, matching the single TLS cipher suite the firmware enables
(TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256). The device has no clock source, so
certificate validity dates are not checked on the device.

The CA certificate is compiled into the firmware. That is why the certificates are
committed: every clone builds the same firmware hash, and the committed decisions
(bound to that hash) apply. Regenerating (`make certs FORCE=1`) creates a new CA and
changes the firmware hash; every decision then becomes stale (scenario 4 shows why).

`server.key` is a private key in a public repository on purpose. It is the key of a demo
broker on an internal Docker network and must never be used for anything else. Secret
scanners will flag it; that is expected.

These certificates protect nothing. They exist so the demo shows a real TLS
handshake with server verification.
