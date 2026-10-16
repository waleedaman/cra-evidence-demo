# Scenario 5: new advisory after the release

**Claim:** releasing is not the end. The archived SBOM of firmware in the field is
scanned again with newer data; a new finding re-opens the gate and must be communicated.

**Setup:** v1.0 as released (all decisions signed, VEX signed, gate PASS). Rescan with
snapshot `after` if one was recorded (real data), otherwise baseline + the SYNTHETIC record
DEMO-2026-0001 (`docs/synthetic-data.md`).

| Step | Expected (synthetic fallback) |
| --- | --- |
| gate v1.0 | PASS |
| scan with newer data | 38 findings, mbedtls OSV 1, magenta SYNTHETIC line |
| queue | 1 new: DEMO-2026-0001, mbedtls, Medium |
| gate | FAIL: R4 1 of 38 without decision |
| triage | decision `under_investigation`, due in 14 days, opened by `REVIEWER` |
| vex SIGN=1 | 38 statements incl. `under_investigation 1`, signed |
| gate | PASS (Medium is below the High threshold; due date not passed) |

Rehearse what happens after the due date: `make gate VERSION=v1.0 GATE_DATE=<due + 1>`
inside the scenario workspace fails R7. With a real `after` snapshot the new finding may be
High; then the last gate fails R7 ("still under investigation, >= High"), which is the
policy working as intended.

**Recording the real snapshot:** about 1–2 weeks before the talk, with network:
`make snapshot NAME=after`, commit `vulndb/snapshots.yaml`, `make fetch` on the presenter
machine. Check with `make ready`.

**Alternative considered:** a synthetic record for Zephyr instead of mbedtls. mbedtls was
chosen because the TLS client is clearly reachable in this product, so "under
investigation" is the honest first status.
