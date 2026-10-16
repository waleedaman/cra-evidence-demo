# Synthetic data

Everything in this repository is real data from real tools, with exactly one exception.

## DEMO-2026-0001 (scenario 5 fallback)

| | |
| --- | --- |
| File | `scenarios/5-new-cve/DEMO-2026-0001.osv.json` |
| Format | OSV schema 1.6, ecosystem GIT, repo `https://github.com/Mbed-TLS/mbedtls`, version `v4.1.0` |
| Content | "SYNTHETIC DEMO RECORD, not a real vulnerability": a made-up TLS handshake denial of service, CVSS 3.1 5.9 (Medium) |
| Used when | scenario 5 runs and no snapshot named `after` was recorded |
| Used by | `make scan ... OSV_EXTRA=scenarios/5-new-cve/DEMO-2026-0001.osv.json` |

It describes no real flaw in Mbed TLS. It exists so that scenario 5 ("a new advisory
appears after the release") can be shown when no newer database was recorded before the
talk. The preferred way is real data: about one to two weeks before the talk run
`make snapshot NAME=after` (network), then `make fetch` on the presenter machine; scenario
5 uses the `after` snapshot automatically if it exists, and then shows whatever really
changed. If nothing relevant changed, the synthetic record is the fallback.

### How it is kept apart from real data

- The ID uses the `DEMO-` prefix; `pipeline/scan.py` refuses synthetic records with any
  other prefix.
- The recorded snapshot is never modified: `make scan OSV_EXTRA=...` builds a separate
  copy of the OSV GIT database (`<cache>/osv/<snapshot>+synthetic-<sha12>/`) with the
  record added.
- `findings.json` records it (`snapshot.synthetic_osv_records`), `make scan` prints a
  magenta "SYNTHETIC data added" line, and `make gate` shows "+ 1 SYNTHETIC record(s)" in R3.
- The decision made for it in scenario 5 and the VEX statement exist only in the scenario
  workspace (`out/scenarios/5/`), never in `decisions/`.

## Not synthetic

All CVEs in scenarios 1 to 4 are real records from the `baseline` snapshot (Grype DB and
OSV GIT database recorded 2026-10-15). The cJSON copy is the real upstream v1.7.17 with
the real upstream fix commit; `make cjson-test` runs the real code.
