# The five failure modes (Phase 8)

Each scenario is one make target and runs on the W5500-EVB-Pico2 build
(`w5500_evb_pico2/rp2350a/m33`), the firmware the committed decisions are for.

| # | `make` | Failure mode | Real data used |
| --- | --- | --- | --- |
| 1 | `scenario-1` | Ambiguous identifiers: a vendored library is invisible to scanners | cJSON 1.7.17 in `app/lib/cjson`, 8 real cJSON CVEs |
| 2 | `scenario-2` | Supplier patch: fixed, but the version string still says vulnerable | CVE-2024-31755, upstream fix 7e4d5dab backported |
| 3 | `scenario-3` | Configuration-dependent: the CVE's code is not compiled | CVE-2026-10638 (Zephyr ICMPv6), IPv6 off |
| 4 | `scenario-4` | A configuration change invalidates earlier decisions | v1.1 = v1.0 + `CONFIG_NET_IPV6=y` |
| 5 | `scenario-5` | A new advisory after the release | snapshot `after`, or synthetic DEMO-2026-0001 |

> **Needs approval (chosen overnight, not yet agreed):** the CVE and component of every
> scenario above, the vendoring of cJSON into the application (it builds the MQTT payload
> now), release v1.1 as the scenario 4 change, and the synthetic fallback record for
> scenario 5 (mbedtls, Medium). Alternatives are listed in each scenario's README.

## Before the talk

```bash
make prepare REVIEWER="Your Name"   # builds + scans v1.0 and v1.1, VEX + gate for v1.0 (slow)
make ready   REVIEWER="Your Name"   # fast readiness check, all rows must be OK
```

`make prepare` needs the v1.0 decisions signed (`make review`), otherwise the v1.0 gate
fails and scenario 5 cannot start from a passing release.

## During the talk

```bash
make demo                  # menu
make scenario-3            # or directly; Enter advances each step
make reset                 # delete all scenario workspaces (< 1 s)
```

Every step prints the command as you would type it, waits for Enter, then runs it.
Behind the scenes it adds `OUT_ROOT=out/scenarios/<N> DECISIONS=out/scenarios/<N>/decisions`,
so a scenario works on a copy of the release outputs and of `decisions/` and can be run
any number of times. Nothing tracked is modified. Step durations are appended to
`out/scenarios/<N>/timings.txt`.

`AUTO=1` runs without pauses (`PAUSE_SECONDS=3` waits instead), used by `make record-N`.
Fallback recordings and replay: `docs/presenting.md`.

## Files

- `lib.sh`: step/pause helpers, sourced by every `run.sh`
- `menu.sh`: `make demo`
- `<N>-*/run.sh`, `<N>-*/README.md`: the scenario and its notes
- `5-new-cve/DEMO-2026-0001.osv.json`: the only synthetic data (`docs/synthetic-data.md`)
