# Data model

All files are JSON or YAML (SPDX tag-value for the raw `west spdx` output). Paths are
relative to `out/<release>/<board_dir>/` unless noted. `board_dir` is the board name
with `/` replaced by `_`.

| File | Written by | Format | Key content |
| --- | --- | --- | --- |
| `artifacts.json` | `make build` | JSON | `version`, `board`, `artifacts{name: {sha256, size}}` |
| `sbom/{app,zephyr,build,modules-deps,sdk}.spdx` | `make sbom` | SPDX 2.3 tag-value | raw `west spdx` documents |
| `provenance.intoto.json`, `provenance.sigstore.json` | `make provenance` | in-toto Statement v1 + SLSA Provenance v1; Sigstore bundle | subjects = firmware files and SBOM documents with sha256 |
| `verify.json` | `make verify` | JSON | per check `{check, actual, ok}` |
| `normalized/firmware.spdx.json` | `make normalize` | SPDX 2.3 JSON | one package per component, CPE/PURL, root = firmware (PURL + sha256) |
| `findings.json` | `make scan` | JSON, schema `cra-evidence-demo/findings/v1` | `product`, `sbom` (sha256), `snapshot`, `tools`, `coverage`, `findings[]` |
| `queue.json` | `make queue` | JSON | open items: `state` new / draft / stale |
| `evidence/<file>.json` | `make evidence` | JSON | `sbom_listed`, `generated_into`, `kconfig`, `map_text_bytes`, `symbols`, `verdict`, `zephyr_elf_sha256` |
| `vex/firmware.openvex.json` (+ `.sigstore.json`) | `make vex` | OpenVEX 0.2.0 (schema pinned in `schema/vendor/`) | one statement per decision |
| `gate.json` | `make gate` | JSON, schema `cra-evidence-demo/gate/v1` | `result`, `evaluated_for`, `policy_sha256`, `rules[{rule, ok, detail, blocking[]}]` |
| `diff-<a>.json` (in release B) | `make diff` | JSON | firmware hashes, Kconfig changes, compiled sources added/removed, findings delta, decisions of A and triggers |

Committed inputs:

| File | Schema | Content |
| --- | --- | --- |
| `decisions/<release>/<board_dir>/<vuln>--<component>.yaml` | `schema/decision.schema.json` | one decision; see `docs/decisions.md` |
| `identifiers/component-map.yaml` | `identifiers/component-map.schema.json` | identifier additions, each evidence-bound and reviewable |
| `policy/gate.yaml` | (documented in `docs/gate.md`) | threshold and rules |
| `vulndb/snapshots.yaml` | (written by `make snapshot`) | DB archives: URL, sha256, build/record dates |
| `pins.env`, `requirements.lock` | - | every pinned version and checksum |

## Identity of a finding

`(vuln_id or alias, component PURL, product.version, product.firmware_sha256)`. The
component falls back to its name only when it has no PURL (gcc, identified by CPE).
This tuple is what `make queue`, `make vex` and `make gate` compare.
