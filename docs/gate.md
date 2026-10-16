# Release gate (Phase 7)

```bash
make gate VERSION=v1.0 [BOARD=...] [GATE_DATE=2026-11-10] [POLICY=policy/gate.yaml]
make pipeline VERSION=v1.0          # build, sbom, provenance, normalize, scan, vex SIGN=1, gate
```

The gate answers one question for one firmware build: may it be released (or stay
released)? It reads only what the earlier steps wrote and checks them against each other;
it scans nothing itself. Policy: `policy/gate.yaml`. Result: a PASS/FAIL table, the
blocking items, and `out/<v>/<board>/gate.json`. Exit code 1 on FAIL.

| Rule | Passes when | Typical failure |
| --- | --- | --- |
| R1 SBOM valid | the normalized SBOM parses, is valid SPDX 2.3 and meets the NTIA minimum elements | a broken map entry |
| R2 Provenance | `make verify` checks all pass: cosign signature, artifact and SBOM digests, pins, clean tree | rebuilt from uncommitted changes |
| R3 Findings current | `findings.json` was made for this firmware hash and this SBOM, from a snapshot not older than `max_snapshot_age_days` (60) | scan older than the last rebuild |
| R4 Every finding decided | every finding has a valid decision bound to this release and firmware hash | new finding (scenario 5), rebuilt firmware (scenario 4) |
| R5 Decision quality | reviewer is a person (name not matching the tool/AI pattern), evidence includes more than `scanner-report` | "reviewer: Claude", only the scanner output as evidence |
| R6 No unaccepted affected | no `affected` decision at or above the threshold without an approved, unexpired `exception` | exception expired |
| R7 Investigations | `under_investigation` only below the threshold, and only until `due_date` | a High still under investigation; due date passed |
| R8 VEX current | `vex/firmware.openvex.json` has one statement per decision, for this firmware, and its cosign signature verifies | decisions changed after `make vex` |

Severity threshold: `High` (Critical and High block). Severity comes from the finding
(Grype/NVD, or the CVSS v3 rating of OSV for OSV-only findings).

## Dates

`GATE_DATE=YYYY-MM-DD` evaluates due dates, exception expiry and snapshot age as of that
date. Use it to rehearse the talk day: `make gate VERSION=v1.0 GATE_DATE=2026-11-12`.
Default: today (UTC).

## What the gate cannot know

- Whether a decision is *right*. R5 checks that a person signed it and that it rests on
  more than scanner output. The content is reviewed by people: decisions are committed to
  git, the history is the audit trail.
- The reviewer check is a name pattern. Anyone can type any name. The real control is
  code review of `decisions/` (CODEOWNERS, signed commits); see `docs/ci-checklist.md`.
- Components that are not in the SBOM (scenario 1). R1 checks the SBOM is well-formed, not
  that it is complete; the normalizer prints unattributed files as a gap instead.
