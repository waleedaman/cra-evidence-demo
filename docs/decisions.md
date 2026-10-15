# Decisions (Phase 6)

A decision is a person's judgement about one finding (one vulnerability in one component)
for one firmware build. Scanners produce findings; only decisions produce VEX statements
and, in Phase 7, a release.

```bash
make decide VERSION=v1.0 VULN=CVE-2023-4039        # draft one decision from the finding
make decide VERSION=v1.0 VULN=open                 # draft every open finding without a file
#   ... edit the YAML file(s) ...
make queue  VERSION=v1.0                           # drafts show as "draft" until complete
make vex    VERSION=v1.0 [SIGN=1]                  # OpenVEX from the complete decisions
```

## Where decisions live

`decisions/<release>/<board>/<vuln_id>--<component>.yaml`, for example
`decisions/v1.0/w5500_evb_pico2_rp2350a_m33/CVE-2023-4039--gcc.yaml`.

The original plan was `decisions/<version>/<vuln-id>.yaml`. That cannot hold the same CVE
for two boards (each board is its own firmware with its own SHA-256) or one CVE in two
components. Decisions are committed to git: the history is the audit trail.

## Data model

Validated by `schema/decision.schema.json` (JSON Schema 2020-12).

| Field | Required | Content |
| --- | --- | --- |
| `vuln_id`, `aliases` | yes / no | CVE (or GHSA, OSV, `DEMO-` for synthetic data) and other IDs |
| `component` | yes | component name in the normalized SBOM |
| `component_purl` or `component_cpe` | one of them | how the component is identified; CPE only when it has no PURL (gcc) |
| `product` | yes | `name`, `version` (SBOM version, `1.0.0`), `board`, `purl`, `firmware_file`, `firmware_sha256` |
| `status` | yes | `not_affected`, `affected`, `fixed`, `under_investigation` (OpenVEX) |
| `justification` | for `not_affected` | OpenVEX value: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist` |
| `impact_statement` | for `not_affected` | why this firmware is not affected, in words |
| `action_statement` | for `affected` | what is done or what users must do |
| `due_date` | for `under_investigation` | when the investigation must be finished |
| `evidence` | yes, at least one | list of `{type, path_or_url, description}`; types: `scanner-report`, `advisory`, `sbom`, `config`, `linker-map`, `symbols`, `source`, `commit`, `test`, `analysis`, `other` |
| `reviewer` | yes | the responsible person, never a tool or an AI |
| `decided_at` | yes | UTC timestamp |
| `reassess_trigger` | yes | what would make the decision wrong (e.g. "CONFIG_IEEE802154 enabled") |
| `exception` | no | approved exception to ship an `affected` finding above the gate threshold: `approved_by`, `approved_at`, `expires`, `reason` |
| `finding` | no | context copied from the scan; ignored by every check |

`under_investigation` requires a due date in the schema because the gate (Phase 7) allows it
only below a severity threshold and only until that date.

## Binding to the firmware

A decision covers a finding only if `vuln_id` (or an alias), the component and
`product.version` + `product.firmware_sha256` all match the current build. Rebuild the
firmware with any change and every decision becomes **stale**: `make queue` shows it as
stale, `make vex` refuses to build. That is deliberate (scenario 4): a justification such
as "the vulnerable code is not compiled" is a statement about one binary.

## What `make decide` fills in, and what it does not

It copies facts: IDs, component and product binding, the scanner's match (for example
"Grype matched gcc 14.3.0 against `< 2023-09-12`"), the cross-check against OSV, and the
advisory links. It leaves every judgement empty: `status` stays `under_investigation`
without a due date, `reviewer` and `decided_at` are empty. Such a file fails the schema on
purpose, so an unfinished draft can never end up in a VEX document.

The scanner report is pre-filled as evidence, but scanner output alone never counts as a
decision: the Phase 7 gate requires at least one other evidence item.

## Checks

- `make queue`: a decision file for this firmware that fails the schema is listed as
  `draft`, with what is missing ("to complete: decided_at, due_date, reviewer, ...").
- `make vex`: builds nothing if any decision file of the release and board is a draft or
  bound to another firmware.
