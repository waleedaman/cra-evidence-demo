# VEX formats (Phase 6)

`make vex VERSION=v1.0 [SIGN=1]` writes `out/<v>/<board>/vex/firmware.openvex.json`
(OpenVEX v0.2.0). With `SIGN=1` it also writes `firmware.openvex.sigstore.json`, a cosign
bundle signed offline with `keys/cosign.key`, and verifies it with `keys/cosign.pub`.

## How the OpenVEX document is built

- **vexctl 0.4.4** builds it: `vexctl create` for the first decision, `vexctl add` for each
  further one. Our code only maps decision fields to vexctl flags.
- **Product:** the firmware PURL with the purl-spec `checksum` qualifier, e.g.
  `pkg:generic/cra-evidence-demo-firmware@1.0.0?checksum=sha256:3e9941d6...`. OpenVEX
  also has a `hashes` field, but vexctl has no flag for it. The qualifier carries the same
  binding inside the identifier.
- **Subcomponent:** the component PURL. For gcc, which has no PURL, it is the CPE.
- **Order and dates:** statements are ordered by `decided_at`. Each vexctl call runs with
  `SOURCE_DATE_EPOCH=decided_at`, so the same decisions give a byte-identical document
  (checked).
- **Status notes:** `status_notes` carries the reviewer, the evidence list and the reassess
  trigger. OpenVEX has no evidence field.
- **Checks:** the result is validated against the OpenVEX JSON schema and read back with
  `vexctl merge`. The schema comes from openvex/spec at a pinned commit, is vendored in
  `schema/vendor/`, pinned in `pins.env` and checked by `make doctor`. vexctl 0.4.4 has no
  validate command.

| Decision field | OpenVEX statement field |
| --- | --- |
| `vuln_id`, `aliases` | `vulnerability.name`, `vulnerability.aliases` |
| `product.purl` + `product.firmware_sha256` | `products[].@id` (PURL with `checksum` qualifier) |
| `component_purl` / `component_cpe` | `products[].subcomponents[].@id` |
| `status` | `status` |
| `justification` | `justification` |
| `impact_statement` | `impact_statement` |
| `action_statement` | `action_statement` (+ `action_statement_timestamp`) |
| `decided_at` | `timestamp` |
| `reviewer`, `evidence`, `reassess_trigger`, `due_date` | `status_notes` (free text) |

## Can a scanner consume it? (Grype 0.120.1: not for our case)

`grype sbom:firmware.spdx.json --vex firmware.openvex.json` does **not** suppress the
matching findings. We checked the Grype source (`grype/vex/openvex/implementation.go`):

- For an SBOM input, Grype only takes the VEX product to be
  `pkg:generic/<source name>@<source version>`, and an SPDX source has no version. As a
  fallback it treats the matched package's own PURL as the product.
- A statement "the firmware is not affected through its zephyr subcomponent" therefore
  never matches. Only "the zephyr package itself is not affected" would, and that is a
  different claim: not true in general, only for this build.
- CPE subcomponents are not compared at all (a TODO in the source), so the gcc statement
  could not match either way.

The demo therefore does not rely on scanner-side VEX filtering. The decisions are checked
directly by `make queue` and by the gate in Phase 7. The OpenVEX file is the published
statement for customers and authorities.

## Mapping to CSAF VEX

The same decisions map to a CSAF 2.0 document with the `csaf_vex` profile. We do not build
a CSAF exporter. A CSAF document needs publisher and tracking metadata (publisher, IDs,
revision history) that belongs to a real PSIRT process, not to a demo.

| Decision | CSAF 2.0 (`csaf_vex`) |
| --- | --- |
| product (name, version, PURL, firmware SHA-256) | `product_tree`: a branch for vendor/product/version, `product.product_identification_helper` with `purl` and `hashes` (`file_hashes` sha256 + filename) |
| component (PURL/CPE) | its own `product_tree` entry; `relationships` with category `default_component_of` links component and firmware into one product ID |
| `vuln_id`, `aliases` | `vulnerabilities[].cve` (other IDs in `ids`) |
| `status: not_affected` | `product_status.known_not_affected` |
| `status: affected` | `product_status.known_affected` |
| `status: fixed` | `product_status.fixed` |
| `status: under_investigation` | `product_status.under_investigation` |
| `justification` | `flags[].label`: the five OpenVEX justifications have the same names as the CSAF flag labels |
| `impact_statement` | `threats[]` with `category: impact` |
| `action_statement` | `remediations[]` (`vendor_fix`, `mitigation`, `workaround`, `no_fix_planned`, `none_available`) |
| `due_date` | no direct field; a `notes[]` entry |
| `evidence`, `reviewer`, `reassess_trigger` | `notes[]`, `references[]`; who decided is not modelled per statement |
| `decided_at` | `document.tracking` revision history / `flags[].date` |

Not verified here: the exact CSAF 2.0 section numbers and whether a CSAF 2.1 profile
changes any of these field names. Check against the OASIS CSAF specification before using
this table as a reference.
