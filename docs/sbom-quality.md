# SBOM validation and normalization (Phase 4)

```bash
make validate  VERSION=v1.0 [BOARD=...]   # check every SPDX document of a build
make normalize VERSION=v1.0 [BOARD=...]   # one component SBOM: normalized/firmware.spdx.json
make validate  VERSION=v1.0 [BOARD=...]   # again: now includes the normalized document
```

Both run offline in the tooling image. Raw reports: `out/<v>/<board>/validate/*.json`
and `out/<v>/<board>/normalized/report.json`.

## What `make validate` checks

| Column | Tool | Meaning |
| --- | --- | --- |
| SPDX | spdx-tools 0.8.5 `validate_full_spdx_document` | the document is valid SPDX 2.3 |
| NTIA minimum elements | ntia-conformance-checker 6.0.0, `ntia` | name, version, supplier, identifier per component; author, timestamp, a `DESCRIBES` relationship |
| FSCT3 | ntia-conformance-checker 6.0.0, `fsct3-min` | CISA *Framing Software Component Transparency* (2024) minimum: NTIA + concluded license + copyright + SBOM type |
| CPE/PURL | our own count | components that carry at least one CPE or PURL |

Why the extra CPE/PURL column: the NTIA checker accepts the SPDX ID as the component
"identifier" (`spdx2_adapter.py`), so every SPDX package passes that element. A scanner
cannot match an SPDX ID against any vulnerability database.

Exit code: 1 if any document is not valid SPDX, or if the normalized document fails NTIA.
NTIA/FSCT3 gaps in the raw `west spdx` documents are expected and only reported.

### Not checked: BSI TR-03183-2

ntia-conformance-checker 6.0.0 has a `bsi` mode, but every document-level BSI check in
`bsi_checker.py` requires an SPDX 3 document; on SPDX 2.x it silently evaluates nothing.
`west spdx` (Zephyr v4.4.2) writes only SPDX 2.2/2.3, so we do not report a BSI result.
Not verified: which SBOM format versions TR-03183-2 v2.1.0 itself accepts (the PDF was
not reachable from this environment). Check section "formats" of the TR before quoting it.

FSCT3's "SBOM type" element exists only in SPDX 3, so no SPDX 2.3 document can pass FSCT3.

## Findings in the raw `west spdx` output

Measured on the presenter machine's v1.0 builds (2026-10-15).

| Document | w5500_evb_pico2 | native_sim |
| --- | --- | --- |
| `app.spdx` | NTIA fail: version, supplier | same |
| `zephyr.spdx` | NTIA fail: supplier missing for 4 of 5 trees | same |
| `build.spdx` | valid; 57 targets checked, 37 not reachable from the root | **invalid SPDX**: no `DESCRIBES` relationship |
| `modules-deps.spdx` | NTIA "PASS", but only 1 of 5 packages is checked | same |
| `sdk.spdx` | NTIA fail: version, supplier | same |

- **native_sim `build.spdx` is not valid SPDX.** `west spdx` always writes
  `DESCRIBES` for the CMake target `zephyr_final` (`zspdx/walker.py`). native_sim has no
  such target: `zephyr.exe` is linked by the custom target `native_runner_executable`,
  which runs the native simulator's own Makefile. So the document has 83 packages and no
  `DESCRIBES` relationship, and `zephyr.exe`, the file that actually runs, appears in no
  SBOM document.
- **"PASS" can mean "checked almost nothing".** In `modules-deps.spdx` the modules are
  linked to Zephyr with `DEPENDENCY_OF`, which the checker does not follow
  (`constants.py`), so 4 of 5 packages are skipped and the document passes. `validate`
  prints how many packages were not reachable.
- **Toolchain code is invisible.** The board firmware statically links `libc.a` (picolibc)
  and `libgcc.a` from the Zephyr SDK. `sdk.spdx` has one unversioned `sdk` package with 46
  headers and nothing about the libraries.

### spdx-tools takes 53 s for `zephyr.spdx`

Parsing the 348 KB tag-value `zephyr.spdx` took 53 s, while the 895 KB `build.spdx` took
1 s. Profiling showed the time in `p_license` in the tag-value parser: it calls
`license_expression.get_spdx_licensing()` for every license expression (~2 000 here), and
each call reloads the full license index (~27 ms). The JSON and RDF parsers use one shared
instance (`spdx_tools.common.spdx_licensing`). spdx-tools 0.8.5 is the latest release on
PyPI (checked 2026-10-15).

`pipeline/spdxio.py` points the tag-value parser at that shared instance. Result:
0.6 s instead of 53 s. Checked: the parsed `zephyr.spdx` converted to JSON is
byte-identical with and without the workaround, and validation gives the same (empty)
message list. All checks for one board now take about 4 s.

## What `make normalize` produces

`out/<v>/<board>/normalized/firmware.spdx.json`: SPDX 2.3 JSON with one root package for
the firmware and one package per component that is actually in the build:

| Component | From | Identifiers |
| --- | --- | --- |
| firmware (root) | `app.spdx` + map `product` | generic PURL; SHA-256 + SHA-512 of `zephyr.uf2` (`zephyr.exe` on native_sim) |
| zephyr | `zephyr.spdx` + `modules-deps.spdx` | CPE + PURL from `west spdx` |
| mbedtls, tf-psa-crypto | same + map | module.yml CPE/PURL **plus** the other NVD CPE names |
| cmsis_6, hal_rpi_pico | same + map | supplier + PURL of the fork commit; no CPE exists |
| picolibc, gcc | map only, when their evidence is in the build | picolibc: PURL; gcc: CPE |

Rules:

- A source tree with 0 files in this build is dropped (native_sim: cmsis_6, hal_rpi_pico).
  The raw SBOM lists them anyway, and a scanner would report their CVEs for a build that
  does not contain them.
- The CMake targets of `build.spdx` are build steps, not components, and are not copied.
  The raw documents stay in `sbom/` and are referenced from the normalized document by
  SHA-1 (`ExternalDocumentRef`, as SPDX 2.3 requires), so every claim can be traced back.
- Root `STATIC_LINK` component for every component.
- Every change made from the map is written into the SBOM as an SPDX annotation with
  rationale, evidence, author, date and review state.
- Deterministic: same inputs + same map give a byte-identical file (`Created` is taken
  from the raw documents, the namespace contains a hash of all inputs).
- A failed run deletes the previous `firmware.spdx.json`, so a later step cannot pick up
  a stale SBOM.

What is still missing is printed as `gap:` lines, for example on native_sim the host
C library and the host `libgcc.a`. native_sim is a simulator target and these come from
the ci-base image; we report them instead of guessing versions.

## identifiers/component-map.yaml

The map is the only place where a human (or an AI that drafts for a human) adds
identifiers. Validated against `identifiers/component-map.schema.json` before use.

Every entry carries: `version` it was written for, `rationale`, `evidence`, `added_by`,
`added_on`, `reviewed_by`, `reviewed_on`.

Safety rules in `normalize.py`:

- **Version-bound.** If the build's version of the component differs from `version`,
  normalize stops: a module update needs a new review. Tested by changing the mbedtls
  entry to 4.0.0.
- **Evidence-bound.** Toolchain entries apply only if their linked archive and SDK files
  are in this build, and pinned file hashes match (picolibc: `picolibc.h`, which states
  the version). If the toolchain is used but the evidence no longer matches, normalize
  stops. Tested by changing one hash digit.
- **Review is visible.** Entries with empty `reviewed_by` are counted on every run and
  marked "NOT reviewed by a person yet" in the SBOM annotations.

### The CPE split (talk material)

NVD files vulnerabilities for the same product under different CPE vendor:product names.
Counted in the grype DB snapshot "baseline" (built 2026-10-15) by querying its
`cpes` / `affected_cpe_handles` tables:

| CPE vendor:product | CVEs | |
| --- | --- | --- |
| `arm:mbed_tls` (module.yml) | 58 | |
| `trustedfirmware:mbed_tls` | 31 | |
| `mbed-tls:mbedtls` | 14 | 73 distinct; 15 not under `arm:mbed_tls` |
| `arm:tf-psa-crypto` (module.yml) | 2 | |
| `trustedfirmware:tf-psa-crypto` | 3 | no overlap with the line above |

A CPE-based scan with only the module.yml identifiers can never report those 15 + 3
CVEs. These are database counts, not findings for this firmware; matching against the
actual versions happens in Phase 5.

Not mapped on purpose: picolibc is derived from newlib, which has CVEs under
`newlib_project:newlib`. Whether any applies to picolibc 1.8.10 is a human decision,
not an identifier mapping.

## Before and after (w5500_evb_pico2, v1.0)

| | raw `west spdx` (5 documents) | `firmware.spdx.json` |
| --- | --- | --- |
| valid SPDX | 5 of 5 (native_sim: 4 of 5) | yes |
| NTIA minimum elements | 1 of 5 documents pass (checking 1 package) | PASS, 8 of 8 components |
| components with CPE or PURL | zephyr, mbedtls, tf-psa-crypto (ids in a separate document) | 8 of 8 |
| C library / compiler runtime | not listed | picolibc 1.8.10, gcc 14.3.0 |
| FSCT3 | fail | fail: concluded license unknown for picolibc/gcc, no copyright texts, SBOM type (SPDX 3 only) |
