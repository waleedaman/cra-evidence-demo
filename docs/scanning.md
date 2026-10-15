# Vulnerability matching and review queue (Phase 5)

```bash
make scan  VERSION=v1.0 [BOARD=...] [SNAPSHOT=baseline]
make queue VERSION=v1.0 [BOARD=...] [ROWS=15]
```

Both run offline (`--network none`) against a frozen snapshot from `vulndb/snapshots.yaml`.
`make scan` refuses to run if the Grype DB in the cache was not built at the recorded time
or the OSV archive's sha256 differs from the recorded one.

| File | Content |
| --- | --- |
| `out/<v>/<board>/scan/<snapshot>/grype.json` | raw Grype report |
| `out/<v>/<board>/scan/<snapshot>/osv-scanner-custom.json` | what we asked OSV-Scanner |
| `out/<v>/<board>/scan/<snapshot>/osv.json`, `osv.log` | raw OSV-Scanner report and log |
| `out/<v>/<board>/findings.json` | merged findings of the latest scan (copy per snapshot in `scan/<snapshot>/`) |
| `out/<v>/<board>/queue.json` | open review items |

Every `findings.json` records the product (version, firmware file and SHA-256), the SBOM's
SHA-256, the tool versions, and the snapshot: name, Grype DB build time and archive
sha256, OSV record time and archive sha256.

## Grype

`grype -c config/grype.yaml sbom:normalized/firmware.spdx.json -o json`. Grype reads the
SPDX JSON directly and matches every CPE of a package against NVD data.

Checked: Grype uses **all** CPEs of a package. With the same SBOM but mbedtls set to
3.6.0, Grype reports 25 CVEs: 16 via `arm:mbed_tls` and 9 only via
`trustedfirmware:mbed_tls`, the CPE added by `identifiers/component-map.yaml`. With
Mbed TLS 4.1.0 (our build) no CPE matches anything in the baseline snapshot.

## OSV-Scanner: what works offline for C code

Checked in the OSV-Scanner 2.7.0 source and its matching library osv-scalibr:

1. **Our PURLs land in the wrong ecosystem.** OSV-Scanner reads the SPDX file, but maps
   `pkg:github/...` PURLs to the ecosystem *GitHub Actions* (CI workflow actions). Offline it
   then fails, because no GitHub Actions database exists, and online it would query the wrong
   data.
2. **Commit-only queries are skipped offline.** `enricher/vulnmatch/osvlocal/matcher.go`:
   "Commit-only query with no version tag; commit graph reachability requires online OSV
   API." That is why `cmsis_6` and `hal_rpi_pico` (built from fork commits, no release tag)
   cannot be checked offline.
3. **Repository + release tag works offline.** For the `GIT` ecosystem the local matcher
   compares the repository URL with the OSV record's range and the tag with the record's
   list of affected versions (`internal/vulns/vulnerability.go`, `IsAffected`).

So `pipeline/scan.py` turns each component's `pkg:github/<owner>/<repo>@<tag>` into
"`https://github.com/<owner>/<repo>` at `<tag>`", writes them in OSV-Scanner's own input
format and runs `osv-scanner scan source --offline -L osv-scanner:<file>`. OSV-Scanner
does the matching; we only choose the query. The repository URL is queried as written and
in lower case, because OSV records use both spellings (`Mbed-TLS/mbedtls` and
`mbed-tls/mbedtls`) and the matcher compares exactly.

**Cache layout.** OSV-Scanner 2.7.0 reads offline databases from
`<OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY>/osv-scalibr/<ecosystem>/all.zip`. Phase 0
assumed the older `osv-scanner/` sub-directory, which is how our archives are stored.
`make scan` links the verified archive into the layout OSV-Scanner reads. Loading the
200 MB GIT database takes about 20 s.

## Results: v1.0, baseline snapshot (built/recorded 2026-10-15)

| Component | Grype input | Grype | OSV-Scanner input | OSV |
| --- | --- | --- | --- | --- |
| zephyr 4.4.2 | 1 CPE | 26 | repo@v4.4.2 | 2 |
| mbedtls 4.1.0 | 3 CPE | 0 | repo@v4.1.0 | 0 |
| tf-psa-crypto 1.1.0 | 2 CPE | 0 | repo@v1.1.0 | 0 |
| gcc 14.3.0 (board) | 1 CPE | 1 | no GitHub PURL | - |
| picolibc 1.8.10 (board) | no CPE | - | repo@1.8.10 | 0 |
| cmsis_6, hal_rpi_pico (board) | no CPE | - | commit only | - |

Board: 29 findings (27 Grype only, 2 OSV-Scanner only, 0 found by both).
native_sim: 28 (no gcc component, see `docs/sbom-quality.md`).

### The two databases disagree, in both directions

- **24 of the 26 Zephyr findings from Grype** have an OSV record that does *not* list
  v4.4.2. NVD's CPE data says "affected below 4.5.0" for all of them. The OSV records,
  built from the CVE record's own data and the Zephyr git history, say fixed in v4.4.0,
  v4.4.1 or v4.4.2. Example: CVE-2026-10686, NVD `>= 1.8.0, < 4.5.0`, OSV fixed in v4.4.1.
  2 Zephyr findings have no OSV record at all.
- **2 findings only OSV-Scanner reports:** CVE-2026-75084 and CVE-2026-75085, published
  2026-10-14, the day before the snapshot. The grype DB has the NVD records, but without
  CPE configuration yet (`grype db search --vuln CVE-2026-75084` lists no affected
  package), so no CPE-based scanner can match them. CVE-2026-75084 is in the TI CC1200
  radio driver, which this firmware does not build.
- **gcc CVE-2023-4039** is a matching artifact: the NVD range is `< 2023-09-12`, a date
  instead of a version, and Grype compares `14.3.0` against it with an unknown version
  format. The issue also concerns AArch64 stack protection; this firmware is Arm
  Cortex-M33 (Thumb).

None of this is decided automatically. The scanners produce candidates, the review
queue lists them, and Phase 6 records a human decision with evidence for each.

## Review queue

`make queue` lists every finding that has no decision for **this** firmware:
a decision file under `decisions/` counts only if its `vuln_id` (or an alias), its
`component_purl` (component name when the component has no PURL, e.g. gcc), its
`product.version` (the SBOM version, `1.0.0`) and its `product.firmware_sha256` all match.
A decision for the same vulnerability but another version or firmware hash is shown as
**stale**, not as decided. Unreadable decision files are reported, not skipped silently.

Columns: severity (Grype/NVD; for OSV-only findings the CVSS v3 rating of OSV-Scanner's
`max_severity`), which scanner found it, and a cross-check: "OSV: not this version",
"OSV: no record", "Grype: no match", or "OSV: cannot check" (no GitHub PURL with a tag).

The decision data model and its JSON Schema come in Phase 6; the queue already uses the
fields defined for it: `vuln_id`, `component_purl`, `product.version`,
`product.firmware_sha256`.
