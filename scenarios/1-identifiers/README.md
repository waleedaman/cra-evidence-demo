# Scenario 1: ambiguous identifiers

**Claim:** a library copied into the source tree is invisible to every scanner until a
person identifies it. Scanners match identifiers, not code.

**Setup:** cJSON 1.7.17 is vendored in `app/lib/cjson/` (real upstream files; see its
README). `west spdx` lists `./lib/cjson/cJSON.c` as an application file. The scenario
first normalizes with a copy of `identifiers/component-map.yaml` without the `cjson` entry.

| Step | Expected |
| --- | --- |
| normalize (map without cjson) | 8 components, gap line: `./lib/cjson/cJSON.c` not attributed |
| scan | 29 findings, no cjson row |
| map-entry cjson | version 1.7.17, file hashes, 2 CPEs (`cjson_project`, `davegamble`), 1 PURL |
| normalize + scan | 9 components; cjson: Grype 6, OSV 8; 37 findings |
| queue | 8 new cJSON items, CVE-2025-57052 **Critical** on top |
| evidence cJSON_Utils.c | not compiled: the vulnerable file is not vendored |
| decision | CVE-2025-57052 not_affected / vulnerable_code_not_present (signed v1.0 decision) |

**Talking points:** the Critical finding was there all along, and it does not apply. You
only know both after identifying the component. Both CPE vendors are needed: NVD files
cJSON under `davegamble` and `cjson_project`. The map entry is evidence-bound: if
`cJSON.c` changes, its sha256 no longer matches and `make normalize` stops.

**Alternatives considered:** a vendored copy of an older mbedTLS (too heavy for the
board), lwIP (not used by Zephyr), a header-only library (no linker evidence).
