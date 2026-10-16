# cJSON (vendored)

| | |
| --- | --- |
| Upstream | https://github.com/DaveGamble/cJSON |
| Version | 1.7.17 (tag `v1.7.17`, commit `87d8f0961a01bf09bef98ff89bae9fdec42181ee`) |
| Files | `cJSON.c`, `cJSON.h`, `LICENSE` (MIT), copied unchanged from the tag |
| Local patches | `patches/0001-Add-NULL-check-to-cJSON_SetValuestring.patch` = upstream commit `7e4d5dabe7a9b754c601f214e65b544e67ba9f59` (fix for CVE-2024-31755), applied to `cJSON.c` |
| Version string | still reports 1.7.17 (`CJSON_VERSION_PATCH 17`) |

Used by the application to build the MQTT JSON payload.

This directory is the starting point of two talk scenarios:

- **Scenario 1 (ambiguous identifiers):** a library copied into the application tree has
  no package metadata. `west spdx` lists these files as part of the application, so no
  scanner sees "cJSON 1.7.17".
- **Scenario 2 (supplier patch):** the fix for CVE-2024-31755 is backported, but the version
  stays 1.7.17, so every public database still reports the CVE.

sha256 of the files as copied from the tag (before the patch):
`cJSON.c` de63e951ce3bc9b6938c7635575a6c90c3b364595b0b0f4c5ae8f9c83a43c17d,
`cJSON.h` c01a8ca5609bb2c956dd1ae836d5d926ec68153ecebc5a75ea0febc2e076da8d.
