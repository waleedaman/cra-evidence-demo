#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Scenario 1: ambiguous identifiers. A library copied into the application tree (cJSON
# 1.7.17 in app/lib/cjson) has no package metadata: the SBOM lists its files as part of
# the application and no scanner sees it. See README.md in this folder.
SCENARIO=1
source "$(dirname "$0")/../lib.sh"

title "Ambiguous identifiers: the vendored library nobody scans" \
      "Firmware v1.0, ${BOARD}. Same build, same scanners, two identifier maps."
setup v1.0

step "SBOM without an identifier for cJSON: what does the normalized SBOM contain?" \
     "make normalize VERSION=v1.0 MAP=<map without cjson>" -- \
     smake normalize VERSION=v1.0 MAP="${SC}/map-before.yaml"
step "Scan it. Look for cJSON." \
     "make scan VERSION=v1.0" -- smake scan VERSION=v1.0
say "No component 'cjson', so no cJSON findings. The library is in the firmware all the same."
step "The fix is data, not code: one reviewed entry in the identifier map" \
     "make map-entry ID=cjson" -- smake map-entry ID=cjson
step "Normalize again, with the entry" \
     "make normalize VERSION=v1.0" -- smake normalize VERSION=v1.0
step "Scan again" "make scan VERSION=v1.0" -- smake scan VERSION=v1.0
step "The most severe open item is now a Critical cJSON finding" \
     "make queue VERSION=v1.0 ROWS=6" -- smake queue VERSION=v1.0 ROWS=6
step "Is the vulnerable code (cJSON_Utils.c) in this firmware?" \
     "make evidence VERSION=v1.0 FILE=lib/cjson/cJSON_Utils.c" -- \
     smake evidence VERSION=v1.0 FILE=lib/cjson/cJSON_Utils.c
step "The decision a person signed for v1.0, with that evidence" \
     "make decision VERSION=v1.0 VULN=CVE-2025-57052" -- \
     ${MAKE_CMD} --no-print-directory -s decision VERSION=v1.0 VULN=CVE-2025-57052 BOARD="${BOARD}"
done_msg
