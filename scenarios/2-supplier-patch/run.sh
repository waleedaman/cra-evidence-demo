#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Scenario 2: supplier patch. The fix for CVE-2024-31755 is backported into the vendored
# cJSON, the version stays 1.7.17, every database keeps reporting the CVE. See README.md.
SCENARIO=2
source "$(dirname "$0")/../lib.sh"
PATCH=app/lib/cjson/patches/0001-Add-NULL-check-to-cJSON_SetValuestring.patch

title "Supplier patch: fixed, but the version says otherwise" \
      "Firmware v1.0, ${BOARD}. cJSON 1.7.17 with one upstream fix backported."
setup v1.0

step "Both scanners report CVE-2024-31755 for cJSON 1.7.17" \
     "make finding VERSION=v1.0 VULN=CVE-2024-31755" -- smake finding VERSION=v1.0 VULN=CVE-2024-31755
step "We ship 1.7.17 plus this upstream commit" \
     "cat ${PATCH}" -- helper show-file --path "${PATCH}" --start 1 --end 26
step "Proof, not a claim: the same test against upstream 1.7.17 and our copy" \
     "make cjson-test" -- ${MAKE_CMD} --no-print-directory -s cjson-test
step "The decision: status fixed, the evidence is the patch, the commit and the test" \
     "make decision VERSION=v1.0 VULN=CVE-2024-31755" -- smake decision VERSION=v1.0 VULN=CVE-2024-31755
step "Tell the customer in a machine-readable way: OpenVEX, signed" \
     "make vex VERSION=v1.0 SIGN=1" -- smake vex VERSION=v1.0 SIGN=1
step "The statement for CVE-2024-31755" \
     "make vex-statement VERSION=v1.0 VULN=CVE-2024-31755" -- smake vex-statement VERSION=v1.0 VULN=CVE-2024-31755
say "The scanners will report this CVE as long as the version is 1.7.17. The VEX travels with the firmware."
done_msg
