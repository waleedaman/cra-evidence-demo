#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Scenario 5: a new advisory after the release. The archived v1.0 SBOM is scanned again
# with a newer DB snapshot ("after", recorded before the talk) or, if none was recorded,
# with the baseline plus ONE SYNTHETIC record (DEMO-2026-0001, docs/synthetic-data.md).
SCENARIO=5
source "$(dirname "$0")/../lib.sh"
OUT="${SC}/v1.0/${BD}"
HERE=scenarios/5-new-cve

if grep -qE '^  after:' vulndb/snapshots.yaml; then
  DB=(SNAPSHOT=after); DB_TEXT="snapshot 'after'"
else
  DB=(SNAPSHOT=baseline OSV_EXTRA="${HERE}/DEMO-2026-0001.osv.json")
  DB_TEXT="baseline + SYNTHETIC record DEMO-2026-0001"
fi
if [[ -z "${REVIEWER:-}" ]]; then
  read -r -p "Your name (the person who opens the investigation): " REVIEWER
  export REVIEWER
fi

title "New advisory after the release" \
      "Released firmware v1.0, ${BOARD}. Rescan with: ${DB_TEXT}"
setup v1.0

step "v1.0 as released: every finding decided, VEX signed" \
     "make gate VERSION=v1.0" -- smake gate VERSION=v1.0 SOFT=1
step "Weeks later: the SAME archived SBOM, a newer vulnerability database" \
     "make scan VERSION=v1.0 ${DB[*]}" -- smake scan VERSION=v1.0 "${DB[@]}"
step "One new item, for firmware that is already in the field" \
     "make queue VERSION=v1.0" -- smake queue VERSION=v1.0 ROWS=5
step "The gate for the released firmware fails now" \
     "make gate VERSION=v1.0" -- smake gate VERSION=v1.0 SOFT=1
step "Open an investigation: under_investigation with a due date, in your name" \
     "make triage VERSION=v1.0 DAYS=14 REVIEWER=\"${REVIEWER}\"" -- smake triage VERSION=v1.0 DAYS=14
step "Customers learn about it from the updated, signed VEX" \
     "make vex VERSION=v1.0 SIGN=1" -- smake vex VERSION=v1.0 SIGN=1
step "Gate again" "make gate VERSION=v1.0" -- smake gate VERSION=v1.0 SOFT=1
say "Below the threshold an investigation may stay open until its due date; at or above it, the gate keeps failing until the decision is made."
done_msg
