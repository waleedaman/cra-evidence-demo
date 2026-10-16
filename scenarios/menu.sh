#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# make demo: presenter menu. Each entry is one make target; see scenarios/README.md.
set -uo pipefail
B=$'\e[1m'; R=$'\e[0m'; CY=$'\e[1;36m'
MAKE_CMD=${MAKE_CMD:-make}
items=(
  "scenario-1|Ambiguous identifiers: vendored cJSON nobody scans"
  "scenario-2|Supplier patch: fixed, but still version 1.7.17"
  "scenario-3|Configuration: ICMPv6 CVE, IPv6 not compiled"
  "scenario-4|Config change: v1.1 enables IPv6"
  "scenario-5|New advisory after release"
  "ready|Readiness check"
  "reset|Delete scenario workspaces"
)
while true; do
  clear 2>/dev/null || true
  printf '%s\n\n' "${CY}From firmware build to CRA evidence: demo menu${R}"
  for i in "${!items[@]}"; do
    printf '  %s  %s\n' "${B}$((i + 1))${R}" "${items[$i]#*|}"
  done
  printf '\n  %s  quit\n\n' "${B}q${R}"
  read -r -p "> " choice || exit 0
  [[ "${choice}" == "q" ]] && exit 0
  if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#items[@]} )); then
    target=${items[$((choice - 1))]%%|*}
    ${MAKE_CMD} --no-print-directory "${target}"
    read -r -p $'\n(Enter: back to the menu) ' _ || exit 0
  fi
done
