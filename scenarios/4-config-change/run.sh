#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Scenario 4: a configuration change invalidates earlier decisions. Release v1.1 enables
# IPv6 (releases/v1.1/release.conf). Same components, same scanner findings, different truth.
SCENARIO=4
source "$(dirname "$0")/../lib.sh"

title "Configuration change: v1.1 enables IPv6" \
      "Releases v1.0 and v1.1, ${BOARD}. releases/v1.1/release.conf: CONFIG_NET_IPV6=y"
setup v1.0,v1.1

step "The only source change of v1.1" "cat releases/v1.1/release.conf" -- \
     helper show-file --path releases/v1.1/release.conf
step "What changed between the two builds, and which v1.0 decisions it hits" \
     "make diff A=v1.0 B=v1.1" -- smake diff A=v1.0 B=v1.1
step "Release gate for v1.1" "make gate VERSION=v1.1" -- smake gate VERSION=v1.1 SOFT=1 GATE_ROWS=4
step "Start from the v1.0 decisions: carried forward, every one needs a new review" \
     "make decide VERSION=v1.1 VULN=open FROM=v1.0" -- \
     smake decide VERSION=v1.1 VULN=open FROM=v1.0
step "Redo the analysis for CVE-2026-10638: the file is now compiled" \
     "make evidence VERSION=v1.1 FILE=subsys/net/ip/icmpv6.c SYMBOL=net_icmpv6_send_error KCONFIG=CONFIG_NET_IPV6" -- \
     smake evidence VERSION=v1.1 FILE=subsys/net/ip/icmpv6.c SYMBOL=net_icmpv6_send_error KCONFIG=CONFIG_NET_IPV6
say "v1.0's 'not compiled' is false for v1.1. The fix commit (09c8578c) is already in Zephyr v4.4.2: the new decision is a different one, 'fixed', and needs a new review."
step "Still blocked until a person signs every decision for v1.1" \
     "make gate VERSION=v1.1" -- smake gate VERSION=v1.1 SOFT=1 GATE_ROWS=4
done_msg
