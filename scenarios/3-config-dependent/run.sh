#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Scenario 3: configuration-dependent. CVE-2026-10638 is in Zephyr's ICMPv6 code; this
# firmware is built without IPv6. Evidence from the build that the code is absent.
SCENARIO=3
source "$(dirname "$0")/../lib.sh"

title "Configuration-dependent: the CVE is in Zephyr, but is it in our firmware?" \
      "Firmware v1.0, ${BOARD}. Zephyr v4.4.2, IPv4 only."
setup v1.0

step "Grype: Zephyr 4.4.2 is in the NVD range of CVE-2026-10638 (High)" \
     "make finding VERSION=v1.0 VULN=CVE-2026-10638" -- smake finding VERSION=v1.0 VULN=CVE-2026-10638
step "Four checks against the build: SBOM, .config, linker map, symbols" \
     "make evidence VERSION=v1.0 FILE=subsys/net/ip/icmpv6.c SYMBOL=net_icmpv6_send_error KCONFIG=CONFIG_NET_IPV6" -- \
     smake evidence VERSION=v1.0 FILE=subsys/net/ip/icmpv6.c SYMBOL=net_icmpv6_send_error KCONFIG=CONFIG_NET_IPV6
step "For comparison: the IPv4 counterpart IS in the firmware" \
     "make evidence VERSION=v1.0 FILE=subsys/net/ip/icmpv4.c KCONFIG=CONFIG_NET_IPV4" -- \
     smake evidence VERSION=v1.0 FILE=subsys/net/ip/icmpv4.c KCONFIG=CONFIG_NET_IPV4
step "The decision: not_affected, vulnerable_code_not_present, and when to look again" \
     "make decision VERSION=v1.0 VULN=CVE-2026-10638" -- smake decision VERSION=v1.0 VULN=CVE-2026-10638
say "The justification is a statement about ONE binary. Scenario 4 changes the configuration."
done_msg
