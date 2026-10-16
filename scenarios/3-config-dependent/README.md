# Scenario 3: configuration-dependent vulnerability

**Claim:** "Zephyr 4.4.2 is affected" is a statement about source code. Whether *this
firmware* is affected depends on what the build compiled. The build itself is the evidence.

**Setup:** CVE-2026-10638 (High) in `subsys/net/ip/icmpv6.c`. The firmware is IPv4 only
(`CONFIG_NET_IPV6` not set).

| Step | Expected |
| --- | --- |
| finding | Grype: NVD range `>= 4.2.0, < 4.5.0`; OSV record does not list v4.4.2 |
| evidence icmpv6.c | not a source of the build, `CONFIG_NET_IPV6` not set, 0 bytes, symbol absent |
| evidence icmpv4.c | listed, compiled into `libsubsys__net__ip.a`, 836 bytes, present |
| decision | not_affected / vulnerable_code_not_present, reassess trigger `CONFIG_NET_IPV6=y` |

**Four checks, four sources:** build SBOM (`west spdx`, CMake file API), `.config`,
linker map, `nm` on `zephyr.elf`. "Compiled" is not "contains code": `kernel/pipe.c` is
compiled but contributes 0 bytes (`make evidence FILE=kernel/pipe.c`).

**Alternatives considered:** CVE-2026-10685 (Bluetooth GATT; Bluetooth off), CVE-2026-10773
(DHCPv4; static IP). ICMPv6 was chosen because scenario 4 can switch it on.
