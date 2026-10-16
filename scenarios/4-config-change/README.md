# Scenario 4: a configuration change invalidates decisions

**Claim:** decisions are statements about one binary. Change the configuration and
the same CVE needs a new decision, even though the scanner output does not change at all.

**Setup:** release v1.1 = v1.0 + `releases/v1.1/release.conf` (`CONFIG_NET_IPV6=y`) and
`releases/v1.1/VERSION` (1.1.0). Built by `make prepare` (release overlay, see
`docs/reproducibility.md`).

| Step | Expected |
| --- | --- |
| release.conf | one line: `CONFIG_NET_IPV6=y` |
| diff A=v1.0 B=v1.1 | firmware rebuilt, ~30 Kconfig changes, +6 compiled files (icmpv6.c, ipv6.c, ...), findings **identical** (37), 0 of 37 decisions bound to v1.1; reassess triggers hit: CVE-2026-10637, -10638, -10640, -10686 |
| gate v1.1 | FAIL: R4 37 of 37 without decision, R8 no VEX |
| decide FROM=v1.0 | 37 drafts carried forward, 4 with "REASSESS" marked first |
| evidence v1.1 icmpv6.c | compiled, 1 320 bytes, `net_icmpv6_send_error` present |
| gate v1.1 | still FAIL: drafts need a person's review |

**Talking points:** the scanner cannot see the change; only the build evidence can.
For CVE-2026-10638 the new decision is `fixed`: the fix commit 09c8578c is already in the
v4.4.2 source (`make evidence` + the commit's lines). Different reason, same CVE, new
review. `make gate` also fails R2 if v1.1 was built from uncommitted changes.

**Alternative considered:** enabling Bluetooth (bigger change, more noise on screen).
