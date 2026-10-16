# CI checklist: taking this workflow into a real product

The demo runs on one laptop. These are the things to change or add before you rely on
the same workflow for a product. `.github/workflows/pipeline.yml` is a starting point
that already does the first three.

## Already in the demo

- [x] Tooling pinned by digest and checksum; `make doctor` fails on any drift
- [x] Offline steps (`--network none`) after an explicit fetch
- [x] Firmware identified by hash; decisions, VEX and gate bound to it
- [x] Gate as code (`policy/gate.yaml`), PASS/FAIL with reasons, machine-readable result
- [x] Scheduled rescan of the released SBOM with today's databases (the CI workflow)

## Before production

- [ ] **Signing keys:** keyless signing (Sigstore with OIDC) or a KMS/HSM-backed key
      instead of `keys/cosign.key` on a laptop; upload to a transparency log.
- [ ] **Builder identity:** build in CI with an isolated, ephemeral builder; the
      provenance `builder.id` must name it (SLSA Build L2/L3).
- [ ] **Reviewer identity:** protect `decisions/` with CODEOWNERS and required reviews;
      require signed commits. The gate's name check is only a heuristic.
- [ ] **Snapshots:** record DB snapshots on a schedule and keep them (artifact storage),
      so every past scan can be reproduced.
- [ ] **Archive per release:** firmware, SBOMs, provenance, findings, decisions, VEX and
      gate result. The CRA (Art. 13(13)) requires the technical documentation to be kept
      for at least 10 years after the product is placed on the market, or for the support
      period if that is longer. Check the details with your compliance team.
- [ ] **Coverage gaps:** components identified only by commit (cmsis_6, hal_rpi_pico)
      need online OSV queries or another source; vendored code needs map entries (scenario 1).
- [ ] **VEX distribution:** publish VEX with each release (and update it) where customers
      fetch it; consider CSAF VEX for customers who require it (`docs/vex-formats.md`).
- [ ] **Alerting:** a new finding without a decision on a released firmware must reach a
      person (issue, ticket), with the due-date rule of R7.
- [ ] **Vulnerability handling process:** reporting channel (CVD policy, security.txt),
      timelines, and the CRA reporting obligations for actively exploited vulnerabilities.
      None of that is tooling.
