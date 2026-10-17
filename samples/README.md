# Samples

Real outputs of the pipeline for the W5500-EVB-Pico2 board, copied from `out/` by
`make samples` after `make prepare`, so they can be read without building anything.

- `v1.0/w5500_evb_pico2_rp2350a_m33/`: the released firmware: raw and normalized SBOM,
  signed provenance, findings (snapshot `baseline`), review queue, build evidence, signed
  OpenVEX, gate result
- `v1.1/w5500_evb_pico2_rp2350a_m33/`: the IPv6 release of scenario 4, with
  `diff-v1.0.json` (no decisions, so no VEX; its gate fails)

Not included: firmware binaries, ELF, linker map and logs (size). Their SHA-256 are in
`artifacts.json` and in the signed provenance. The provenance and VEX are signed with the
presenter's key; the committed `keys/cosign.pub` verifies them (if you created your own
key as described in the main README, the presenter's key is in `keys/presenter.pub`).
