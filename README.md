# From Firmware Build to CRA Evidence

Demo repository for the talk *"From Firmware Build to CRA Evidence: A Reproducible SBOM
and Vulnerability Workflow"*. Open tooling only. Licensed under Apache-2.0.

> Status: Phase 5 (vulnerability matching and review queue). Decisions/VEX and gate phases are not built yet.

## Requirements

- Linux or Windows with WSL2 (run every command from the WSL2 shell)
- Docker (Docker Desktop with WSL2 integration on Windows)
- GNU make, bash, git
- About 15 GB free disk for the image, workspace and DB snapshots (estimate, to be measured)
- x86_64 host (only linux/amd64 tool artifacts are pinned)

## First-time setup (needs network)

```bash
make pin-base                 # once per base-image bump: records the ci-base digest in pins.env
make env                      # build the pinned tooling image
make snapshot NAME=baseline   # once: record the current vulnerability DBs (trust on first use)
make fetch                    # west workspace + verify/import the recorded DB snapshots
make doctor                   # offline: every version, pin and checksum must PASS
```

Acceptance check for Phase 0: `make clean-clone-check` (fresh clone + fresh workspace
volume, DB archives taken from this clone via `VULNDB_MIRROR`, then `make doctor`).

After `make fetch`, every other target runs with `--network none`.

## Sensor node (Phase 1)

A Zephyr application that reads a simulated temperature sensor and publishes it over
MQTT with TLS (server certificate verified against a demo CA).

```bash
make pin-mosquitto            # once: records the broker image digest in pins.env
make certs                    # once: demo-only CA + broker certificate (certs/generated/)
make build VERSION=v1.0       # native_sim build -> out/v1.0/native_sim_native_64/
make run                      # device + broker on an internal Docker network
make build VERSION=v1.0 BOARD=w5500_evb_pico2/rp2350a/m33   # real board (see docs/hardware.md)
```

## SBOM (Phase 2)

```bash
make build VERSION=v1.0 && make sbom VERSION=v1.0   # -> out/v1.0/<board>/sbom/*.spdx
```

What each SPDX document contains and the gaps we found: `docs/sbom.md`.

## Provenance and reproducibility (Phase 3)

```bash
make keys                                   # once: keys/cosign.key (private) + keys/cosign.pub
make provenance VERSION=v1.0                # signed SLSA v1 provenance, offline
make verify VERSION=v1.0                    # signature, digests, pins
make reproduce-check VERSION=v1.0           # two clean builds, different paths, compare hashes
```

See `docs/provenance.md` and `docs/reproducibility.md`.

## SBOM validation and normalization (Phase 4)

```bash
make validate VERSION=v1.0    # SPDX validity, NTIA minimum elements, FSCT3, CPE/PURL coverage
make normalize VERSION=v1.0   # -> out/v1.0/<board>/normalized/firmware.spdx.json
```

Identifiers that `west spdx` does not provide are added only from the reviewed
`identifiers/component-map.yaml`. Details and findings: `docs/sbom-quality.md`.

## Vulnerability matching and review queue (Phase 5)

```bash
make scan VERSION=v1.0 [SNAPSHOT=baseline]   # Grype + OSV-Scanner, offline -> out/v1.0/<board>/findings.json
make queue VERSION=v1.0 [ROWS=15]            # findings without a decision for this firmware hash
```

What each scanner can and cannot see, and why they disagree: `docs/scanning.md`.

## Where things are pinned

- `pins.env`: Zephyr commit, module SHAs, base image digest, SDK, CLI tools (+ sha256)
- `requirements.lock`: Python packages with hashes
- `vulndb/snapshots.yaml`: vulnerability DB snapshots (URL, sha256, build date)
- `versions.lock.md`: generated, human-readable view of all of the above

See `docs/environment.md` for the design decisions behind the environment.
