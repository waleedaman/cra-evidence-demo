# From Firmware Build to CRA Evidence

Demo repository for the talk *"From Firmware Build to CRA Evidence: A Reproducible SBOM
and Vulnerability Workflow"*. Open tooling only. Licensed under Apache-2.0.

> Status: Phase 0 (environment). The application, SBOM, provenance, scanning, VEX and
> gate phases are not built yet.

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

After `make fetch`, every other target runs with `--network none`.

## Where things are pinned

- `pins.env`: Zephyr commit, module SHAs, base image digest, SDK, CLI tools (+ sha256)
- `requirements.lock`: Python packages with hashes
- `vulndb/snapshots.yaml`: vulnerability DB snapshots (URL, sha256, build date)
- `versions.lock.md`: generated, human-readable view of all of the above

See `docs/environment.md` for the design decisions behind the environment.
