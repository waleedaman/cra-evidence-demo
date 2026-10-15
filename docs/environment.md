# Environment (Phase 0)

## Image

- Base: `ghcr.io/zephyrproject-rtos/ci-base`, pinned by digest. We use `ci-base` rather
  than `ci` because `ci` installs every SDK toolchain plus extra toolchains and simulators
  (`setup.sh -t all`). We only need native_sim (host gcc, already in ci-base) and one ARM
  board later.
- The image's Python packages were installed from Zephyr `main` when upstream built it.
  The image therefore cannot be rebuilt bit-for-bit from its Dockerfile. The digest pin
  is the reproducibility guarantee for the base layer.
- On top: Zephyr SDK 1.0.1 *minimal* bundle plus the `arm-zephyr-eabi` toolchain only.
  We extract our own sha256-verified toolchain archive into `gnu/` instead of letting
  `setup.sh` download it. The SDK is located through `ZEPHYR_SDK_INSTALL_DIR`, so no CMake
  package registration is needed. SDK host tools are not installed.
- CLI tools are installed from release artifacts verified against `pins.env`. apt is not
  used in our layer because apt packages cannot be pinned reliably without a snapshot mirror.
- Pipeline Python code runs in its own venv (`/opt/cra-venv`, Python 3.12, hashed lock).
  That venv is deliberately **not** on `PATH`, so Zephyr's CMake keeps using the ci-base
  venv with Zephyr's own requirements.

## Workspace and mounts

- The west workspace lives in a named Docker volume mounted at `/ws`. Zephyr has tens of
  thousands of files, and bind-mounting them from a Windows drive is slow.
- The repo is bind-mounted at `/ws/demo` and is the west manifest repository
  (`west init -l`).
- `west.yml` imports only the modules in `name-allowlist`, at the SHAs Zephyr v4.4.2
  declares. `make doctor` checks HEAD and a clean tree for each one.
- Containers run as the host UID/GID. `/ws` is world-writable (sticky) in the image so
  the volume works for any UID.

## Network policy

- Network: `make pin-base`, `make env`, `make snapshot`, `make fetch`.
- Everything else: `docker run --network none`. `make doctor` proves this: it fails if DNS
  or outbound TCP works.
- Grype is configured (`config/grype.yaml`) not to auto-update, not to check for app
  updates, and not to reject old DBs. Its default rejects DBs older than 5 days.

## Vulnerability DB snapshots

- `make snapshot NAME=<name>` downloads the *current* upstream Grype DB (via its
  `latest.json`) and OSV ecosystem zips. It then records URL, sha256, build date and HTTP
  `Last-Modified` in `vulndb/snapshots.yaml`. This is trust-on-first-use, and the date is
  part of the record.
- `make fetch` re-verifies archives. If an archive is missing it re-downloads it and
  **fails** when the bytes no longer match. Upstream replaces "latest" archives over time,
  so long-term reproducibility needs our own copy of the archives. Publishing them as
  release assets of this repo is planned for Phase 10, pending a licence check of the
  bundled data.
- Each Grype snapshot is imported into its own cache directory (`/ws/cache/grype/<name>`),
  so scenario 5 can switch between a "before" and an "after" snapshot.

## Known limitations / open items

- The base image digest and DB snapshots are recorded on first use, not derived from a
  signed upstream source.
- `GIT` exists in the OSV bucket (verified 2026-10-15). The bucket also lists an
  `[EMPTY]` ecosystem (records without a package), which may matter for C/C++ in Phase 5.
- The OSV `all.zip` files are replaced every few hours, so a recorded OSV snapshot can
  only be re-created from our own copy. `make fetch VULNDB_MIRROR=<dir>` takes verified
  archives from a local directory (another clone, a USB stick) before trying upstream.
  `make clean-clone-check` uses this to prove a fresh clone reaches `make doctor` PASS.
- OSV-Scanner offline mode does not support commit-level matching, so OSV findings for
  embedded C libraries are expected to be sparse (Phase 5 topic).
- Only linux/amd64 is supported.
