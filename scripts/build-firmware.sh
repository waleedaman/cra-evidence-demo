#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-firmware.sh BOARD VERSION BUILD_DIR OUT_DIR
# Runs inside the tooling container (called by `make build` and `make reproduce-check`).
# Always a clean build: the build directory is deleted, `west spdx --init` prepares
# the CMake file-based API for the SBOM, then `west build` runs. Set QUIET=1 to
# suppress the artifact table. ZEPHYR_TOOLCHAIN_VARIANT comes from the environment.
set -euo pipefail

board="$1" version="$2" build_dir="$3" out_dir="$4"
mkdir -p "${out_dir}"
log="${out_dir}/build.log"

rm -rf "${build_dir}"
west spdx --init -d "${build_dir}" > /dev/null
if ! west build -b "${board}" -d "${build_dir}" app > "${log}" 2>&1; then
  tail -n 25 "${log}"
  exit 1
fi
if [[ "${QUIET:-0}" != "1" ]]; then
  grep -E "^ +(FLASH|RAM):" "${log}" || true
fi
quiet=()
[[ "${QUIET:-0}" == "1" ]] && quiet=(--quiet)
/opt/cra-venv/bin/python -m pipeline.artifacts --build-dir "${build_dir}" --out-dir "${out_dir}" \
  --board "${board}" --version "${version}" "${quiet[@]}"
