#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-firmware.sh BOARD VERSION BUILD_DIR OUT_DIR
# Runs inside the tooling container (called by `make build` and `make reproduce-check`).
# Always a clean build: the build directory is deleted, `west spdx --init` prepares
# the CMake file-based API for the SBOM, then `west build` runs. Set QUIET=1 to
# suppress the artifact table. ZEPHYR_TOOLCHAIN_VARIANT comes from the environment.
#
# Releases: app/ is the current source. A later release that only changes the
# version and the configuration is described by releases/<VERSION>/VERSION and
# releases/<VERSION>/release.conf. Zephyr reads the app version only from
# <app dir>/VERSION, so such a release is built from a copy of app/ next to the
# build directory (never by editing the tracked app/VERSION), with release.conf
# applied through EXTRA_CONF_FILE.
set -euo pipefail

board="$1" version="$2" build_dir="$3" out_dir="$4"
mkdir -p "${out_dir}"
log="${out_dir}/build.log"

app_dir="app"
extra=()
rel="releases/${version}"
if [[ -d "${rel}" ]]; then
  app_dir="${build_dir}-src/app"
  rm -rf "${build_dir}-src"
  mkdir -p "${app_dir}"
  cp -r app/. "${app_dir}/"
  cp "${rel}/VERSION" "${app_dir}/VERSION"
  extra=(-- "-DEXTRA_CONF_FILE=${PWD}/${rel}/release.conf"
         "-DDEMO_CA_DER=${PWD}/certs/generated/demo-ca.der")
fi

rm -rf "${build_dir}"
west spdx --init -d "${build_dir}" > /dev/null
if ! west build -b "${board}" -d "${build_dir}" "${app_dir}" "${extra[@]}" > "${log}" 2>&1; then
  tail -n 25 "${log}"
  exit 1
fi
if [[ "${QUIET:-0}" != "1" ]]; then
  grep -E "^ +(FLASH|RAM):" "${log}" || true
fi
quiet=()
[[ "${QUIET:-0}" == "1" ]] && quiet=(--quiet)
"${CRA_PY:-/opt/cra-venv/bin/python}" -m pipeline.artifacts --build-dir "${build_dir}" --out-dir "${out_dir}" \
  --board "${board}" --version "${version}" "${quiet[@]}"
