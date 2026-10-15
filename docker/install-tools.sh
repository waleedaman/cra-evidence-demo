#!/usr/bin/env bash
# Installs the pinned tools into the image. Runs once during `docker build`.
# Every artifact is downloaded, checked against the sha256 in pins.env, and
# only then installed. Any mismatch aborts the build.
set -euo pipefail

# shellcheck source=../pins.env
source /opt/cra/pins.env

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: only linux/amd64 artifacts are pinned (got $(uname -m))" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# download URL OUTFILE SHA256
download() {
  local url="$1" out="$2" sha="$3"
  echo ">> ${url}"
  wget -q -O "${out}" "${url}"
  echo "${sha}  ${out}" | sha256sum --check --strict -
}

gh="https://github.com"

# --- Zephyr SDK: minimal bundle + ARM GNU toolchain --------------------------
sdk_base="${gh}/zephyrproject-rtos/sdk-ng/releases/download/v${ZEPHYR_SDK_VERSION}"
download "${sdk_base}/zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64_minimal.tar.xz" \
  "${work}/sdk.tar.xz" "${ZEPHYR_SDK_MINIMAL_SHA256}"
download "${sdk_base}/toolchain_gnu_linux-x86_64_arm-zephyr-eabi.tar.xz" \
  "${work}/arm.tar.xz" "${ZEPHYR_SDK_ARM_SHA256}"
mkdir -p /opt/toolchains
tar -xf "${work}/sdk.tar.xz" -C /opt/toolchains
sdk_dir="/opt/toolchains/zephyr-sdk-${ZEPHYR_SDK_VERSION}"
# setup.sh would download the toolchain itself (unverified); we extract our
# verified copy into the same place setup.sh uses (gnu/<toolchain>).
mkdir -p "${sdk_dir}/gnu"
tar -xf "${work}/arm.tar.xz" -C "${sdk_dir}/gnu"

# --- grype (tarball) -------------------------------------------------------------
download "${gh}/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
  "${work}/grype.tar.gz" "${GRYPE_SHA256}"
tar -xzf "${work}/grype.tar.gz" -C "${work}" grype
install -m 0755 "${work}/grype" /usr/local/bin/grype

# --- single-binary tools -------------------------------------------------------
download "${gh}/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
  "${work}/osv-scanner" "${OSV_SCANNER_SHA256}"
download "${gh}/openvex/vexctl/releases/download/v${VEXCTL_VERSION}/vexctl-linux-amd64" \
  "${work}/vexctl" "${VEXCTL_SHA256}"
download "${gh}/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
  "${work}/cosign" "${COSIGN_SHA256}"
download "${gh}/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64" \
  "${work}/jq" "${JQ_SHA256}"
for t in osv-scanner vexctl cosign jq; do
  install -m 0755 "${work}/${t}" "/usr/local/bin/${t}"
done

# --- Python venv for pipeline code (separate from Zephyr's venv) -------------------
# Kept off PATH on purpose: Zephyr's CMake must keep finding the ci-base venv python.
/usr/bin/python3 -m venv /opt/cra-venv
/opt/cra-venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: \
  -r /opt/cra/requirements.lock

# --- record what was installed (checked again by `make doctor`) ---------------------
sha256sum /usr/local/bin/grype /usr/local/bin/osv-scanner /usr/local/bin/vexctl \
  /usr/local/bin/cosign /usr/local/bin/jq \
  "${sdk_dir}/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" > /opt/cra/installed.sha256
/opt/cra-venv/bin/pip freeze --all > /opt/cra/pip-freeze.txt
echo "install-tools: done"
