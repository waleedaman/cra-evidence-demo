# Build/tooling image for the CRA evidence demo.
#
# Base: official Zephyr CI base image (ci-base), pinned by digest. The digest is
# passed in by `make env` from pins.env; the build refuses to run without it.
# Added on top: Zephyr SDK (minimal + arm-zephyr-eabi only), grype, osv-scanner,
# vexctl, cosign, jq, and a separate Python venv for the pipeline tools.
# Every download is verified against the sha256 in pins.env.

# The default is a deliberately non-existent image: `make env` always passes the pinned
# digest, and a plain `docker build` without it fails at the pull.
ARG BASE_IMAGE=base-image-must-be-passed-by-make-env
FROM ${BASE_IMAGE}
ARG BASE_IMAGE

LABEL org.opencontainers.image.title="cra-evidence-demo-tools" \
      org.opencontainers.image.description="Pinned build and SBOM/VEX tooling for the CRA evidence demo" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="${BASE_IMAGE}"

COPY pins.env requirements.lock /opt/cra/
COPY docker/install-tools.sh /opt/cra/install-tools.sh
RUN bash /opt/cra/install-tools.sh

# The SDK is found through this variable (no CMake package registry needed,
# so it works for any UID the container runs as).
ENV ZEPHYR_SDK_INSTALL_DIR=/opt/toolchains/zephyr-sdk \
    CRA_BASE_IMAGE=${BASE_IMAGE} \
    CRA_VENV=/opt/cra-venv \
    CRA_IN_IMAGE=1

# /ws becomes the west workspace (a named Docker volume is mounted here and is
# initialised from this directory, including its permissions). The demo repo
# itself is bind-mounted at /ws/demo.
RUN mkdir -p /ws && chmod 1777 /ws && \
    git config --system --add safe.directory '*'

WORKDIR /ws/demo
