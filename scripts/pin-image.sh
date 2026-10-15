#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# pin-image.sh IMAGE TAG PREFIX
# Pull IMAGE:TAG once and record its registry digest in pins.env as
# <PREFIX>_DIGEST and <PREFIX>_DIGEST_RECORDED (trust on first use, dated).
set -euo pipefail

image="$1" tag="$2" prefix="$3"
docker pull "${image}:${tag}"
digest="$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "${image}:${tag}" \
  | grep "^${image}@" | head -n1 | cut -d@ -f2)"
if [[ -z "${digest}" ]]; then
  echo "ERROR: no repo digest found for ${image}:${tag}" >&2
  exit 1
fi
grep -q "^${prefix}_DIGEST=" pins.env || { echo "ERROR: ${prefix}_DIGEST missing in pins.env" >&2; exit 1; }
sed -i "s|^${prefix}_DIGEST=.*|${prefix}_DIGEST=${digest}|; s|^${prefix}_DIGEST_RECORDED=.*|${prefix}_DIGEST_RECORDED=$(date -u +%Y-%m-%d)|" pins.env
echo "recorded ${image}@${digest} in pins.env (commit it)"
