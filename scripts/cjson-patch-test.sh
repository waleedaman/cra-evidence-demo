#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# cjson-patch-test.sh: evidence for scenario 2 (CVE-2024-31755, supplier backport).
# Builds app/lib/cjson/tests/setvaluestring_null.c with the host compiler twice:
#   A) upstream cJSON 1.7.17 = app/lib/cjson/cJSON.c with the local patch reversed
#   B) app/lib/cjson/cJSON.c as compiled into the firmware (1.7.17 + patch)
# and runs both. A is expected to crash (SIGSEGV), B to reject the NULL argument.
# Writes the transcript to out/evidence/cjson-CVE-2024-31755-test.txt.
set -uo pipefail

src=app/lib/cjson
patch_file=${src}/patches/0001-Add-NULL-check-to-cJSON_SetValuestring.patch
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
out=out/evidence/cjson-CVE-2024-31755-test.txt
mkdir -p "$(dirname "${out}")"

mkdir -p "${work}/upstream"
cp "${src}/cJSON.c" "${src}/cJSON.h" "${work}/upstream/"
(cd "${work}/upstream" && git apply -R "${OLDPWD}/${patch_file}") || { echo "patch does not reverse cleanly"; exit 1; }

run() {  # label dir
  gcc -O0 -I"$2" -o "${work}/$1.bin" "${src}/tests/setvaluestring_null.c" "$2/cJSON.c" || exit 1
  { "${work}/$1.bin"; } 2>/dev/null
  local rc=$?
  if (( rc > 128 )); then echo "CRASH (signal $((rc - 128)))"; else echo "exit code ${rc}"; fi
}

{
  echo "cJSON.c sha256 (firmware): $(sha256sum "${src}/cJSON.c" | cut -d' ' -f1)"
  echo "cJSON.c sha256 (upstream): $(sha256sum "${work}/upstream/cJSON.c" | cut -d' ' -f1)"
  echo "compiler: $(gcc --version | head -n1)"
  echo
  echo "A) upstream 1.7.17 (patch reversed):"
  run upstream "${work}/upstream" 2>&1
  echo
  echo "B) firmware copy (1.7.17 + upstream fix 7e4d5dab):"
  run patched "${src}" 2>&1
} | tee "${out}"
echo "transcript -> ${out}"
