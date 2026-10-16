#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# make-samples.sh BOARD: copy the evidence files of the v1.0 and v1.1 release outputs into
# samples/ (committed), so readers can inspect real outputs without building anything.
# Binaries, the linker map and logs are left out (size); their hashes are in
# artifacts.json and the signed provenance.
set -euo pipefail

board_dir="${1//\//_}"
rm -rf samples/v1.0 samples/v1.1
for rel in v1.0 v1.1; do
  src="out/${rel}/${board_dir}"
  [[ -f "${src}/artifacts.json" ]] || { echo "missing ${src}: run make prepare" >&2; exit 1; }
  dst="samples/${rel}/${board_dir}"
  mkdir -p "${dst}"
  for f in artifacts.json config provenance.intoto.json provenance.sigstore.json verify.json \
           sbom normalized validate findings.json queue.json evidence vex gate.json diff-v1.0.json; do
    [[ -e "${src}/${f}" ]] && cp -r "${src}/${f}" "${dst}/"
  done
  # scanner raw output: keep the reports, not the OSV-Scanner input copy
  if [[ -d "${src}/scan" ]]; then
    mkdir -p "${dst}/scan"
    cp -r "${src}/scan/." "${dst}/scan/"
  fi
done
du -sh samples/v1.0 samples/v1.1
