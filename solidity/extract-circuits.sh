#!/usr/bin/env bash
#
# Assembles Railgun joinsplit circuit artifacts into the canonical layout the
# domain prover and integration test consume:
#
#     <out>/<NNxMM>/{wasm,zkey,vkey.json}
#
# Source is the railgun circuits-v2 repo, which keeps:
#   - proving keys at  zkeys/<NNxMM>.zkey
#   - witness wasm at  build/<NNxMM>_js/<NNxMM>.wasm
# The verification key (vkey.json) is exported from the zkey with snarkjs.
#
# Usage: extract-circuits.sh <out-dir> [NNxMM ...] [--repo CIRCUITS_V2_REPO]
#   circuits default to those the domain/tests use: 01x01 01x02
#   CIRCUITS_V2_REPO defaults to ~/workspace.zkp/railgun/circuits-v2

set -euo pipefail

OUT="${1:?usage: extract-circuits.sh <out-dir> [NNxMM...]}"
shift || true
REPO="${HOME}/workspace.zkp/railgun/circuits-v2"
CIRCUITS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    *) CIRCUITS+=("$1"); shift;;
  esac
done
if [ ${#CIRCUITS[@]} -eq 0 ]; then
  CIRCUITS=(01x01 01x02)
fi

ZKEYS="${REPO}/zkeys"
BUILD="${REPO}/build"
SNARKJS="${REPO}/node_modules/.bin/snarkjs"
if [ ! -x "${SNARKJS}" ]; then
  SNARKJS="npx --no-install snarkjs"
fi
if [ ! -d "${ZKEYS}" ]; then
  echo "circuits-v2 zkeys not found at ${ZKEYS} (pass --repo)" >&2
  exit 1
fi

for c in "${CIRCUITS[@]}"; do
  zkey="${ZKEYS}/${c}.zkey"
  wasm="${BUILD}/${c}_js/${c}.wasm"
  if [ ! -f "${zkey}" ] || [ ! -f "${wasm}" ]; then
    echo "missing artifacts for ${c}: zkey=${zkey} wasm=${wasm}" >&2
    exit 1
  fi
  mkdir -p "${OUT}/${c}"
  cp "${zkey}" "${OUT}/${c}/zkey"
  cp "${wasm}" "${OUT}/${c}/wasm"
  ${SNARKJS} zkey export verificationkey "${zkey}" "${OUT}/${c}/vkey.json" >/dev/null
  echo "assembled ${c} -> ${OUT}/${c}"
done
echo "Done."
