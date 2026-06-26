#!/usr/bin/env bash
#
# Copies the pre-compiled real Railgun contract artifacts (RailgunSmartWallet and
# the PoseidonT3/PoseidonT4 libraries it links against) from a checkout of the
# Railgun contract repo into ../integration-test/abis, where the Go integration
# test embeds them via go:embed.
#
# Usage: copy-railgun-artifacts.sh [RAILGUN_CONTRACT_REPO]
#   RAILGUN_CONTRACT_REPO defaults to ~/workspace.zkp/railgun/contract

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:-${HOME}/workspace.zkp/railgun/contract}"
SRC="${REPO}/artifacts/contracts/logic"
DST="${HERE}/../integration-test/abis"

mkdir -p "${DST}"

cp "${SRC}/RailgunSmartWallet.sol/RailgunSmartWallet.json" "${DST}/RailgunSmartWallet.json"
cp "${SRC}/Poseidon.sol/PoseidonT3.json" "${DST}/PoseidonT3.json"
cp "${SRC}/Poseidon.sol/PoseidonT4.json" "${DST}/PoseidonT4.json"

echo "Copied RailgunSmartWallet, PoseidonT3, PoseidonT4 artifacts to ${DST}"
