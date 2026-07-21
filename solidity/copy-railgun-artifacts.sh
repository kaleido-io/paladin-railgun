#!/usr/bin/env bash
#
# Populates ../integration-test/abis with the pre-compiled Railgun contract
# artifacts the Go integration test embeds via go:embed: the RailgunSmartWallet
# privacy-pool contract, the PoseidonT3/PoseidonT4 libraries it links against,
# and the TestERC20 test-token stub.
#
# THESE ARTIFACTS ARE NOT DISTRIBUTED WITH THIS REPOSITORY. They are derived from
# the third-party Railgun contract repo (github.com/Railgun-Privacy/contract),
# which is licensed separately and NOT under a license compatible with this
# project's Apache-2.0 license. Obtaining, building, and using that repo is your
# own responsibility, subject to its license. This convenience script only copies
# artifacts out of a checkout that you have already cloned and compiled yourself;
# the files it writes are git-ignored and never committed here.
#
# Usage: copy-railgun-artifacts.sh [RAILGUN_CONTRACT_REPO]
#   RAILGUN_CONTRACT_REPO defaults to ../contract (a sibling of the
#   paladin-railgun repo), pointing at your own checkout of
#   github.com/Railgun-Privacy/contract with its Hardhat artifacts built.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Parent of the paladin-railgun repo, where third-party repos are cloned as peers.
PEER_ROOT="$(cd "${HERE}/../.." && pwd)"
REPO="${1:-${PEER_ROOT}/contract}"
SRC="${REPO}/artifacts/contracts"
DST="${HERE}/../integration-test/abis"

if [ ! -d "${SRC}" ]; then
  echo "Railgun contract artifacts not found at ${SRC}" >&2
  echo "Clone github.com/Railgun-Privacy/contract as a sibling of paladin-railgun" >&2
  echo "and build its Hardhat artifacts, or pass the repo path as an argument." >&2
  exit 1
fi

mkdir -p "${DST}"

cp "${SRC}/logic/RailgunSmartWallet.sol/RailgunSmartWallet.json" "${DST}/RailgunSmartWallet.json"
cp "${SRC}/logic/Poseidon.sol/PoseidonT3.json" "${DST}/PoseidonT3.json"
cp "${SRC}/logic/Poseidon.sol/PoseidonT4.json" "${DST}/PoseidonT4.json"
cp "${SRC}/teststubs/TokenStubs.sol/TestERC20.json" "${DST}/TestERC20.json"

echo "Copied RailgunSmartWallet, PoseidonT3, PoseidonT4, TestERC20 artifacts to ${DST}"
