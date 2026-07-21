#!/usr/bin/env bash
#
# Runs the Railgun end-to-end integration test (shield / transfer / unshield via
# Paladin private APIs against the real RailgunSmartWallet, with real Groth16
# proofs verified on-chain).
#
# CONVENIENCE ONLY. This test depends on third-party Railgun repositories that are
# NOT distributed with this project and are licensed separately (not under a
# license compatible with this project's Apache-2.0 license). Obtaining, building,
# and using them is your own responsibility, subject to their licenses. Clone them
# yourself as siblings of the paladin-railgun repo:
#   - github.com/Railgun-Privacy/circuits-v2  -> ../circuits-v2  (circuit artifacts)
#   - github.com/Railgun-Privacy/contract     -> ../contract     (RailgunSmartWallet,
#     Poseidon libs and TestERC20 Hardhat artifacts; must be compiled first)
#
# Prerequisites:
#   - An EVM node reachable per testbed.config.yaml (http://localhost:8545).
#   - The two sibling repos above.
#
# Usage: run-e2e.sh [CIRCUITS_V2_REPO] [RAILGUN_CONTRACT_REPO]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
PEER_ROOT="$(cd "${ROOT}/.." && pwd)"        # parent dir holding sibling repos
REPO="${1:-${PEER_ROOT}/circuits-v2}"
CONTRACT_REPO="${2:-${PEER_ROOT}/contract}"

# Populate the (git-ignored) Railgun contract artifacts the test embeds via
# go:embed, copied from your own checkout of the Railgun contract repo.
"${ROOT}/solidity/copy-railgun-artifacts.sh" "${CONTRACT_REPO}"

CIRCUITS_DIR="$(mktemp -d)/circuits"
trap 'rm -rf "$(dirname "${CIRCUITS_DIR}")"' EXIT

# The e2e exercises 1x2 transacts (transfer + unshield-with-change).
"${ROOT}/solidity/extract-circuits.sh" "${CIRCUITS_DIR}" 01x01 01x02 --repo "${REPO}"

export RAILGUN_CIRCUITS_DIR="${CIRCUITS_DIR}"
export GOFLAGS=-mod=mod

cd "${HERE}"
go test -v -run TestRailgunE2ESuite ./...
