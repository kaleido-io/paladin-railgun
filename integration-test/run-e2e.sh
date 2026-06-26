#!/usr/bin/env bash
#
# Runs the Railgun end-to-end integration test (shield / transfer / unshield via
# Paladin private APIs against the real RailgunSmartWallet, with real Groth16
# proofs verified on-chain).
#
# Prerequisites:
#   - An EVM node reachable per testbed.config.yaml (http://localhost:8545).
#   - The Railgun circuits-v2 repo (for circuit artifacts: zkeys/ + build/),
#     default ~/workspace.zkp/railgun/circuits-v2.
#
# Usage: run-e2e.sh [CIRCUITS_V2_REPO]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
REPO="${1:-${HOME}/workspace.zkp/railgun/circuits-v2}"

CIRCUITS_DIR="$(mktemp -d)/circuits"
trap 'rm -rf "$(dirname "${CIRCUITS_DIR}")"' EXIT

# The e2e exercises 1x2 transacts (transfer + unshield-with-change).
"${ROOT}/solidity/extract-circuits.sh" "${CIRCUITS_DIR}" 01x01 01x02 --repo "${REPO}"

export RAILGUN_CIRCUITS_DIR="${CIRCUITS_DIR}"
export GOFLAGS=-mod=mod
export GOMODCACHE="${GOMODCACHE:-${HOME}/workspace.paladin/paladin/.gomodcache}"

cd "${HERE}"
go test -v -run TestRailgunE2ESuite ./...
