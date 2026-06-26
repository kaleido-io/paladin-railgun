#!/usr/bin/env bash
#
# Runs the Railgun Go proving tests: assembles circuit artifacts from the Railgun
# circuits-v2 repo, then runs the note-crypto / prover / transaction-builder
# tests, verifying each Go-generated Groth16 proof with snarkjs against the real
# circuit verification keys.
#
# Usage: run-proving-tests.sh [CIRCUITS_V2_REPO]
#   defaults to ~/workspace.zkp/railgun/circuits-v2

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="$(cd "${HERE}/.." && pwd)"          # the domain-impl Go module
REPO_ROOT="$(cd "${MODULE}/.." && pwd)"      # repo root (holds solidity/)
REPO="${1:-${HOME}/workspace.zkp/railgun/circuits-v2}"

CIRCUITS_DIR="$(mktemp -d)/circuits"
trap 'rm -rf "$(dirname "${CIRCUITS_DIR}")"' EXIT

# Assemble the circuit sizes exercised by the tests.
"${REPO_ROOT}/solidity/extract-circuits.sh" "${CIRCUITS_DIR}" 01x02 --repo "${REPO}"

export RAILGUN_CIRCUITS_DIR="${CIRCUITS_DIR}"
export SNARKJS="${REPO}/node_modules/.bin/snarkjs"
export GOFLAGS=-mod=mod
export GOMODCACHE="${GOMODCACHE:-${HOME}/workspace.paladin/paladin/.gomodcache}"

cd "${MODULE}"
go test ./internal/railgun/railgunnote/ ./internal/railgun/railgunprover/ ./internal/railgun/railguntx/ -v
