#!/usr/bin/env bash
#
# Runs the Railgun Go proving tests: assembles circuit artifacts from the Railgun
# circuits-v2 repo, then runs the note-crypto / prover / transaction-builder
# tests, verifying each Go-generated Groth16 proof with snarkjs against the real
# circuit verification keys.
#
# CONVENIENCE ONLY. This project does not distribute the Railgun circuits-v2 repo
# and is not licensed to. You must clone github.com/Railgun-Privacy/circuits-v2
# yourself (as a sibling of the paladin-railgun repo) and build its artifacts,
# subject to that repo's own license, for this script to work.
#
# Usage: run-proving-tests.sh [CIRCUITS_V2_REPO]
#   CIRCUITS_V2_REPO defaults to ../circuits-v2 (a sibling of paladin-railgun).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="$(cd "${HERE}/.." && pwd)"          # the domain-impl Go module
REPO_ROOT="$(cd "${MODULE}/.." && pwd)"      # repo root (holds solidity/)
PEER_ROOT="$(cd "${REPO_ROOT}/.." && pwd)"   # parent dir holding sibling repos
REPO="${1:-${PEER_ROOT}/circuits-v2}"

CIRCUITS_DIR="$(mktemp -d)/circuits"
trap 'rm -rf "$(dirname "${CIRCUITS_DIR}")"' EXIT

# Assemble the circuit sizes exercised by the tests.
"${REPO_ROOT}/solidity/extract-circuits.sh" "${CIRCUITS_DIR}" 01x02 --repo "${REPO}"

export RAILGUN_CIRCUITS_DIR="${CIRCUITS_DIR}"
export SNARKJS="${REPO}/node_modules/.bin/snarkjs"
export GOFLAGS=-mod=mod

cd "${MODULE}"
go test ./internal/railgun/railgunnote/ ./internal/railgun/railgunprover/ ./internal/railgun/railguntx/ -v
