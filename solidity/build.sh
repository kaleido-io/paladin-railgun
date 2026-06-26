#!/usr/bin/env bash
#
# Compiles the RailgunFactory wrapper and emits a Paladin build artifact
# (ABI + bytecode JSON) into ../integration-test/abis, where the Go integration
# test embeds it via go:embed.
#
# The real Railgun contracts (RailgunSmartWallet, PoseidonT3, PoseidonT4) are
# NOT compiled here — their pre-built Hardhat artifacts are copied from the
# Railgun contract repo by copy-railgun-artifacts.sh.
#
# Requires: solc (>= 0.8.20) and python3.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${HERE}/../integration-test/abis"
BUILD_DIR="${HERE}/build"

mkdir -p "${OUT_DIR}" "${BUILD_DIR}"

solc --combined-json abi,bin --optimize --overwrite -o "${BUILD_DIR}" \
  "${HERE}/contracts/RailgunFactory.sol"

python3 - "${BUILD_DIR}/combined.json" "${OUT_DIR}" <<'PY'
import json, sys
combined_path, out_dir = sys.argv[1], sys.argv[2]
d = json.load(open(combined_path))

def emit(key, outname):
    c = d["contracts"][key]
    abi = c["abi"]
    if isinstance(abi, str):
        abi = json.loads(abi)
    artifact = {"abi": abi, "bytecode": "0x" + c["bin"]}
    path = f"{out_dir}/{outname}.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"wrote {path}")

emit("contracts/RailgunFactory.sol:RailgunFactory", "RailgunFactory")
PY

rm -rf "${BUILD_DIR}"
echo "Done."
