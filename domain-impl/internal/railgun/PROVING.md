# Railgun real proving (Go)

A from-scratch Go implementation of Railgun's note cryptography and Groth16
proving, producing **on-chain-valid** `shield` / `transact` / `unshield` calldata
for the real `RailgunSmartWallet` contract.

Every layer is validated against the Railgun reference implementation (the TS
helpers + circuits in the third-party `Railgun-Privacy/contract` and
`Railgun-Privacy/circuits-v2` repos) and against **snarkJS** using the real
circuit verification keys — so the proofs these packages produce are accepted by
the on-chain verifier.

> **Third-party materials.** The circuits and the Railgun reference implementation
> used for validation are licensed separately from this project (not under its
> Apache-2.0 license) and are **not** distributed here. Obtain and build them
> yourself, subject to their licenses. The committed `testdata/*.json` files are
> numeric known-answer vectors generated from that reference to validate this
> independent Go implementation; they contain no Railgun source. See the
> [root README](../../../README.md#third-party-dependencies-and-licensing).

## Packages

| Package | What it does | Validated by |
|---------|--------------|--------------|
| `railgunnote` | Note model — keys, `mpk`, `npk`, commitment, nullifier, EdDSA-Poseidon spend signature; depth-16 Poseidon Merkle tree; joinsplit witness builder | `testdata/vectors.json` (generated from the Railgun TS helpers) |
| `railgunprover` | Groth16 proving via `go-rapidsnark` (witness calc + prover); proof formatting for the contract (`SnarkProof` G2 coord swap) | snarkJS `groth16 verify` against the real vkey |
| `railguntx` | `boundParamsHash` (`keccak256(abi.encode(BoundParams)) % field`); full `transact` builder | ethers reference + snarkJS |

### Key derivations (BN254 / Poseidon)

```
nullifyingKey   = Poseidon(viewingKey)
masterPublicKey = Poseidon(spendPub.x, spendPub.y, nullifyingKey)   // "mpk"
notePublicKey   = Poseidon(mpk, random)                              // "npk"
commitment      = Poseidon(npk, tokenID, value)
nullifier       = Poseidon(nullifyingKey, leafIndex)
signature       = EdDSA-Poseidon(spendingKey, sighash)
  sighash       = Poseidon(merkleRoot, boundParamsHash, nullifiers…, commitmentsOut…)
```

`go-iden3-crypto/babyjub` is wire-compatible with the reference's `circomlibjs`
EdDSA-Poseidon, so spending keys, public keys, and signatures all match.

## Running the proving tests

The circuit artifacts (`wasm`, `zkey`, `vkey.json`) are large (~9MB/circuit) and
are **not committed**. They are assembled from the Railgun **circuits-v2** repo,
which keeps proving keys at `zkeys/<NNxMM>.zkey` and witness wasm at
`build/<NNxMM>_js/<NNxMM>.wasm` (the verification key is exported from the zkey
with snarkjs). `solidity/extract-circuits.sh` produces the canonical
`<dir>/<NNxMM>/{wasm,zkey,vkey.json}` layout the prover loads:

The commands below assume you have cloned + built `Railgun-Privacy/circuits-v2`
as a sibling of the `paladin-railgun` repo (`../circuits-v2`); pass a different
path as an argument to override.

```bash
# one-shot: assemble circuits + run all proving tests (verifies each proof in snarkJS)
scripts/run-proving-tests.sh [path-to-circuits-v2-repo]   # default ../circuits-v2

# or manually (CIRCUITS_V2 = your own checkout of Railgun-Privacy/circuits-v2)
CIRCUITS_V2=../../circuits-v2
solidity/extract-circuits.sh /tmp/circuits 01x02 --repo "${CIRCUITS_V2}"
RAILGUN_CIRCUITS_DIR=/tmp/circuits \
SNARKJS="${CIRCUITS_V2}/node_modules/.bin/snarkjs" \
GOFLAGS=-mod=mod \
go test ./internal/railgun/railguntx/ -run TestBuildTransact -v
```

The note/merkle/witness/boundParams unit tests run with no external deps;
only the proof-generation tests need `RAILGUN_CIRCUITS_DIR` (+ snarkJS to verify).

## Remaining work (follow-up)

These packages are the cryptographic core; they are not yet wired into the
domain handlers. To reach full end-to-end through Paladin private APIs:

1. **Domain identity model** — expose `mpk` as the verifier (derive the viewing
   key deterministically from the Paladin-managed spending key); store each
   note's `random` in its state so it remains spendable.
2. **State-backed commitment tree** — maintain Railgun's append-only Poseidon
   tree from `Shield`/`Transact` events (leaf index = insertion order), persisted
   as Paladin states, so `AssembleTransaction` can produce Merkle proofs. (This
   is distinct from the toolkit's sparse Merkle tree.)
3. **Handlers** — `shield` assembles real `npk`/token/value (no proof);
   `transfer`/`unshield` build the witness in `Assemble` and generate the proof
   in `Sign()` via `railguntx.BuildTransact`.
4. **Contract setup** — `initializeRailgunLogic(...)` + `setVerificationKey(...)`
   (static VK from `vkey.json`) before any `transact`.
5. **E2E test** — public ERC-20 deploy + private shield/transfer/unshield via
   Paladin APIs against a live node (anvil, chainID 31337 to match `boundParams`).
