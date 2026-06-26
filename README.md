# Paladin Railgun Domain

A [LFDT Paladin](https://github.com/LFDT-Paladin/paladin) **domain plugin** that
brings the [Railgun](https://www.railgun.org/) privacy protocol to Paladin as a
private token type.

Paladin is a privacy-preserving transaction manager for EVM blockchains. A
*domain* is a pluggable extension (implementing `plugintk.DomainAPI`) that
teaches Paladin how to assemble, prove, submit, and index a particular class of
private transactions. This repository implements a domain for Railgun: a
zk-SNARK shielded-pool protocol where value is held in Poseidon-commitment notes
inside an on-chain Merkle tree, and spends are authorized by Groth16 proofs and
nullifiers — without revealing amounts, owners, or which notes were spent.

The domain is implemented based on the **`RailgunSmartWallet` contract** and the
**Railgun joinsplit circuits**: notes, nullifiers, the commitment tree, the
spend witness, and the Groth16 proof are all generated in Go and accepted by the
on-chain verifier.

## Capabilities

Exposed as Paladin private transactions (the user submits the receiver and
amount; the domain handles all the cryptography):

| Operation  | Description                                                        | On-chain call |
|------------|--------------------------------------------------------------------|---------------|
| `shield`   | Deposit ERC-20 tokens, mint a private note for a recipient         | `shield(ShieldRequest[])` (no proof) |
| `transfer` | Spend notes, create new notes for recipients (+ change)            | `transact(Transaction[])` (Groth16 proof) |
| `unshield` | Burn notes to withdraw ERC-20 to a public address                  | `transact(Transaction[])` with unshield (Groth16 proof) |
| `balanceOf`| Read the shielded balance of an account (domain call)              | — |

## Code structure

```
domain-impl/                 The domain Go module (github.com/LFDT-Paladin/paladin/domains/railgun)
  pkg/                       Public API + shared types
    railgun/                 Entry point: New(callbacks) plugintk.DomainAPI
    types/                   Note / tree-leaf state schemas, config, IRailgun ABI, receipts
    railgunsignerapi/        Signing algorithm constants, nullifier + masterPublicKey derivation
  internal/railgun/          The domain implementation
    railgun.go               plugintk.DomainAPI: configure, deploy, transaction lifecycle,
                             GetVerifier (masterPublicKey), Sign (nullifier + Groth16 proof)
    handler_events.go        HandleEventBatch: Shield/Transact/Unshield/Nullified -> state updates
    events.go / events_abi.go  Real RailgunSmartWallet event ABIs + decoders
    receipts.go, stubs.go    Domain receipt builder + unsupported DomainAPI methods
    fungible/                Per-operation handlers (shield, transfer, unshield, balanceOf),
                             note/tree state helpers, on-chain calldata assembly
    railgunnote/             Railgun note cryptography — keys, npk, commitment, nullifier,
                             EdDSA-Poseidon spend signature, depth-16 Poseidon Merkle tree,
                             joinsplit witness builder (validated against reference vectors)
    railgunprover/           Groth16 proving via go-rapidsnark (witness calc + prover)
    railguntx/               boundParamsHash + full transact() calldata assembly
    PROVING.md               How the proving stack works + how to run its tests
  scripts/run-proving-tests.sh  One-shot: assemble circuits + run the Go proving tests

solidity/                    Hardhat project for the domain's own Solidity + helper scripts
  contracts/                 RailgunFactory.sol, IPaladinContractRegistry.sol
  test/                      Hardhat tests for RailgunFactory
  hardhat.config.ts          Hardhat config (compile + test)
  extract-circuits.sh        Assemble circuit artifacts (wasm/zkey/vkey) for tests
  copy-railgun-artifacts.sh  Copy the compiled RailgunSmartWallet + Poseidon artifacts
  build.sh                   Emit the RailgunFactory ABI+bytecode the Go tests embed

integration-test/            Separate Go module: end-to-end tests against a live EVM node
  railgun_e2e_test.go        shield -> transfer -> unshield via Paladin private APIs,
                             with Groth16 proofs verified on-chain
  railgun_test.go            Deploy + register the wallet with the domain
  run-e2e.sh                 One-shot: assemble circuits + run the e2e suite
```

The cryptographic core (`railgunnote`, `railgunprover`, `railguntx`) is validated
against ground-truth vectors generated from the Railgun reference implementation
and against snarkJS using the real circuit verification keys — see
[`domain-impl/internal/railgun/PROVING.md`](domain-impl/internal/railgun/PROVING.md).

## How it works

Railgun's note model is mapped onto Paladin's state store:

- A note is a Paladin state `{ owner (masterPublicKey), random, token, value, leafIndex }`;
  its state id is the Poseidon commitment.
- Spends are detected via Paladin's nullifier mechanism: each note carries a
  `NullifierSpec`, so the owner's node computes `Poseidon(nullifyingKey, leafIndex)`
  and Paladin matches it against on-chain `Nullified` events.
- The on-chain commitment tree is rebuilt from `Shield`/`Transact` events so the
  domain can produce Merkle inclusion proofs when spending.
- `transfer`/`unshield` build the joinsplit witness during assembly and generate
  the Groth16 proof in the signing phase (where the private key is available).

> The real Railgun events carry no Paladin transaction id, so the domain embeds
> it in unvalidated ciphertext fields to correlate on-chain events back to the
> originating private transaction. See `internal/railgun/PROVING.md` and the
> integration-test README for this and other design notes.

## Building and testing

The repo is laid out as two Go modules (`domain-impl/` and `integration-test/`)
plus the `solidity/` artifacts. Both modules sit alongside a Paladin checkout
and reference it via `replace` directives in their `go.mod`.

```bash
# build + unit tests of the domain (proving tests are env-gated; skip without circuits)
cd domain-impl
go build ./...
go test ./...

# proving tests (Go-generated proofs verified by snarkJS against the real vkeys)
scripts/run-proving-tests.sh [path-to-circuits-v2-repo]

# full end-to-end against a live EVM node (see integration-test/README.md)
cd ../integration-test && ./run-e2e.sh [path-to-circuits-v2-repo]

# compile + test the domain's own Solidity (RailgunFactory) with Hardhat
cd ../solidity && npm install && npm test
```

Domain module path: `github.com/LFDT-Paladin/paladin/domains/railgun` (rooted at
`domain-impl/`).

## References

- **Paladin** — [repository](https://github.com/LFDT-Paladin/paladin) ·
  [documentation](https://github.com/LFDT-Paladin/paladin#readme) (see the repo's
  `doc-site/` and architecture docs)
- **Paladin domain toolkit** —
  [`paladin/toolkit`](https://github.com/LFDT-Paladin/paladin/tree/main/toolkit)
  (the `plugintk.DomainAPI` interface this plugin implements)
- **Zeto domain** —
  [`paladin/domains/zeto`](https://github.com/LFDT-Paladin/paladin/tree/main/domains/zeto),
  the reference zk-token domain this implementation draws patterns from
- **Railgun** — [protocol & docs](https://www.railgun.org/) · the RailgunSmartWallet
  contract and the `circuits-v2` joinsplit circuits (Railgun Privacy)

## License

Apache-2.0. See SPDX headers in source files.
