# Paladin Railgun Domain

A [LFDT Paladin](https://github.com/LFDT-Paladin/paladin) domain plugin that
demonstrates how to implement a ZKP-based token protocol using the
[Railgun](https://www.railgun.org/) privacy protocol.

> **Demonstration only.** Do not use in production.

Paladin is a modular framework for privacy-preserving digital assets on EVM
blockchains. A *domain* is a pluggable extension (implementing
`plugintk.DomainAPI`) that teaches Paladin how to assemble, prove, submit, and
index a particular class of private transactions.

This repository implements a domain for Railgun: a zk-SNARK shielded-pool
protocol where value is held in Poseidon-commitment notes inside an on-chain
Merkle tree, and spends are authorized by Groth16 proofs and nullifiers — without
revealing amounts, owners, or which notes were spent.

The domain targets the `RailgunSmartWallet` contract and the Railgun
joinsplit circuits. Notes, nullifiers, the commitment tree, the spend witness,
and the Groth16 proof are all generated in Go and accepted by the on-chain
verifier.

> **Third-party Railgun materials are not included.** The ZKP circuit artifacts,
> the `RailgunSmartWallet` contract, and its Poseidon libraries are not
> packaged in this repo and are licensed separately. You must obtain and
> build them yourself, subject to their own licenses. See
> [Third-party dependencies and licensing](#third-party-dependencies-and-licensing).

## Capabilities

Exposed as Paladin private transactions — the user submits the receiver and
amount; the domain handles the cryptography:

| Operation   | Description                                                | On-chain call |
|-------------|------------------------------------------------------------|---------------|
| `shield`    | Deposit ERC-20 tokens; mint a private note for a recipient | `shield(ShieldRequest[])` (no proof) |
| `transfer`  | Spend notes; create new notes for recipients (+ change)    | `transact(Transaction[])` (Groth16 proof) |
| `unshield`  | Burn notes to withdraw ERC-20 to a public address          | `transact(Transaction[])` with unshield (Groth16 proof) |
| `balanceOf` | Read the shielded balance of an account (domain call)      | — |

## How it works

Railgun's note model is mapped onto Paladin's state store:

- A note is Paladin state `{ owner (masterPublicKey), random, token, value, leafIndex }`;
  its state id is the Poseidon commitment.
- Spends are detected via Paladin's nullifier mechanism: each note carries a
  `NullifierSpec`, so the owner's node computes
  `Poseidon(nullifyingKey, leafIndex)` and Paladin matches it against on-chain
  `Nullified` events.
- The on-chain commitment tree is rebuilt from `Shield`/`Transact` events so the
  domain can produce Merkle inclusion proofs when spending.
- `transfer` and `unshield` build the joinsplit witness during assembly and
  generate the Groth16 proof in the signing phase (where the private key is
  available).

> Real Railgun events carry no Paladin transaction id, so the domain embeds it in
> unvalidated ciphertext fields to correlate on-chain events back to the
> originating private transaction. See
> [`domain-impl/internal/railgun/PROVING.md`](domain-impl/internal/railgun/PROVING.md)
> and [`integration-test/README.md`](integration-test/README.md) for this and
> other design notes.

## Code structure

```
domain-impl/                 Domain Go module (github.com/LFDT-Paladin/paladin/domains/railgun)
  pkg/                       Public API and shared types
    railgun/                 Entry point: New(callbacks) → plugintk.DomainAPI
    types/                   Note / tree-leaf state schemas, config, IRailgun ABI, receipts
    railgunsignerapi/        Signing algorithm constants; nullifier + masterPublicKey derivation
  internal/railgun/          Domain implementation
    railgun.go               plugintk.DomainAPI: configure, deploy, transaction lifecycle,
                             GetVerifier (masterPublicKey), Sign (nullifier + Groth16 proof)
    handler_events.go        HandleEventBatch: Shield/Transact/Unshield/Nullified → state updates
    events.go / events_abi.go  RailgunSmartWallet event ABIs and decoders
    receipts.go, stubs.go    Domain receipt builder; unsupported DomainAPI stubs
    fungible/                Per-operation handlers (shield, transfer, unshield, balanceOf),
                             note/tree state helpers, on-chain calldata assembly
    railgunnote/             Note cryptography — keys, npk, commitment, nullifier,
                             EdDSA-Poseidon spend signature, depth-16 Poseidon Merkle tree,
                             joinsplit witness builder (validated against reference vectors)
    railguncrypto/           Note ciphertext encryption/decryption (ECDH, blinding, symmetric)
    railgunprover/           Groth16 proving via go-rapidsnark (witness calc + prover)
    railguntx/               boundParamsHash and full transact() calldata assembly
    PROVING.md               How the proving stack works and how to run its tests
  scripts/run-proving-tests.sh  Assemble circuits and run the Go proving tests

solidity/                    Hardhat project for domain Solidity and helper scripts
  contracts/                 RailgunFactory.sol, IPaladinContractRegistry.sol
  test/                      Hardhat tests for RailgunFactory
  hardhat.config.ts          Hardhat config (compile + test)
  extract-circuits.sh        Assemble circuit artifacts (wasm/zkey/vkey) for tests
  copy-railgun-artifacts.sh  Copy compiled RailgunSmartWallet + Poseidon artifacts
  build.sh                   Emit RailgunFactory ABI+bytecode embedded by Go tests

integration-test/            Separate Go module: end-to-end tests against a live EVM node
  railgun_e2e_test.go        shield → transfer → unshield via Paladin private APIs,
                             with Groth16 proofs verified on-chain
  railgun_receive_test.go    External 0zk wallet receives and decrypts from on-chain data
  railgun_test.go            Deploy and register the wallet with the domain
  run-e2e.sh                 One-shot: assemble circuits and run the e2e suite
```

The cryptographic core (`railgunnote`, `railguncrypto`, `railgunprover`,
`railguntx`) is validated against ground-truth vectors from the Railgun reference
implementation and against snarkJS using the real circuit verification keys — see
[`domain-impl/internal/railgun/PROVING.md`](domain-impl/internal/railgun/PROVING.md).

## Prerequisites

The Go domain module (`domain-impl/`) builds and unit-tests with only the first
two rows below. The remaining rows are needed only for the convenience test
scripts, and pull in third-party repositories that you must clone yourself as
**siblings of this repo** — see
[Third-party dependencies and licensing](#third-party-dependencies-and-licensing).

| Requirement | Used for |
|-------------|----------|
| [Paladin](https://github.com/LFDT-Paladin/paladin) checkout as a sibling directory (`../paladin` relative to this repo) | Both Go modules resolve Paladin packages via `replace` directives in their `go.mod` |
| Go 1.24+ | Domain and integration-test modules |
| [`Railgun-Privacy/circuits-v2`](https://github.com/Railgun-Privacy/circuits-v2) cloned + built at `../circuits-v2` | Proving tests and e2e tests (circuit wasm/zkey/vkey artifacts) |
| [`Railgun-Privacy/contract`](https://github.com/Railgun-Privacy/contract) cloned + built at `../contract` | e2e tests (compiled `RailgunSmartWallet`, Poseidon libs, `TestERC20`) |
| EVM JSON-RPC node at `http://localhost:8545` | Integration tests ([`integration-test/README.md`](integration-test/README.md)) |
| Node.js + npm | Hardhat compile/test in `solidity/` |

## Building and testing

The repo contains two Go modules (`domain-impl/` and `integration-test/`) plus
the `solidity/` Hardhat project.

The `domain-impl/` build and its unit tests need **no third-party Railgun
materials**. The proving tests and the end-to-end integration test do — and those
scripts are provided **for convenience only** (see
[Third-party dependencies and licensing](#third-party-dependencies-and-licensing)).
They assume the third-party repos are cloned as siblings of this repo:

```
<parent>/
├── paladin-railgun/   ← this repo
├── paladin/           ← github.com/LFDT-Paladin/paladin
├── circuits-v2/       ← github.com/Railgun-Privacy/circuits-v2 (cloned + built by you)
└── contract/          ← github.com/Railgun-Privacy/contract    (cloned + built by you)
```

```bash
# Domain: build + unit tests (proving tests are env-gated; skipped without circuits)
cd domain-impl
go build ./...
go test ./...

# Proving tests — Go-generated proofs verified by snarkJS against real vkeys
#   (needs ../circuits-v2 built; override the path with an argument)
scripts/run-proving-tests.sh [path-to-circuits-v2-repo]

# End-to-end against a live EVM node (see integration-test/README.md)
#   (needs ../circuits-v2 and ../contract built; override paths with arguments)
cd ../integration-test && ./run-e2e.sh [path-to-circuits-v2-repo] [path-to-contract-repo]

# Domain Solidity (RailgunFactory) via Hardhat
cd ../solidity && npm install && npm test
```

When no path is given, the helper scripts default to the sibling directories
`../circuits-v2` and `../contract`. They assemble circuit artifacts via
`solidity/extract-circuits.sh` into a temporary directory (setting
`RAILGUN_CIRCUITS_DIR`), and the e2e script copies the compiled contract
artifacts into place via `solidity/copy-railgun-artifacts.sh`.

Domain module path: `github.com/LFDT-Paladin/paladin/domains/railgun` (rooted at
`domain-impl/`).

## References

- **Paladin** — [repository](https://github.com/LFDT-Paladin/paladin) ·
  [documentation](https://github.com/LFDT-Paladin/paladin#readme) (see `doc-site/`
  and architecture docs in the repo)
- **Paladin domain toolkit** —
  [`paladin/toolkit`](https://github.com/LFDT-Paladin/paladin/tree/main/toolkit)
  (`plugintk.DomainAPI`, the interface this plugin implements)
- **Zeto domain** —
  [`paladin/domains/zeto`](https://github.com/LFDT-Paladin/paladin/tree/main/domains/zeto),
  the reference zk-token domain this implementation draws patterns from
- **Railgun** — [protocol & docs](https://www.railgun.org/) · the RailgunSmartWallet
  contract and the `circuits-v2` joinsplit circuits (Railgun Privacy)

## Third-party dependencies and licensing

This repository — all Go code under `domain-impl/` and `integration-test/`, and
the Solidity under `solidity/contracts/` — is licensed under **Apache-2.0** (see
[`LICENSE`](LICENSE) and the SPDX headers in source files).

It does not contain, vendor, or distribute any Railgun source, compiled
contract artifacts, or circuit artifacts. Those are **third-party materials
governed by their own licenses, which are not Apache-2.0 and may not be
compatible with it.** Obtaining, building, and using them is **entirely your own
responsibility**, and your use is subject to the upstream licenses:

| Third-party dependency | Upstream | Needed for |
|------------------------|----------|------------|
| ZKP circuit artifacts (`wasm`/`zkey`/`vkey`) | [`Railgun-Privacy/circuits-v2`](https://github.com/Railgun-Privacy/circuits-v2) | Proving tests, e2e test |
| `RailgunSmartWallet` + Poseidon libraries + `TestERC20` (compiled Hardhat artifacts) | [`Railgun-Privacy/contract`](https://github.com/Railgun-Privacy/contract) | e2e test |

The scripts under `solidity/` and the `run-*.sh` scripts (`extract-circuits.sh`,
`copy-railgun-artifacts.sh`, `run-proving-tests.sh`, `run-e2e.sh`) are provided
for convenience only. They do nothing more than read from a checkout of the
above repositories that you have cloned (as siblings of this repo) and built,
and copy the resulting artifacts into git-ignored locations. Any artifacts they
produce locally are excluded from version control (see [`.gitignore`](.gitignore))
and must never be committed to this repository.

The cross-implementation known-answer test vectors under
`domain-impl/internal/railgun/railgunnote/testdata/vectors.json` and
`domain-impl/internal/railgun/railguncrypto/testdata/engine_vectors.json` are
numeric fixtures generated from the Railgun reference implementation (the
`@railgun-community/engine` package and Railgun TS helpers) to validate this
project's independent Go implementation. They contain no Railgun source code; the
generator (`railguncrypto/testdata/gen_fixtures.js`) requires you to supply the
Railgun engine yourself and is not run as part of the normal build.

`RailgunFactory.json` under `integration-test/abis/` is the only compiled artifact
committed here; it is built from this repo's own Apache-2.0
[`solidity/contracts/RailgunFactory.sol`](solidity/contracts/RailgunFactory.sol).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and the SPDX headers in source files. This
license covers only the contents of this repository; see
[Third-party dependencies and licensing](#third-party-dependencies-and-licensing)
for materials that are not part of it.
