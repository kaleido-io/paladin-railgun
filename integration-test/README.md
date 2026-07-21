# Railgun domain integration test

Integration tests against the RailgunSmartWallet privacy-pool contract:

1. `TestRailgunDeploySuite` — deploy + register the wallet with the domain.
2. `TestRailgunE2ESuite` — the full capability set (shield / transfer / unshield)
   driven through Paladin private APIs, with real Groth16 proofs verified
   on-chain.

## End-to-end test (`TestRailgunE2ESuite`)

Drives the complete lifecycle through Paladin private transactions:

```
shield 100 -> alice        (no proof; ERC-20 deposit)
transfer 30 alice -> bob   (1x2 joinsplit proof, verified on-chain)
unshield 70 alice -> addr  (1x1 joinsplit proof, verified on-chain)
```

Setup performs, as public transactions: deploy Poseidon libs +
RailgunSmartWallet + factory, `initializeRailgunLogic`, `setVerificationKey` for
the 1x1 and 1x2 circuits (from each circuit's `vkey.json`), deploy a `TestERC20`,
mint + approve. Then it registers the wallet with the domain and runs the three
private operations, asserting each succeeds (success of transfer/unshield means
the on-chain verifier accepted the proof) and that shielded balances move
100 → (alice 70, bob 30) → (alice 0).

Run it (needs an EVM node + the two third-party Railgun repos below):

```bash
# defaults to the sibling repos ../circuits-v2 and ../contract
./run-e2e.sh [path-to-circuits-v2-repo] [path-to-contract-repo]
# or manually, with the contract artifacts copied into abis/ (see below) and
# circuits 01x01 + 01x02 assembled into <dir>/<NNxMM>/{wasm,zkey,vkey.json}:
RAILGUN_CIRCUITS_DIR=<dir> go test -v -run TestRailgunE2ESuite ./...
```

> **Third-party materials, not distributed here.** The circuit artifacts and the
> compiled `RailgunSmartWallet`/Poseidon/`TestERC20` contract artifacts come from
> the `Railgun-Privacy/circuits-v2` and `Railgun-Privacy/contract` repositories,
> which are licensed separately from this project. You must clone and build them
> yourself (as siblings of the `paladin-railgun` repo), subject to their licenses;
> the `run-e2e.sh` script is a convenience wrapper over your own checkouts. See the
> [root README](../README.md#third-party-dependencies-and-licensing).

> Notes:
> - Circuit artifacts come from the circuits-v2 repo (`zkeys/` + `build/`),
>   assembled by `../solidity/extract-circuits.sh`.
> - The unshield always emits a change note (zero-value if it consumes the full
>   balance) so it produces a Transact event carrying the tx-id used to correlate
>   the on-chain event back to the private transaction.
> - The leaf-index prediction the domain uses for nullifiers assumes sequential
>   execution (no concurrent transactions inserting between assemble and on-chain
>   confirmation), which holds for this single-node testbed.

## Deploy/register test (`TestRailgunDeploySuite`)

1. **Deploys the real Railgun stack** on-chain (phase 1, throwaway testbed):
   - `PoseidonT3` and `PoseidonT4` hash libraries,
   - `RailgunSmartWallet` (bytecode linked against the two libraries),
   - `RailgunFactory`, configured to register the deployed wallet.
2. **Starts a testbed node** with the Railgun domain registered against the
   factory address (phase 2).
3. **Calls `testbed_deploy`**, which drives the domain's
   `InitDeploy` → `PrepareDeploy` → factory `deploy()` →
   `PaladinRegisterSmartContract_V0` event → domain's `InitContract`.
4. **Asserts** the registered instance address equals the deployed
   `RailgunSmartWallet` — i.e. the real contract was registered with the domain.

## Prerequisites

This test talks to a real EVM node, exactly like the upstream
`paladin/domains/integration-test` suite. Before running:

- An Ethereum JSON-RPC node listening at `http://localhost:8545`
  (ws at `ws://localhost:8546`) — e.g. `anvil` or a Besu dev node. Adjust
  `testbed.config.yaml` if your endpoints differ.
- The compiled Railgun contract artifacts populated into `abis/` (they are
  git-ignored and not distributed here — the module will not even compile
  without them, because they are embedded via `go:embed`). Generate them from
  your own checkout of the third-party [`Railgun-Privacy/contract`](https://github.com/Railgun-Privacy/contract)
  repo (cloned + built as a sibling `../contract`):

  ```bash
  ../solidity/copy-railgun-artifacts.sh [path-to-railgun-contract-repo]  # default ../contract
  ```

  See the [root README](../README.md#third-party-dependencies-and-licensing) —
  these materials are licensed separately and are your responsibility.

## Running

```bash
cd integration-test
../solidity/copy-railgun-artifacts.sh   # populate git-ignored abis/ first (see Prerequisites)
go test -v -run TestRailgunDeploySuite ./...
```

## Contract artifacts (`abis/`)

The Go test embeds these via `go:embed`. Only `RailgunFactory.json` is committed
to this repo; the Railgun-derived artifacts are **git-ignored and not
distributed** — you generate them locally from your own checkout of the Railgun
contract repo (`run-e2e.sh` does this for you).

| Artifact | Source | Committed? |
|----------|--------|------------|
| `RailgunSmartWallet.json`, `PoseidonT3.json`, `PoseidonT4.json`, `TestERC20.json` | Pre-compiled Hardhat artifacts from the third-party [`Railgun-Privacy/contract`](https://github.com/Railgun-Privacy/contract) repo (licensed separately; your responsibility) | No — git-ignored, user-generated |
| `RailgunFactory.json` | Compiled from this repo's Apache-2.0 [`../solidity/contracts/RailgunFactory.sol`](../solidity/contracts/RailgunFactory.sol) | Yes |

Generate / regenerate them with:

```bash
../solidity/copy-railgun-artifacts.sh [path-to-railgun-contract-repo]  # default ../contract
../solidity/build.sh                                                   # factory (needs solc >= 0.8.20, python3)
```
