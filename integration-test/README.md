# Railgun domain integration test

Integration tests against the **real RailgunSmartWallet** privacy-pool contract:

1. `TestRailgunDeploySuite` — deploy + register the wallet with the domain.
2. `TestRailgunE2ESuite` — the full capability set (shield / transfer / unshield)
   driven through Paladin **private APIs**, with real Groth16 proofs verified
   **on-chain**.

## End-to-end test (`TestRailgunE2ESuite`)

Drives the complete lifecycle through Paladin private transactions:

```
shield 100 -> alice        (no proof; ERC-20 deposit)
transfer 30 alice -> bob   (1x2 joinsplit proof, verified on-chain)
unshield 70 alice -> addr  (1x1 joinsplit proof, verified on-chain)
```

Setup performs, as **public** transactions: deploy Poseidon libs +
RailgunSmartWallet + factory, `initializeRailgunLogic`, `setVerificationKey` for
the 1x1 and 1x2 circuits (from each circuit's `vkey.json`), deploy a `TestERC20`,
mint + approve. Then it registers the wallet with the domain and runs the three
private operations, asserting each succeeds (success of transfer/unshield means
the on-chain verifier accepted the proof) and that shielded balances move
100 → (alice 70, bob 30) → (alice 0).

Run it (needs an EVM node + the Railgun circuits-v2 repo for circuit artifacts):

```bash
./run-e2e.sh [path-to-circuits-v2-repo]   # default ~/workspace.zkp/railgun/circuits-v2
# or manually, with circuits 01x01 + 01x02 assembled into <dir>/<NNxMM>/{wasm,zkey,vkey.json}:
RAILGUN_CIRCUITS_DIR=<dir> go test -v -run TestRailgunE2ESuite ./...
```

> Notes:
> - Circuit artifacts come from the **circuits-v2** repo (`zkeys/` + `build/`),
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

## Running

```bash
cd integration-test
go test -v -run TestRailgunDeploySuite ./...
```

## Contract artifacts (`abis/`)

| Artifact | Source |
|----------|--------|
| `RailgunSmartWallet.json`, `PoseidonT3.json`, `PoseidonT4.json` | Pre-compiled Hardhat artifacts copied from the Railgun contract repo |
| `RailgunFactory.json` | Compiled from `../solidity/contracts/RailgunFactory.sol` |

Regenerate them with:

```bash
../solidity/copy-railgun-artifacts.sh [path-to-railgun-contract-repo]  # real Railgun artifacts
../solidity/build.sh                                                   # factory (needs solc >= 0.8.20, python3)
```
