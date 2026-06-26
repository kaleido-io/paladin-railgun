/*
 * Copyright © 2024 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package integrationtest

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	railgun "github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgun"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/solutils"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/require"
)

// The real Railgun privacy-pool contract (RailgunSmartWallet) plus the two
// Poseidon hash libraries it links against, and the thin Paladin registration
// factory. The wallet/library JSON are the Hardhat artifacts from the Railgun
// contract repo (copied via solidity/copy-railgun-artifacts.sh); the factory is
// compiled by solidity/build.sh.
var (
	//go:embed abis/RailgunFactory.json
	railgunFactoryBuildJSON []byte
	//go:embed abis/RailgunSmartWallet.json
	railgunSmartWalletBuildJSON []byte
	//go:embed abis/PoseidonT3.json
	poseidonT3BuildJSON []byte
	//go:embed abis/PoseidonT4.json
	poseidonT4BuildJSON []byte
)

// Fully-qualified library link names as they appear in the RailgunSmartWallet
// artifact's linkReferences.
const (
	poseidonT3LinkName = "contracts/logic/Poseidon.sol:PoseidonT3"
	poseidonT4LinkName = "contracts/logic/Poseidon.sol:PoseidonT4"
)

const controllerName = "controller"

// mapConfig marshals an arbitrary config struct into the map[string]any form
// the testbed expects for a domain's configuration block.
func mapConfig(t *testing.T, config any) (m map[string]any) {
	configJSON, err := json.Marshal(&config)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(configJSON, &m))
	return m
}

// newTestbed starts a testbed node wired up with the supplied domains and
// returns a teardown function plus an RPC client.
func newTestbed(t *testing.T, hdWalletSeed *testbed.UTInitFunction, domains map[string]*testbed.TestbedDomain) (func(), testbed.Testbed, rpcclient.Client) {
	tb := testbed.NewTestBed()
	httpURL, _, _, done, err := tb.StartForTest("./testbed.config.yaml", domains, hdWalletSeed)
	require.NoError(t, err)
	rpc := rpcclient.WrapRestyClient(resty.New().SetBaseURL(httpURL))
	return done, tb, rpc
}

// deployBytecode is a small helper that deploys a contract via the testbed RPC
// and returns its address.
func deployBytecode(ctx context.Context, t *testing.T, rpc rpcclient.Client, deployer string, build *solutils.SolidityBuild, paramsJSON string) *pldtypes.EthAddress {
	var addr pldtypes.EthAddress
	rpcerr := rpc.CallRPC(ctx, &addr, "testbed_deployBytecode",
		deployer, build.ABI, build.Bytecode.String(), pldtypes.RawJSON(paramsJSON))
	require.NoError(t, rpcerr)
	return &addr
}

// deployRailgunContracts deploys, on a throwaway testbed (no domains), the real
// Railgun stack and the Paladin registration factory:
//
//  1. PoseidonT3 and PoseidonT4 hash libraries.
//  2. RailgunSmartWallet, with its bytecode linked against the two libraries.
//  3. RailgunFactory, configured to register the deployed wallet.
//
// It returns the factory address (the domain's registry) and the wallet address
// (the instance that will be registered). The factory must exist before the
// domain testbed starts, because the domain indexes registration events from it.
func deployRailgunContracts(ctx context.Context, t *testing.T, hdWalletSeed *testbed.UTInitFunction, deployer string) (factory, wallet *pldtypes.EthAddress) {
	tb := testbed.NewTestBed()
	httpURL, _, _, done, err := tb.StartForTest("./testbed.config.yaml", map[string]*testbed.TestbedDomain{}, hdWalletSeed)
	require.NoError(t, err)
	defer done()
	rpc := rpcclient.WrapRestyClient(resty.New().SetBaseURL(httpURL))

	// 1. Poseidon libraries (no further links)
	poseidonT3 := deployBytecode(ctx, t, rpc, deployer, solutils.MustLoadBuild(poseidonT3BuildJSON), `{}`)
	poseidonT4 := deployBytecode(ctx, t, rpc, deployer, solutils.MustLoadBuild(poseidonT4BuildJSON), `{}`)

	// 2. RailgunSmartWallet, linking the deployed Poseidon libraries
	libs := map[string]*pldtypes.EthAddress{
		poseidonT3LinkName: poseidonT3,
		poseidonT4LinkName: poseidonT4,
	}
	walletBuild := solutils.MustLoadBuildResolveLinks(railgunSmartWalletBuildJSON, libs)
	wallet = deployBytecode(ctx, t, rpc, deployer, walletBuild, `{}`)

	// 3. RailgunFactory(implementation = wallet)
	factoryBuild := solutils.MustLoadBuild(railgunFactoryBuildJSON)
	factory = deployBytecode(ctx, t, rpc, deployer, factoryBuild,
		fmt.Sprintf(`{"_implementation": "%s"}`, wallet))

	return factory, wallet
}

// newRailgunDomain builds the testbed domain wrapper for the Railgun plugin,
// registered against the given factory address.
func newRailgunDomain(t *testing.T, config *types.DomainFactoryConfig, factoryAddress *pldtypes.EthAddress) (chan plugintk.DomainAPI, *testbed.TestbedDomain) {
	waitForDomain := make(chan plugintk.DomainAPI, 1)
	tbd := &testbed.TestbedDomain{
		Config: mapConfig(t, config),
		Plugin: plugintk.NewDomain(func(callbacks plugintk.DomainCallbacks) plugintk.DomainAPI {
			domain := railgun.New(callbacks)
			waitForDomain <- domain
			return domain
		}),
		RegistryAddress: factoryAddress,
		AllowSigning:    true,
	}
	return waitForDomain, tbd
}
