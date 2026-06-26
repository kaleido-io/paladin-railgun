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
	"math/big"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/solutils"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/algorithms"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/require"
)

//go:embed abis/TestERC20.json
var testERC20BuildJSON []byte

// resolveEthAddress resolves a Paladin identity to its ECDSA/ETH address.
func resolveEthAddress(ctx context.Context, t *testing.T, rpc rpcclient.Client, name string) *pldtypes.EthAddress {
	var addr string
	rpcerr := rpc.CallRPC(ctx, &addr, "testbed_resolveVerifier", name, algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
	require.Nil(t, rpcerr)
	return pldtypes.MustEthAddress(addr)
}

// resolveMpk resolves a Paladin identity to its Railgun masterPublicKey (address).
func resolveMpk(ctx context.Context, t *testing.T, rpc rpcclient.Client, domainName, name string) string {
	var mpk string
	rpcerr := rpc.CallRPC(ctx, &mpk, "testbed_resolveVerifier", name,
		railgunsignerapi.AlgoDomainRailgunSnarkBJJ(domainName), railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY)
	require.Nil(t, rpcerr)
	return mpk
}

// -----------------------------------------------------------------------
// Public RailgunSmartWallet setup (initialize + verification keys)
// -----------------------------------------------------------------------

// initializeWallet calls initializeRailgunLogic(treasury, 0, 0, 0, owner) — fees
// are zero so shield/unshield move the full value.
func initializeWallet(ctx context.Context, t *testing.T, tb testbed.Testbed, sender string, wallet *pldtypes.EthAddress, owner *pldtypes.EthAddress) {
	params, _ := json.Marshal(map[string]interface{}{
		"_treasury":    owner.String(),
		"_shieldFee":   "0",
		"_unshieldFee": "0",
		"_nftFee":      "0",
		"_owner":       owner.String(),
	})
	_, err := tb.ExecTransactionSync(ctx, &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			Type:     pldapi.TransactionTypePublic.Enum(),
			From:     sender,
			To:       wallet,
			Function: "initializeRailgunLogic",
			Data:     params,
		},
		ABI: solutils.MustParseBuildABI(railgunSmartWalletBuildJSON),
	})
	require.NoError(t, err)
}

// setVerificationKey registers a circuit's verifying key (from its snarkjs
// vkey.json) so the on-chain verifier can check transact proofs of that size.
func setVerificationKey(ctx context.Context, t *testing.T, tb testbed.Testbed, sender string, wallet *pldtypes.EthAddress, nIn, nOut int, vkeyJSON []byte) {
	params, _ := json.Marshal(map[string]interface{}{
		"_nullifiers":   nIn,
		"_commitments":  nOut,
		"_verifyingKey": vkParams(t, vkeyJSON),
	})
	_, err := tb.ExecTransactionSync(ctx, &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			Type:     pldapi.TransactionTypePublic.Enum(),
			From:     sender,
			To:       wallet,
			Function: "setVerificationKey",
			Data:     params,
		},
		ABI: solutils.MustParseBuildABI(railgunSmartWalletBuildJSON),
	})
	require.NoError(t, err)
}

// vkParams converts a snarkjs vkey.json into the contract's VerifyingKey tuple.
// G2 point coordinates are swapped (snarkjs [c0,c1] -> solidity [c1,c0]),
// matching the Railgun reference formatVKey.
func vkParams(t *testing.T, vkeyJSON []byte) map[string]interface{} {
	var vk struct {
		Alpha1 []string   `json:"vk_alpha_1"`
		Beta2  [][]string `json:"vk_beta_2"`
		Gamma2 [][]string `json:"vk_gamma_2"`
		Delta2 [][]string `json:"vk_delta_2"`
		IC     [][]string `json:"IC"`
	}
	require.NoError(t, json.Unmarshal(vkeyJSON, &vk))
	g2 := func(p [][]string) map[string]interface{} {
		return map[string]interface{}{
			"x": []string{p[0][1], p[0][0]},
			"y": []string{p[1][1], p[1][0]},
		}
	}
	ic := make([]map[string]interface{}, len(vk.IC))
	for i, p := range vk.IC {
		ic[i] = map[string]interface{}{"x": p[0], "y": p[1]}
	}
	return map[string]interface{}{
		"artifactsIPFSHash": "",
		"alpha1":            map[string]interface{}{"x": vk.Alpha1[0], "y": vk.Alpha1[1]},
		"beta2":             g2(vk.Beta2),
		"gamma2":            g2(vk.Gamma2),
		"delta2":            g2(vk.Delta2),
		"ic":                ic,
	}
}

// -----------------------------------------------------------------------
// Test ERC-20
// -----------------------------------------------------------------------

func deployTestERC20(ctx context.Context, t *testing.T, tb testbed.Testbed, rpc rpcclient.Client, deployer string) *pldtypes.EthAddress {
	build := solutils.MustLoadBuild(testERC20BuildJSON)
	var addr pldtypes.EthAddress
	rpcerr := rpc.CallRPC(ctx, &addr, "testbed_deployBytecode", deployer, build.ABI, build.Bytecode.String(), pldtypes.RawJSON(`{}`))
	require.Nil(t, rpcerr)
	return &addr
}

func mintERC20(ctx context.Context, t *testing.T, tb testbed.Testbed, sender string, erc20 *pldtypes.EthAddress, to *pldtypes.EthAddress, amount *big.Int) {
	params, _ := json.Marshal(map[string]interface{}{"_account": to.String(), "_amount": amount.String()})
	_, err := tb.ExecTransactionSync(ctx, &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{Type: pldapi.TransactionTypePublic.Enum(), From: sender, To: erc20, Function: "mint", Data: params},
		ABI:             solutils.MustParseBuildABI(testERC20BuildJSON),
	})
	require.NoError(t, err)
}

func approveERC20(ctx context.Context, t *testing.T, tb testbed.Testbed, sender string, erc20, spender *pldtypes.EthAddress, amount *big.Int) {
	params, _ := json.Marshal(map[string]interface{}{"spender": spender.String(), "amount": amount.String()})
	_, err := tb.ExecTransactionSync(ctx, &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{Type: pldapi.TransactionTypePublic.Enum(), From: sender, To: erc20, Function: "approve", Data: params},
		ABI:             solutils.MustParseBuildABI(testERC20BuildJSON),
	})
	require.NoError(t, err)
}

// -----------------------------------------------------------------------
// Private Railgun operations (via testbed_invoke)
// -----------------------------------------------------------------------

func railgunInvoke(ctx context.Context, t *testing.T, rpc rpcclient.Client, from string, instance *pldtypes.EthAddress, function string, data []byte) {
	rpcerr := rpc.CallRPC(ctx, nil, "testbed_invoke", &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{From: from, To: instance, Function: function, Data: data},
		ABI:             types.RailgunABI,
	}, true)
	require.Nil(t, rpcerr, "private %s must succeed (on-chain proof verified)", function)
}

// railgunBalance queries the domain's balanceOf call for an account.
func railgunBalance(ctx context.Context, t *testing.T, rpc rpcclient.Client, instance *pldtypes.EthAddress, account string) *big.Int {
	params, _ := json.Marshal(map[string]interface{}{"account": account})
	var raw pldtypes.RawJSON
	rpcerr := rpc.CallRPC(ctx, &raw, "testbed_call", &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{To: instance, Function: "balanceOf", Data: params},
		ABI:             types.RailgunABI,
	}, pldtypes.JSONFormatOptions(""))
	require.Nil(t, rpcerr)
	var result struct {
		TotalBalance *pldtypes.HexUint256 `json:"totalBalance"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	if result.TotalBalance == nil {
		return big.NewInt(0)
	}
	return result.TotalBalance.Int()
}
