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
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Identities used in the end-to-end test (all on node1).
const (
	aliceName = "alice@node1"
	bobName   = "bob@node1"
)

// TestRailgunE2ESuite exercises the full Railgun capability set — shield,
// transfer, and unshield — through Paladin private APIs against the real
// RailgunSmartWallet, with real Groth16 proofs verified on-chain.
//
// Requires:
//   - an EVM node reachable per testbed.config.yaml
//   - RAILGUN_CIRCUITS_DIR with circuits 01x01 and 01x02 extracted
//     (solidity/extract-circuits.sh <dir> 01x01 01x02)
func TestRailgunE2ESuite(t *testing.T) {
	if os.Getenv("RAILGUN_CIRCUITS_DIR") == "" {
		t.Skip("set RAILGUN_CIRCUITS_DIR (extract circuits 01x01 01x02) to run the e2e test")
	}
	suite.Run(t, new(railgunE2ETestSuite))
}

type railgunE2ETestSuite struct {
	suite.Suite
	hdWalletSeed   *testbed.UTInitFunction
	circuitsDir    string
	domainName     string
	walletAddress  *pldtypes.EthAddress
	factoryAddress *pldtypes.EthAddress
	instanceAddr   *pldtypes.EthAddress
	erc20Address   *pldtypes.EthAddress
	controllerEth  *pldtypes.EthAddress
	tb             testbed.Testbed
	rpc            rpcclient.Client
	domain         plugintk.DomainAPI
	done           func()
}

func (s *railgunE2ETestSuite) SetupSuite() {
	log.SetLevel("debug")
	ctx := context.Background()
	t := s.T()
	s.hdWalletSeed = testbed.HDWalletSeedScopedToTest()
	s.circuitsDir = os.Getenv("RAILGUN_CIRCUITS_DIR")
	s.domainName = "railgun_" + pldtypes.RandHex(8)

	// Phase 1: deploy the real RailgunSmartWallet (+ Poseidon libs) and factory.
	s.factoryAddress, s.walletAddress = deployRailgunContracts(ctx, t, s.hdWalletSeed, controllerName)

	// Phase 2: start the domain (with proving enabled) registered to the factory.
	waitForDomain, railgunTestbed := newRailgunDomain(t, testDomainConfig(s.circuitsDir), s.factoryAddress)
	done, tb, rpc := newTestbed(t, s.hdWalletSeed, map[string]*testbed.TestbedDomain{s.domainName: railgunTestbed})
	s.done, s.tb, s.rpc = done, tb, rpc
	s.domain = <-waitForDomain

	// Initialise the wallet and register the verification keys for the circuit
	// sizes the test uses (1x2 transfer, 1x1 full unshield).
	s.controllerEth = resolveEthAddress(ctx, t, rpc, controllerName)
	initializeWallet(ctx, t, tb, controllerName, s.walletAddress, s.controllerEth)
	setVerificationKey(ctx, t, tb, controllerName, s.walletAddress, 1, 2, s.readVKey("01x02"))
	setVerificationKey(ctx, t, tb, controllerName, s.walletAddress, 1, 1, s.readVKey("01x01"))

	// Deploy a test ERC-20, fund the controller, and approve the wallet.
	s.erc20Address = deployTestERC20(ctx, t, tb, rpc, controllerName)
	mintERC20(ctx, t, tb, controllerName, s.erc20Address, s.controllerEth, big.NewInt(1_000_000))
	approveERC20(ctx, t, tb, controllerName, s.erc20Address, s.walletAddress, big.NewInt(1_000_000))

	// Register the wallet instance with the domain.
	var instanceAddr pldtypes.EthAddress
	rpcerr := rpc.CallRPC(ctx, &instanceAddr, "testbed_deploy", s.domainName, controllerName, &types.InitializerParams{
		TokenName: tokenName, Name: "Test Railgun", Symbol: "RAIL",
	})
	require.Nil(t, rpcerr)
	require.Equal(t, s.walletAddress.String(), instanceAddr.String())
	s.instanceAddr = &instanceAddr
}

func (s *railgunE2ETestSuite) TearDownSuite() {
	if s.done != nil {
		s.done()
	}
}

func (s *railgunE2ETestSuite) readVKey(circuit string) []byte {
	data, err := os.ReadFile(filepath.Join(s.circuitsDir, circuit, "vkey.json"))
	require.NoError(s.T(), err)
	return data
}

// TestShieldTransferUnshield drives the full lifecycle:
//
//	shield 100 -> alice ; transfer 30 alice -> bob ; unshield 70 alice -> public
//
// Each private operation must succeed, which means the on-chain shield executed
// and the transfer/unshield Groth16 proofs verified against the registered
// verification keys.
func (s *railgunE2ETestSuite) TestShieldTransferUnshield() {
	ctx := context.Background()
	t := s.T()

	// --- shield 100 to alice (controller pays the ERC-20) ---
	railgunInvoke(ctx, t, s.rpc, controllerName, s.instanceAddr, "shield", mustJSON(t, &types.ShieldParams{
		To:    aliceName,
		Token: s.erc20Address,
		Value: hexU(100),
	}))
	require.Equal(t, int64(100), railgunBalance(ctx, t, s.rpc, s.instanceAddr, aliceName).Int64(), "alice shielded balance")

	// --- transfer 30 alice -> bob (1 input, 2 outputs: bob + change) ---
	railgunInvoke(ctx, t, s.rpc, aliceName, s.instanceAddr, "transfer", mustJSON(t, &types.TransferParams{
		Token:     s.erc20Address,
		Transfers: []*types.TransferParamEntry{{To: bobName, Value: hexU(30)}},
	}))
	require.Equal(t, int64(70), railgunBalance(ctx, t, s.rpc, s.instanceAddr, aliceName).Int64(), "alice after transfer")
	require.Equal(t, int64(30), railgunBalance(ctx, t, s.rpc, s.instanceAddr, bobName).Int64(), "bob after transfer")

	// --- unshield alice's full 70 to a public address (1 input, 1 output) ---
	recipient := pldtypes.MustEthAddress("0x00000000000000000000000000000000000000be")
	railgunInvoke(ctx, t, s.rpc, aliceName, s.instanceAddr, "unshield", mustJSON(t, &types.UnshieldParams{
		To:    recipient,
		Token: s.erc20Address,
		Value: hexU(70),
	}))
	require.Equal(t, int64(0), railgunBalance(ctx, t, s.rpc, s.instanceAddr, aliceName).Int64(), "alice after unshield")
}

func hexU(v int64) *pldtypes.HexUint256 {
	return (*pldtypes.HexUint256)(big.NewInt(v))
}

func mustJSON(t *testing.T, v interface{}) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
