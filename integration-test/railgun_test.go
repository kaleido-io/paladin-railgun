/*
 * Copyright © 2026 Kaleido, Inc.
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
	"testing"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// tokenName is the name of the Railgun token implementation registered in the
// domain config and used when deploying an instance.
const tokenName = "Railgun"

func TestRailgunDeploySuite(t *testing.T) {
	suite.Run(t, new(railgunDeployTestSuite))
}

type railgunDeployTestSuite struct {
	suite.Suite
	hdWalletSeed   *testbed.UTInitFunction
	domainName     string
	factoryAddress *pldtypes.EthAddress
	walletAddress  *pldtypes.EthAddress
	domain         plugintk.DomainAPI
	rpc            rpcclient.Client
	done           func()
}

// testDomainConfig builds a Railgun domain config with a single token
// implementation and its three circuits. circuitsDir (when non-empty) enables
// proving — the directory holds the joinsplit circuit artifacts laid out as
// <dir>/<NNxMM>/{wasm,zkey}.
func testDomainConfig(circuitsDir string) *types.DomainFactoryConfig {
	return &types.DomainFactoryConfig{
		DomainContracts: types.DomainConfigContracts{
			Implementations: []*types.DomainContract{
				{
					Name: tokenName,
					Circuits: &railgunsignerapi.Circuits{
						"shield":   {Name: "shield"},
						"unshield": {Name: "unshield"},
						"transfer": {Name: "transfer"},
					},
				},
			},
		},
		SnarkProver: railgunsignerapi.SnarkProverConfig{
			CircuitsDir: circuitsDir,
		},
	}
}

func (s *railgunDeployTestSuite) SetupSuite() {
	log.SetLevel("debug")
	ctx := context.Background()
	s.hdWalletSeed = testbed.HDWalletSeedScopedToTest()
	s.domainName = "railgun_" + pldtypes.RandHex(8)
	log.L(ctx).Infof("Domain name = %s", s.domainName)

	// Phase 1: deploy the real RailgunSmartWallet (+ Poseidon libraries) and the
	// Paladin registration factory on-chain.
	s.factoryAddress, s.walletAddress = deployRailgunContracts(ctx, s.T(), s.hdWalletSeed, controllerName)
	log.L(ctx).Infof("RailgunSmartWallet deployed to %s", s.walletAddress)
	log.L(ctx).Infof("RailgunFactory deployed to %s", s.factoryAddress)

	// Phase 2: start a testbed node with the Railgun domain registered against
	// the factory address.
	waitForDomain, railgunTestbed := newRailgunDomain(s.T(), testDomainConfig(""), s.factoryAddress)
	done, _, rpc := newTestbed(s.T(), s.hdWalletSeed, map[string]*testbed.TestbedDomain{
		s.domainName: railgunTestbed,
	})
	s.done = done
	s.rpc = rpc
	s.domain = <-waitForDomain
}

func (s *railgunDeployTestSuite) TearDownSuite() {
	if s.done != nil {
		s.done()
	}
}

// TestDeployAndRegister registers the real RailgunSmartWallet with the domain
// through the factory and confirms the testbed returns the registered instance
// address (i.e. the wallet the factory announced).
func (s *railgunDeployTestSuite) TestDeployAndRegister() {
	ctx := context.Background()
	t := s.T()

	var instanceAddr pldtypes.EthAddress
	rpcerr := s.rpc.CallRPC(ctx, &instanceAddr, "testbed_deploy",
		s.domainName, controllerName, &types.InitializerParams{
			TokenName: tokenName,
			Name:      "Test Railgun",
			Symbol:    "RAIL",
		})
	require.NoError(t, rpcerr)

	// The factory emitted PaladinRegisterSmartContract_V0 pointing at the real
	// RailgunSmartWallet, which the domain indexed and accepted via InitContract.
	require.False(t, instanceAddr.IsZero(), "expected a non-zero registered instance address")
	require.Equal(t, s.walletAddress.String(), instanceAddr.String(),
		"registered instance should be the deployed RailgunSmartWallet")
	log.L(ctx).Infof("RailgunSmartWallet registered with domain at %s", instanceAddr)
}
