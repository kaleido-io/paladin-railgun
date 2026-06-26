// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"context"

	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/domain"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

// DomainFactoryConfig is supplied via the Paladin node configuration and
// points the domain at the deployed Railgun factory contract together with
// the set of available circuit configurations.
type DomainFactoryConfig struct {
	DomainContracts DomainConfigContracts          `json:"domainContracts"`
	SnarkProver     railgunsignerapi.SnarkProverConfig `json:"snarkProver"`
}

// DomainConfigContracts lists the on-chain Railgun token implementations
// that the domain can deploy.
type DomainConfigContracts struct {
	Implementations []*DomainContract `yaml:"implementations"`
}

// DomainContract pairs a human-readable implementation name with the set
// of ZK circuits required to operate it.
type DomainContract struct {
	Name     string                       `yaml:"name"`
	Circuits *railgunsignerapi.Circuits   `yaml:"circuits"`
}

// GetCircuits returns the circuit map for the named token implementation.
func (d *DomainFactoryConfig) GetCircuits(ctx context.Context, tokenName string) (*railgunsignerapi.Circuits, error) {
	for _, contract := range d.DomainContracts.Implementations {
		if contract.Name == tokenName {
			return contract.Circuits, nil
		}
	}
	return nil, nil
}

// DomainInstanceConfig is the per-contract configuration published on-chain
// during deployment so that every Paladin node can reconstruct the domain
// instance from the blockchain alone.
type DomainInstanceConfig struct {
	TokenName string                       `json:"tokenName"`
	Circuits  *railgunsignerapi.Circuits   `json:"circuits"`
}

// DomainInstanceConfigABI is the ABI used to encode/decode DomainInstanceConfig
// on-chain.
var DomainInstanceConfigABI = &abi.ParameterArray{
	{Type: "string", Name: "tokenName"},
	{
		Type: "tuple",
		Name: "circuits",
		Components: []*abi.Parameter{
			{Type: "tuple", Name: "shield",   Components: []*abi.Parameter{{Type: "string", Name: "name"}, {Type: "string", Name: "type"}, {Type: "bool", Name: "usesNullifiers"}}},
			{Type: "tuple", Name: "unshield", Components: []*abi.Parameter{{Type: "string", Name: "name"}, {Type: "string", Name: "type"}, {Type: "bool", Name: "usesNullifiers"}}},
			{Type: "tuple", Name: "transfer", Components: []*abi.Parameter{{Type: "string", Name: "name"}, {Type: "string", Name: "type"}, {Type: "bool", Name: "usesNullifiers"}}},
		},
	},
}

// InitializerParams are the constructor parameters supplied by the Paladin
// client when deploying a new Railgun token instance.
type InitializerParams struct {
	TokenName string `json:"tokenName"`
	Name      string `json:"name"`
	Symbol    string `json:"symbol"`
}

// DeployParams are what the domain submits to the factory contract.
type DeployParams struct {
	TransactionID string            `json:"transactionId"`
	Data          pldtypes.HexBytes `json:"data"`
	TokenName     string            `json:"tokenName"`
	Name          string            `json:"name"`
	Symbol        string            `json:"symbol"`
	InitialOwner  string            `json:"initialOwner"`
}

// Transfer parameter types

type TransferParams struct {
	// Token is the ERC-20 backing the notes being transferred.
	Token     *pldtypes.EthAddress  `json:"token"`
	Transfers []*TransferParamEntry `json:"transfers"`
}

type TransferParamEntry struct {
	To    string               `json:"to"`
	Value *pldtypes.HexUint256 `json:"value"`
	Data  pldtypes.HexBytes    `json:"data"`
}

// ShieldParams deposits `value` of ERC-20 `token` and creates a private note
// owned by `to` (a Railgun master public key resolved from the recipient).
type ShieldParams struct {
	To    string               `json:"to"`
	Token *pldtypes.EthAddress  `json:"token"`
	Value *pldtypes.HexUint256 `json:"value"`
}

// UnshieldParams withdraws `value` of ERC-20 `token` to the public address `to`.
type UnshieldParams struct {
	To    *pldtypes.EthAddress `json:"to"`
	Token *pldtypes.EthAddress `json:"token"`
	Value *pldtypes.HexUint256 `json:"value"`
}

type BalanceOfParam struct {
	Account string `json:"account"`
}

type BalanceOfResult struct {
	TotalBalance *pldtypes.HexUint256 `json:"totalBalance"`
	TotalStates  *pldtypes.HexUint256 `json:"totalStates"`
	Overflow     bool                 `json:"overflow"`
}

// DomainHandler and DomainCallHandler are type aliases using the shared
// Paladin domain helpers with the Railgun-specific config type.
type DomainHandler     = domain.DomainHandler[DomainInstanceConfig]
type DomainCallHandler = domain.DomainCallHandler[DomainInstanceConfig]
type ParsedTransaction = domain.ParsedTransaction[DomainInstanceConfig]
