// Copyright © 2026 Kaleido, Inc.
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

// Package railguntx assembles complete, on-chain-valid RailgunSmartWallet
// calldata (shield / transact / unshield) from the validated note-crypto and
// proving primitives. The boundParamsHash matches the contract's
// keccak256(abi.encode(BoundParams)) % SNARK_SCALAR_FIELD.
package railguntx

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"golang.org/x/crypto/sha3"
)

// UnshieldType enum (Globals.sol).
const (
	UnshieldNone   uint8 = 0
	UnshieldNormal uint8 = 1
)

// CommitmentCiphertext mirrors struct CommitmentCiphertext.
type CommitmentCiphertext struct {
	Ciphertext                [4]string `json:"ciphertext"`                // bytes32[4]
	BlindedSenderViewingKey   string    `json:"blindedSenderViewingKey"`   // bytes32
	BlindedReceiverViewingKey string    `json:"blindedReceiverViewingKey"` // bytes32
	AnnotationData            string    `json:"annotationData"`            // bytes
	Memo                      string    `json:"memo"`                      // bytes
}

// BoundParams mirrors struct BoundParams.
type BoundParams struct {
	TreeNumber           uint16                 `json:"treeNumber"`
	MinGasPrice          string                 `json:"minGasPrice"` // uint72
	Unshield             uint8                  `json:"unshield"`
	ChainID              string                 `json:"chainID"` // uint64
	AdaptContract        string                 `json:"adaptContract"`
	AdaptParams          string                 `json:"adaptParams"`
	CommitmentCiphertext []CommitmentCiphertext `json:"commitmentCiphertext"`
}

// boundParamsABI is the single-tuple parameter list used to ABI-encode the
// BoundParams exactly as the contract's hashBoundParams does. uint sizes are
// irrelevant to abi.encode (all padded to 32 bytes); we mirror the struct.
var boundParamsABI = &abi.ParameterArray{
	{
		Name: "boundParams", Type: "tuple",
		Components: abi.ParameterArray{
			{Name: "treeNumber", Type: "uint16"},
			{Name: "minGasPrice", Type: "uint72"},
			{Name: "unshield", Type: "uint8"},
			{Name: "chainID", Type: "uint64"},
			{Name: "adaptContract", Type: "address"},
			{Name: "adaptParams", Type: "bytes32"},
			{
				Name: "commitmentCiphertext", Type: "tuple[]",
				Components: abi.ParameterArray{
					{Name: "ciphertext", Type: "bytes32[4]"},
					{Name: "blindedSenderViewingKey", Type: "bytes32"},
					{Name: "blindedReceiverViewingKey", Type: "bytes32"},
					{Name: "annotationData", Type: "bytes"},
					{Name: "memo", Type: "bytes"},
				},
			},
		},
	},
}

// BoundParamsHash computes keccak256(abi.encode(boundParams)) % SNARK_SCALAR_FIELD.
func BoundParamsHash(ctx context.Context, bp *BoundParams) (*big.Int, error) {
	valuesJSON, err := json.Marshal([]interface{}{bp})
	if err != nil {
		return nil, err
	}
	encoded, err := boundParamsABI.EncodeABIDataJSONCtx(ctx, valuesJSON)
	if err != nil {
		return nil, err
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(encoded)
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), railgunnote.SnarkScalarField), nil
}
