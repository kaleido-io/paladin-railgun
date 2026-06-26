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

package fungible

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunprover"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguntx"
)

// PayloadInput is one input note in a transact proving payload.
type PayloadInput struct {
	Random       string   `json:"random"`
	Value        string   `json:"value"`
	LeafIndex    uint64   `json:"leafIndex"`
	PathElements []string `json:"pathElements"`
}

// PayloadOutput is one output note (npk + value) in a transact proving payload.
type PayloadOutput struct {
	NPK   string `json:"npk"`
	Value string `json:"value"`
}

// ProvingPayload is the SNARK attestation payload built by a handler's Assemble
// and consumed by the domain's Sign. It carries everything needed to build the
// joinsplit witness and the on-chain Transaction except the spend signature and
// proof, which require the owner's private key (available only in Sign).
type ProvingPayload struct {
	Token        string               `json:"token"`        // circuit tokenID (decimal)
	TokenAddress string               `json:"tokenAddress"` // ERC-20 address (0x)
	MerkleRoot   string               `json:"merkleRoot"`   // decimal
	Inputs       []PayloadInput       `json:"inputs"`
	Outputs      []PayloadOutput      `json:"outputs"`
	BoundParams  railguntx.BoundParams `json:"boundParams"`
	// UnshieldValue is set (non-empty) for unshields; the trailing output is the
	// unshield note.
	UnshieldValue string `json:"unshieldValue,omitempty"`
}

// GenerateTransactionProof builds the joinsplit witness from the payload and the
// owner's private key, generates the Groth16 proof, and returns the fully
// assembled on-chain Transaction (serialised). Invoked from the domain's Sign.
func GenerateTransactionProof(ctx context.Context, prover *railgunprover.Prover, privateKey []byte, payload []byte) ([]byte, error) {
	id, err := railgunnote.IdentityFromSpendingKey(privateKey)
	if err != nil {
		return nil, err
	}
	var p ProvingPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}

	token, err := railgunnote.DecodeField(p.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	root, err := railgunnote.DecodeField(p.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid merkleRoot: %w", err)
	}
	bph, err := railguntx.BoundParamsHash(ctx, &p.BoundParams)
	if err != nil {
		return nil, err
	}

	inputs := make([]railgunnote.SpendInput, len(p.Inputs))
	for i, in := range p.Inputs {
		random, err := railgunnote.DecodeField(in.Random)
		if err != nil {
			return nil, fmt.Errorf("input %d random: %w", i, err)
		}
		value, err := railgunnote.DecodeField(in.Value)
		if err != nil {
			return nil, fmt.Errorf("input %d value: %w", i, err)
		}
		path := make([]*big.Int, len(in.PathElements))
		for j, e := range in.PathElements {
			pv, err := railgunnote.DecodeField(e)
			if err != nil {
				return nil, fmt.Errorf("input %d path %d: %w", i, j, err)
			}
			path[j] = pv
		}
		inputs[i] = railgunnote.SpendInput{Random: random, Value: value, LeafIndex: int(in.LeafIndex), PathElements: path}
	}

	outputs := make([]railgunnote.SpendOutput, len(p.Outputs))
	for i, out := range p.Outputs {
		npk, err := railgunnote.DecodeField(out.NPK)
		if err != nil {
			return nil, fmt.Errorf("output %d npk: %w", i, err)
		}
		value, err := railgunnote.DecodeField(out.Value)
		if err != nil {
			return nil, fmt.Errorf("output %d value: %w", i, err)
		}
		outputs[i] = railgunnote.SpendOutput{NPK: npk, Value: value}
	}

	witness, err := railgunnote.BuildWitness(&railgunnote.WitnessInputs{
		Identity:        id,
		Token:           token,
		MerkleRoot:      root,
		BoundParamsHash: bph,
		Inputs:          inputs,
		Outputs:         outputs,
	})
	if err != nil {
		return nil, err
	}

	circuit := railgunprover.CircuitName(len(inputs), len(outputs))
	proof, err := prover.Prove(ctx, circuit, witness.Inputs)
	if err != nil {
		return nil, err
	}

	tx := &railguntx.Transaction{
		Proof:       railgunprover.FormatProof(proof),
		MerkleRoot:  root.Text(10),
		Nullifiers:  fieldsToDec(witness.Nullifiers),
		Commitments: fieldsToDec(witness.CommitmentsOut),
		BoundParams: &p.BoundParams,
	}
	if p.UnshieldValue != "" {
		var addr [20]byte
		addrBytes, err := railgunnote.DecodeField(p.TokenAddress)
		if err != nil {
			return nil, err
		}
		addrBytes.FillBytes(make([]byte, 32)) // validate
		copy(addr[:], padLeft20(addrBytes))
		tx.UnshieldPreimage = &railguntx.CommitmentPreimage{
			NPK:   p.Outputs[len(p.Outputs)-1].NPK,
			Token: railguntx.TokenData{TokenType: 0, TokenAddress: p.TokenAddress, TokenSubID: "0"},
			Value: p.UnshieldValue,
		}
	}

	return json.Marshal(tx)
}

func fieldsToDec(vs []*big.Int) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Text(10)
	}
	return out
}

func padLeft20(v *big.Int) []byte {
	return v.FillBytes(make([]byte, 20))
}
