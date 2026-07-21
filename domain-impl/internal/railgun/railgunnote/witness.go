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

package railgunnote

import (
	"fmt"
	"math/big"
)

// SpendInput is one input note being spent in a transact: the note's random and
// value, its leaf index in the commitment tree, and the Merkle sibling path.
type SpendInput struct {
	Random       *big.Int
	Value        *big.Int
	LeafIndex    int
	PathElements []*big.Int // length MerkleDepth
}

// SpendOutput is one output note being created: the recipient's note public key
// and the value.
type SpendOutput struct {
	NPK   *big.Int
	Value *big.Int
}

// WitnessInputs is everything needed to build a joinsplit circuit witness for a
// single transaction. All inputs/outputs share one token.
type WitnessInputs struct {
	Identity        *Identity
	Token           *big.Int // tokenID (e.g. TokenIDERC20)
	MerkleRoot      *big.Int
	BoundParamsHash *big.Int
	Inputs          []SpendInput
	Outputs         []SpendOutput
}

// Witness is the assembled circuit input (snarkjs/circom format) plus the
// derived public values the caller needs to build the on-chain Transaction.
type Witness struct {
	// Inputs maps each circuit signal name to its decimal-string value(s).
	Inputs map[string]interface{}
	// Nullifiers / CommitmentsOut are the derived public signals.
	Nullifiers     []*big.Int
	CommitmentsOut []*big.Int
}

// BuildWitness derives the nullifiers, output commitments, and spend signature,
// and assembles the full joinsplit witness. The number of inputs/outputs
// determines the circuit (nInputs x nOutputs).
func BuildWitness(w *WitnessInputs) (*Witness, error) {
	if len(w.Inputs) == 0 || len(w.Outputs) == 0 {
		return nil, fmt.Errorf("transact requires at least one input and one output")
	}

	nullifyingKey, err := w.Identity.NullifyingKey()
	if err != nil {
		return nil, err
	}
	pubX, pubY := w.Identity.SpendingPublicKey()

	// Nullifiers for input notes
	nullifiers := make([]*big.Int, len(w.Inputs))
	randomIn := make([]*big.Int, len(w.Inputs))
	valueIn := make([]*big.Int, len(w.Inputs))
	leavesIndices := make([]*big.Int, len(w.Inputs))
	pathElements := make([][]*big.Int, len(w.Inputs))
	for i, in := range w.Inputs {
		if len(in.PathElements) != MerkleDepth {
			return nil, fmt.Errorf("input %d: expected %d path elements, got %d", i, MerkleDepth, len(in.PathElements))
		}
		n, err := Nullifier(nullifyingKey, uint64(in.LeafIndex))
		if err != nil {
			return nil, err
		}
		nullifiers[i] = n
		randomIn[i] = in.Random
		valueIn[i] = in.Value
		leavesIndices[i] = big.NewInt(int64(in.LeafIndex))
		pathElements[i] = in.PathElements
	}

	// Output commitments
	commitmentsOut := make([]*big.Int, len(w.Outputs))
	npkOut := make([]*big.Int, len(w.Outputs))
	valueOut := make([]*big.Int, len(w.Outputs))
	for i, out := range w.Outputs {
		c, err := Commitment(out.NPK, w.Token, out.Value)
		if err != nil {
			return nil, err
		}
		commitmentsOut[i] = c
		npkOut[i] = out.NPK
		valueOut[i] = out.Value
	}

	// Spend signature over the public signals
	sighash, err := SignatureMessage(w.MerkleRoot, w.BoundParamsHash, nullifiers, commitmentsOut)
	if err != nil {
		return nil, err
	}
	r8x, r8y, s := w.Identity.Sign(sighash)

	// Circuit signal values are big.Int (and nested big.Int slices) as expected
	// by the go-rapidsnark witness calculator.
	inputs := map[string]interface{}{
		// Public signals
		"merkleRoot":      reduce(w.MerkleRoot),
		"boundParamsHash": reduce(w.BoundParamsHash),
		"nullifiers":      nullifiers,
		"commitmentsOut":  commitmentsOut,
		// Private signals
		"token":         w.Token,
		"publicKey":     []*big.Int{pubX, pubY},
		"signature":     []*big.Int{r8x, r8y, s},
		"randomIn":      randomIn,
		"valueIn":       valueIn,
		"pathElements":  pathElements,
		"leavesIndices": leavesIndices,
		"nullifyingKey": nullifyingKey,
		"npkOut":        npkOut,
		"valueOut":      valueOut,
	}

	return &Witness{
		Inputs:         inputs,
		Nullifiers:     nullifiers,
		CommitmentsOut: commitmentsOut,
	}, nil
}
