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

package railguntx

import (
	"context"
	"fmt"
	"math/big"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunprover"
)

// SpendNote is an input note being spent: its secret random + value and its
// position (leaf index) in the commitment tree.
type SpendNote struct {
	Random    *big.Int
	Value     *big.Int
	LeafIndex int
}

// OutNote is an output note: the recipient's note public key (npk) and value.
// For an unshield output, NPK is the recipient ETH address as a field element
// (uint256(uint160(address))) — see UnshieldNPK.
type OutNote struct {
	NPK   *big.Int
	Value *big.Int
}

// UnshieldNPK encodes a recipient ETH address as the note public key used for an
// unshield output, matching the contract's transferTokenOut
// (address = uint160(uint256(npk))).
func UnshieldNPK(addr [20]byte) *big.Int {
	return new(big.Int).SetBytes(addr[:])
}

// SnarkProof is the Groth16 proof in the contract's SnarkProof tuple shape.
type SnarkProof = railgunprover.SolidityProof

// Transaction is the fully-assembled calldata for RailgunSmartWallet.transact,
// with field elements rendered as decimal strings (ready for ABI encoding).
type Transaction struct {
	Proof            *SnarkProof
	MerkleRoot       string
	Nullifiers       []string
	Commitments      []string
	BoundParams      *BoundParams
	UnshieldPreimage *CommitmentPreimage
}

// CommitmentPreimage mirrors struct CommitmentPreimage for the on-chain
// unshield output.
type CommitmentPreimage struct {
	NPK   string
	Token TokenData
	Value string
}

// TokenData mirrors struct TokenData (ERC-20 only here).
type TokenData struct {
	TokenType    uint8
	TokenAddress string
	TokenSubID   string
}

// TransactBuild is the full input to BuildTransact.
type TransactBuild struct {
	Spender      *railgunnote.Identity
	Token        *big.Int               // tokenID (circuit "token")
	TokenAddress [20]byte               // ERC-20 address for the unshield preimage
	Tree         *railgunnote.MerkleTree // tree to read root + sibling paths from
	Inputs       []SpendNote
	Outputs      []OutNote // all circuit outputs; for unshield, the unshield note is last
	BoundParams  *BoundParams
	// UnshieldValue is set (non-nil) when BoundParams.Unshield != UnshieldNone;
	// it is the value of the trailing unshield output note.
	UnshieldValue *big.Int
}

// BuildTransact assembles a complete, on-chain-valid transact() Transaction:
// it reads the Merkle root and sibling paths from the tree, computes the
// boundParamsHash, builds the joinsplit witness, generates the Groth16 proof,
// and returns the Transaction calldata.
func BuildTransact(ctx context.Context, p *railgunprover.Prover, in *TransactBuild) (*Transaction, *railgunnote.Witness, error) {
	if len(in.Inputs) == 0 || len(in.Outputs) == 0 {
		return nil, nil, fmt.Errorf("transact requires at least one input and one output")
	}

	root := in.Tree.Root()
	bph, err := BoundParamsHash(ctx, in.BoundParams)
	if err != nil {
		return nil, nil, err
	}

	// Resolve Merkle sibling paths for the inputs.
	spendInputs := make([]railgunnote.SpendInput, len(in.Inputs))
	for i, n := range in.Inputs {
		spendInputs[i] = railgunnote.SpendInput{
			Random:       n.Random,
			Value:        n.Value,
			LeafIndex:    n.LeafIndex,
			PathElements: in.Tree.Proof(n.LeafIndex),
		}
	}
	spendOutputs := make([]railgunnote.SpendOutput, len(in.Outputs))
	for i, o := range in.Outputs {
		spendOutputs[i] = railgunnote.SpendOutput{NPK: o.NPK, Value: o.Value}
	}

	witness, err := railgunnote.BuildWitness(&railgunnote.WitnessInputs{
		Identity:        in.Spender,
		Token:           in.Token,
		MerkleRoot:      root,
		BoundParamsHash: bph,
		Inputs:          spendInputs,
		Outputs:         spendOutputs,
	})
	if err != nil {
		return nil, nil, err
	}

	circuit := railgunprover.CircuitName(len(in.Inputs), len(in.Outputs))
	proof, err := p.Prove(ctx, circuit, witness.Inputs)
	if err != nil {
		return nil, nil, err
	}

	tx := &Transaction{
		Proof:       railgunprover.FormatProof(proof),
		MerkleRoot:  bigToBytes32Dec(root),
		Nullifiers:  bigSliceToBytes32Dec(witness.Nullifiers),
		Commitments: bigSliceToBytes32Dec(witness.CommitmentsOut),
		BoundParams: in.BoundParams,
	}

	if in.BoundParams.Unshield != UnshieldNone {
		if in.UnshieldValue == nil {
			return nil, nil, fmt.Errorf("unshield transact requires UnshieldValue")
		}
		// The trailing output is the unshield note; its preimage must hash to the
		// last commitment (the contract re-checks this).
		tx.UnshieldPreimage = &CommitmentPreimage{
			NPK: in.Outputs[len(in.Outputs)-1].NPK.Text(10),
			Token: TokenData{
				TokenType:    0, // ERC20
				TokenAddress: addrHex(in.TokenAddress),
				TokenSubID:   "0",
			},
			Value: in.UnshieldValue.Text(10),
		}
	}

	return tx, witness, nil
}

// ABIObject renders the Transaction as the JSON object expected by the on-chain
// transact(Transaction[]) ABI (field names + bytes32 hex). Use within
// {"_transactions": [tx.ABIObject()]}.
func (t *Transaction) ABIObject() map[string]interface{} {
	preimage := t.UnshieldPreimage
	if preimage == nil {
		preimage = emptyOnChainPreimage()
	}
	return map[string]interface{}{
		"proof": map[string]interface{}{
			"a": map[string]interface{}{"x": t.Proof.A[0], "y": t.Proof.A[1]},
			"b": map[string]interface{}{
				"x": []string{t.Proof.B[0][0], t.Proof.B[0][1]},
				"y": []string{t.Proof.B[1][0], t.Proof.B[1][1]},
			},
			"c": map[string]interface{}{"x": t.Proof.C[0], "y": t.Proof.C[1]},
		},
		"merkleRoot":  decToBytes32(t.MerkleRoot),
		"nullifiers":  decListToBytes32(t.Nullifiers),
		"commitments": decListToBytes32(t.Commitments),
		"boundParams": t.BoundParams,
		"unshieldPreimage": map[string]interface{}{
			"npk": decToBytes32(preimage.NPK),
			"token": map[string]interface{}{
				"tokenType":    preimage.Token.TokenType,
				"tokenAddress": preimage.Token.TokenAddress,
				"tokenSubID":   preimage.Token.TokenSubID,
			},
			"value": preimage.Value,
		},
	}
}

func emptyOnChainPreimage() *CommitmentPreimage {
	return &CommitmentPreimage{
		NPK:   "0",
		Token: TokenData{TokenType: 0, TokenAddress: "0x0000000000000000000000000000000000000000", TokenSubID: "0"},
		Value: "0",
	}
}

// decToBytes32 converts a decimal-or-hex field element to a 0x 32-byte hex string.
func decToBytes32(s string) string {
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		v, _ = new(big.Int).SetString(s, 10)
	}
	if v == nil {
		v = big.NewInt(0)
	}
	return "0x" + hexEncode(v.FillBytes(make([]byte, 32)))
}

func decListToBytes32(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = decToBytes32(s)
	}
	return out
}

func hexEncode(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = d[c>>4]
		out[i*2+1] = d[c&0xf]
	}
	return string(out)
}

// bigToBytes32Dec renders a field element as a decimal string (uint256 calldata).
func bigToBytes32Dec(v *big.Int) string { return v.Text(10) }

func bigSliceToBytes32Dec(vs []*big.Int) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Text(10)
	}
	return out
}

func addrHex(a [20]byte) string {
	const hexDigit = "0123456789abcdef"
	buf := make([]byte, 2+40)
	buf[0], buf[1] = '0', 'x'
	for i, b := range a {
		buf[2+i*2] = hexDigit[b>>4]
		buf[2+i*2+1] = hexDigit[b&0xf]
	}
	return string(buf)
}
