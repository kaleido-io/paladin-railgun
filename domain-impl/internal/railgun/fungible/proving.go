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

package fungible

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguncrypto"
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

// PayloadOutput is one output note in a transact proving payload. Random,
// OwnerMPK, and OwnerViewingPub let Sign build the on-chain note ciphertext
// (encrypting random/value/token to the owner's Ed25519 viewing key). They are
// empty for outputs that need no ciphertext (e.g. an unshield's change note).
type PayloadOutput struct {
	NPK             string `json:"npk"`
	Value           string `json:"value"`
	Random          string `json:"random,omitempty"`          // note's 16-byte random (decimal)
	OwnerMPK        string `json:"ownerMpk,omitempty"`        // owner master public key (hex)
	OwnerViewingPub string `json:"ownerViewingPub,omitempty"` // owner Ed25519 viewing pubkey (hex)
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
	// TxID is the Paladin transaction id, re-homed into each commitment
	// ciphertext's annotationData for on-chain event correlation.
	TxID string `json:"txId,omitempty"`
}

// GenerateTransactionProof builds the joinsplit witness from the payload and the
// owner's private key, generates the Groth16 proof, and returns the fully
// assembled on-chain Transaction (serialised). Invoked from the domain's Sign.
func GenerateTransactionProof(ctx context.Context, prover *railgunprover.Prover, privateKey []byte, payload []byte) ([]byte, error) {
	id, err := railgunnote.IdentityFromSeed(privateKey)
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

	// Build the real note ciphertext for each output whose owner viewing key is
	// known (transfers), so an external Railgun wallet can recover the note by
	// scanning on-chain. This must happen BEFORE BoundParamsHash, as the
	// ciphertext is part of BoundParams and is bound into the proof. Outputs with
	// no viewing key (e.g. an unshield change note) keep their placeholder.
	if err := encryptOutputCiphertext(id, &p, token); err != nil {
		return nil, err
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

// encryptOutputCiphertext builds the real on-chain note ciphertext for each
// output with a known owner viewing key, encrypting (random, value, token) to
// that owner's Ed25519 viewing key so an external Railgun wallet can recover the
// note by scanning. The Paladin tx-id is carried in annotationData for event
// correlation. Outputs without a viewing key keep their placeholder ciphertext
// but still receive the tx-id annotation.
func encryptOutputCiphertext(id *railgunnote.Identity, p *ProvingPayload, tokenID *big.Int) error {
	cts := p.BoundParams.CommitmentCiphertext
	if len(cts) == 0 {
		return nil
	}
	senderMPK, err := id.MasterPublicKey()
	if err != nil {
		return err
	}
	senderViewingSeed := id.ViewingKey[:]
	tokenHash := tokenID.FillBytes(make([]byte, 32))

	for i := range cts {
		if i >= len(p.Outputs) {
			break
		}
		out := p.Outputs[i]
		if out.OwnerViewingPub == "" {
			cts[i].AnnotationData = annotationTxID(p.TxID)
			continue
		}
		recViewingPub, err := hex.DecodeString(strings.TrimPrefix(out.OwnerViewingPub, "0x"))
		if err != nil {
			return fmt.Errorf("output %d viewing pubkey: %w", i, err)
		}
		recMPK, err := railgunnote.DecodeField(out.OwnerMPK)
		if err != nil {
			return fmt.Errorf("output %d owner mpk: %w", i, err)
		}
		random, err := railgunnote.DecodeField(out.Random)
		if err != nil {
			return fmt.Errorf("output %d random: %w", i, err)
		}
		value, err := railgunnote.DecodeField(out.Value)
		if err != nil {
			return fmt.Errorf("output %d value: %w", i, err)
		}
		if value.BitLen() > 128 {
			return fmt.Errorf("output %d value exceeds 128 bits", i)
		}
		ec, err := railguncrypto.EncryptTransactNote(senderViewingSeed, recViewingPub, railguncrypto.TransactNote{
			ReceiverMPK: recMPK,
			SenderMPK:   senderMPK,
			TokenHash:   tokenHash,
			Random:      random.FillBytes(make([]byte, 16)),
			Value:       value.FillBytes(make([]byte, 16)),
		})
		if err != nil {
			return fmt.Errorf("output %d ciphertext: %w", i, err)
		}
		cts[i] = railguntx.CommitmentCiphertext{
			Ciphertext: [4]string{
				hex0x(ec.Ciphertext[0]), hex0x(ec.Ciphertext[1]),
				hex0x(ec.Ciphertext[2]), hex0x(ec.Ciphertext[3]),
			},
			BlindedSenderViewingKey:   hex0x(ec.BlindedSenderViewingKey),
			BlindedReceiverViewingKey: hex0x(ec.BlindedReceiverViewingKey),
			AnnotationData:            annotationTxID(p.TxID),
			Memo:                      hex0xOrEmpty(ec.Memo),
		}
	}
	return nil
}

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

func hex0xOrEmpty(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return hex0x(b)
}

// annotationTxID returns the tx-id for the annotationData field, or "0x" if unset.
func annotationTxID(txID string) string {
	if txID == "" {
		return "0x"
	}
	return txID
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
