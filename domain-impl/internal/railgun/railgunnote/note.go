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

// Package railgunnote implements the Railgun privacy-token note model — keys,
// note public keys, commitments, nullifiers, and the EdDSA-Poseidon spend
// signature — exactly as defined by the Railgun circuits (joinsplit.circom) and
// the RailgunSmartWallet contract. It is validated against ground-truth vectors
// generated from the Railgun reference implementation (see testdata/vectors.json).
//
// Derivations (all Poseidon over the BN254 scalar field):
//
//	nullifyingKey   = Poseidon(viewingKey)
//	masterPublicKey = Poseidon(spendPub.x, spendPub.y, nullifyingKey)
//	notePublicKey   = Poseidon(masterPublicKey, random)           // "npk"
//	commitment      = Poseidon(npk, tokenID, value)
//	nullifier       = Poseidon(nullifyingKey, leafIndex)
//	signature       = EdDSA-Poseidon(spendingKey, sighash)
//	  where sighash = Poseidon(merkleRoot, boundParamsHash, nullifiers…, commitmentsOut…)
package railgunnote

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// SnarkScalarField is the BN254 scalar field modulus (SNARK_SCALAR_FIELD).
var SnarkScalarField, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Identity is a Railgun wallet's key material: a BabyJubJub spending key and a
// 32-byte viewing key. The two together derive every value the protocol needs.
type Identity struct {
	SpendingKey babyjub.PrivateKey
	ViewingKey  [32]byte
}

func beInt(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// SpendingPublicKey returns the BabyJubJub spending public-key point (x, y).
func (id *Identity) SpendingPublicKey() (x, y *big.Int) {
	pub := id.SpendingKey.Public()
	return pub.X, pub.Y
}

// NullifyingKey = Poseidon(viewingKey).
func (id *Identity) NullifyingKey() (*big.Int, error) {
	return poseidon.Hash([]*big.Int{beInt(id.ViewingKey[:])})
}

// MasterPublicKey = Poseidon(spendPub.x, spendPub.y, nullifyingKey).
func (id *Identity) MasterPublicKey() (*big.Int, error) {
	x, y := id.SpendingPublicKey()
	nk, err := id.NullifyingKey()
	if err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{x, y, nk})
}

// NotePublicKey (npk) = Poseidon(masterPublicKey, random).
func NotePublicKey(masterPublicKey, random *big.Int) (*big.Int, error) {
	return poseidon.Hash([]*big.Int{masterPublicKey, random})
}

// TokenIDERC20 returns the circuit token id for an ERC-20: the address as a
// 160-bit integer.
func TokenIDERC20(addr [20]byte) *big.Int {
	return new(big.Int).SetBytes(addr[:])
}

// Commitment = Poseidon(npk, tokenID, value) — the on-chain note leaf.
func Commitment(npk, tokenID, value *big.Int) (*big.Int, error) {
	return poseidon.Hash([]*big.Int{npk, tokenID, value})
}

// Nullifier = Poseidon(nullifyingKey, leafIndex).
func Nullifier(nullifyingKey *big.Int, leafIndex uint64) (*big.Int, error) {
	return poseidon.Hash([]*big.Int{nullifyingKey, new(big.Int).SetUint64(leafIndex)})
}

// reduce maps a value into the BN254 scalar field. Poseidon inputs must be
// field elements; the reference (circomlibjs) reduces internally, and the
// contract already reduces boundParamsHash (keccak256(...) % field).
func reduce(v *big.Int) *big.Int {
	return new(big.Int).Mod(v, SnarkScalarField)
}

// SignatureMessage = Poseidon(merkleRoot, boundParamsHash, nullifiers…, commitmentsOut…).
// This is the message digest signed by the spending key in a transact proof.
// Inputs are reduced into the field to match the circuit's public-signal domain.
func SignatureMessage(merkleRoot, boundParamsHash *big.Int, nullifiers, commitmentsOut []*big.Int) (*big.Int, error) {
	in := make([]*big.Int, 0, 2+len(nullifiers)+len(commitmentsOut))
	in = append(in, reduce(merkleRoot), reduce(boundParamsHash))
	for _, n := range nullifiers {
		in = append(in, reduce(n))
	}
	for _, c := range commitmentsOut {
		in = append(in, reduce(c))
	}
	return poseidon.Hash(in)
}

// Sign produces the EdDSA-Poseidon signature over the given message digest,
// returning the circuit signature triple (R8.x, R8.y, S).
func (id *Identity) Sign(message *big.Int) (R8x, R8y, S *big.Int) {
	sig := id.SpendingKey.SignPoseidon(message)
	return sig.R8.X, sig.R8.Y, sig.S
}
