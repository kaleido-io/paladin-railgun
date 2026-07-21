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
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/require"
)

type vectors struct {
	SpendingKey       string   `json:"spendingKey"`
	ViewingKey        string   `json:"viewingKey"`
	Random            string   `json:"random"`
	TokenAddress      string   `json:"tokenAddress"`
	Value             string   `json:"value"`
	SpendingPublicKey []string `json:"spendingPublicKey"`
	NullifyingKey     string   `json:"nullifyingKey"`
	MasterPublicKey   string   `json:"masterPublicKey"`
	NPK               string   `json:"notePublicKey_npk"`
	TokenID           string   `json:"tokenID"`
	Commitment        string   `json:"commitment"`
	LeafIndex         uint64   `json:"leafIndex"`
	Nullifier         string   `json:"nullifier"`
	Signature         struct {
		R8x string `json:"R8x"`
		R8y string `json:"R8y"`
		S   string `json:"S"`
	} `json:"signature"`
	SigInputs struct {
		MerkleRoot      string `json:"merkleRoot"`
		BoundParamsHash string `json:"boundParamsHash"`
	} `json:"sigInputs"`
	Merkle struct {
		Depth     int    `json:"depth"`
		ZeroValue string `json:"zeroValue"`
		EmptyRoot string `json:"emptyRoot"`
	} `json:"merkle"`
}

func hexInt(s string) *big.Int {
	b, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	return b
}

func hexBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return b
}

func loadVectors(t *testing.T) *vectors {
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(data, &v))
	return &v
}

func newIdentity(t *testing.T, v *vectors) *Identity {
	var sk babyjub.PrivateKey
	skBytes := hexBytes(v.SpendingKey)
	require.Len(t, skBytes, 32)
	copy(sk[:], skBytes)
	id := &Identity{SpendingKey: sk}
	copy(id.ViewingKey[:], hexBytes(v.ViewingKey))
	return id
}

func TestSpendingPublicKeyMatchesReference(t *testing.T) {
	v := loadVectors(t)
	id := newIdentity(t, v)
	x, y := id.SpendingPublicKey()
	require.Equal(t, 0, x.Cmp(hexInt(v.SpendingPublicKey[0])), "spending pubkey x")
	require.Equal(t, 0, y.Cmp(hexInt(v.SpendingPublicKey[1])), "spending pubkey y")
}

func TestNullifyingAndMasterPublicKey(t *testing.T) {
	v := loadVectors(t)
	id := newIdentity(t, v)
	nk, err := id.NullifyingKey()
	require.NoError(t, err)
	require.Equal(t, 0, nk.Cmp(hexInt(v.NullifyingKey)), "nullifyingKey")
	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)
	require.Equal(t, 0, mpk.Cmp(hexInt(v.MasterPublicKey)), "masterPublicKey")
}

func TestNotePublicKeyCommitmentNullifier(t *testing.T) {
	v := loadVectors(t)
	id := newIdentity(t, v)
	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)

	npk, err := NotePublicKey(mpk, hexInt(v.Random))
	require.NoError(t, err)
	require.Equal(t, 0, npk.Cmp(hexInt(v.NPK)), "npk")

	var addr [20]byte
	copy(addr[:], hexBytes(v.TokenAddress))
	tokenID := TokenIDERC20(addr)
	require.Equal(t, 0, tokenID.Cmp(hexInt(v.TokenID)), "tokenID")

	value, _ := new(big.Int).SetString(v.Value, 10)
	commitment, err := Commitment(npk, tokenID, value)
	require.NoError(t, err)
	require.Equal(t, 0, commitment.Cmp(hexInt(v.Commitment)), "commitment")

	nk, err := id.NullifyingKey()
	require.NoError(t, err)
	nullifier, err := Nullifier(nk, v.LeafIndex)
	require.NoError(t, err)
	require.Equal(t, 0, nullifier.Cmp(hexInt(v.Nullifier)), "nullifier")
}

func TestSpendSignatureMatchesReference(t *testing.T) {
	v := loadVectors(t)
	id := newIdentity(t, v)
	msg, err := SignatureMessage(
		hexInt(v.SigInputs.MerkleRoot),
		hexInt(v.SigInputs.BoundParamsHash),
		[]*big.Int{hexInt(v.Nullifier)},
		[]*big.Int{hexInt(v.Commitment)},
	)
	require.NoError(t, err)
	r8x, r8y, s := id.Sign(msg)
	require.Equal(t, 0, r8x.Cmp(hexInt(v.Signature.R8x)), "R8x")
	require.Equal(t, 0, r8y.Cmp(hexInt(v.Signature.R8y)), "R8y")
	require.Equal(t, 0, s.Cmp(hexInt(v.Signature.S)), "S")
}
