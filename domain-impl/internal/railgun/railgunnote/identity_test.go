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
	"crypto/ed25519"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityFromSeedDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	id1, err := IdentityFromSeed(seed)
	require.NoError(t, err)
	id2, err := IdentityFromSeed(seed)
	require.NoError(t, err)
	// Same seed -> same spending key, viewing key, and mpk on every node.
	require.Equal(t, id1.SpendingKey, id2.SpendingKey)
	require.Equal(t, id1.ViewingKey, id2.ViewingKey)
	mpk1, err := id1.MasterPublicKeyHex()
	require.NoError(t, err)
	mpk2, err := id2.MasterPublicKeyHex()
	require.NoError(t, err)
	require.Equal(t, mpk1, mpk2)

	// the viewing key scalar (Poseidon input) is reduced into the field
	require.True(t, id1.ViewingKeyScalar().Cmp(SnarkScalarField) < 0)
}

// TestViewingKeyIndependentOfSpendingKey checks that the viewing key is NOT
// derived from the spending key: it is derived from the seed along a separate
// path, so it differs from the spending-key bytes and from a viewing key one
// would get by hashing the spending key.
func TestViewingKeyIndependentOfSpendingKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	id, err := IdentityFromSeed(seed)
	require.NoError(t, err)

	// Viewing key must not equal the raw spending-key material.
	require.NotEqual(t, id.SpendingKey[:], id.ViewingKey[:])

	// Viewing key must not be a function of the spending key (the old model):
	// re-deriving from the spending key rather than the seed yields a different
	// value, proving the two derivations are decoupled.
	fromSpend := sha256.Sum256(append(append([]byte{}, viewingKeyDomainTag...), id.SpendingKey[:]...))
	vkFromSpend := new(big.Int).Mod(new(big.Int).SetBytes(fromSpend[:]), SnarkScalarField)
	require.NotEqual(t, 0, id.ViewingKeyScalar().Cmp(vkFromSpend))

	// A different seed yields a different viewing key.
	seed2 := make([]byte, 32)
	copy(seed2, seed)
	seed2[0] ^= 0xff
	id2, err := IdentityFromSeed(seed2)
	require.NoError(t, err)
	require.NotEqual(t, id.ViewingKey, id2.ViewingKey)
}

// TestViewingPublicKeyEd25519 checks the viewing public key is a well-formed,
// deterministic Ed25519 public key derived from the viewing seed — matching
// Railgun's @noble/ed25519 getPublicKey(seed), so it can go into a 0zk address.
func TestViewingPublicKeyEd25519(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	id, err := IdentityFromSeed(seed)
	require.NoError(t, err)
	vpub := id.ViewingPublicKey()
	require.Len(t, vpub, ed25519.PublicKeySize, "viewing public key must be 32 bytes")

	// It must equal the standard Ed25519 public key for the raw viewing seed.
	want := ed25519.NewKeyFromSeed(id.ViewingKey[:]).Public().(ed25519.PublicKey)
	require.Equal(t, want, vpub)

	// Deterministic: same seed -> same public key.
	id2, _ := IdentityFromSeed(seed)
	require.Equal(t, vpub, id2.ViewingPublicKey())
}

func TestEncodeDecodeFieldRoundTrip(t *testing.T) {
	v := big.NewInt(0x1234abcd)
	s := EncodeField(v)
	require.Len(t, s, 2+64)
	got, err := DecodeField(s)
	require.NoError(t, err)
	require.Equal(t, 0, got.Cmp(v))
}

func TestWrongSeedLength(t *testing.T) {
	_, err := IdentityFromSeed(make([]byte, 16))
	require.Error(t, err)
}
