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

package railgunnote

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityFromSpendingKeyDeterministic(t *testing.T) {
	sk := make([]byte, 32)
	for i := range sk {
		sk[i] = byte(i + 1)
	}
	id1, err := IdentityFromSpendingKey(sk)
	require.NoError(t, err)
	id2, err := IdentityFromSpendingKey(sk)
	require.NoError(t, err)
	// Same spending key -> same viewing key -> same mpk on every node.
	require.Equal(t, id1.ViewingKey, id2.ViewingKey)
	mpk1, err := id1.MasterPublicKeyHex()
	require.NoError(t, err)
	mpk2, err := id2.MasterPublicKeyHex()
	require.NoError(t, err)
	require.Equal(t, mpk1, mpk2)

	// viewing key is in-field
	vk := new(big.Int).SetBytes(id1.ViewingKey[:])
	require.True(t, vk.Cmp(SnarkScalarField) < 0)
}

func TestEncodeDecodeFieldRoundTrip(t *testing.T) {
	v := big.NewInt(0x1234abcd)
	s := EncodeField(v)
	require.Len(t, s, 2+64)
	got, err := DecodeField(s)
	require.NoError(t, err)
	require.Equal(t, 0, got.Cmp(v))
}

func TestWrongSpendingKeyLength(t *testing.T) {
	_, err := IdentityFromSpendingKey(make([]byte, 16))
	require.Error(t, err)
}
