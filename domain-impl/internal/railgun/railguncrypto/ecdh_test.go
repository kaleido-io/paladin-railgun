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

package railguncrypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestSharedKeyReferenceVector validates ECDH against the engine known-answer
// vector (@railgun-community/engine src/utils/__tests__/keys-utils.test.ts):
// getSharedSymmetricKey(privateKeyPairA, blindedPublicKeyPairB) == expected.
func TestSharedKeyReferenceVector(t *testing.T) {
	privA := mustHex(t, "0123456789012345678901234567890123456789012345678901234567891234")
	blindedB := mustHex(t, "0987654321098765432109876543210987654321098765432109876543210987")
	want := "fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56"

	got, err := SharedKey(privA, blindedB)
	require.NoError(t, err)
	require.Equal(t, want, hex.EncodeToString(got))
}

func TestViewingScalarLength(t *testing.T) {
	_, err := ViewingScalar(make([]byte, 16))
	require.Error(t, err)
	s, err := ViewingScalar(make([]byte, 32))
	require.NoError(t, err)
	require.Len(t, s.Bytes(), 32)
}
