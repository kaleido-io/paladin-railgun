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

package railguncrypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCMRoundTrip(t *testing.T) {
	key := mustHex(t, "b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f")
	iv := mustHex(t, "5f8c104eec6e72996078ca3149a153c0")
	blocks := [][]byte{
		mustHex(t, "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d"), // 32
		mustHex(t, "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192"), // 32
		mustHex(t, "85b08a7cd73ee433072f1d410aeb4801000000000000000000000000e61ccb53"), // 32 (random||value)
	}

	ct, err := EncryptGCMWithIV(key, iv, blocks)
	require.NoError(t, err)
	require.Len(t, ct.IV, 16)
	require.Len(t, ct.Tag, 16)
	require.Len(t, ct.Data, 3)
	for i, b := range ct.Data {
		require.Len(t, b, len(blocks[i]), "block %d length preserved", i)
	}

	got, err := DecryptGCM(key, ct)
	require.NoError(t, err)
	for i := range blocks {
		require.True(t, bytes.Equal(blocks[i], got[i]), "block %d round-trips", i)
	}
}

func TestGCMTamperDetected(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	ct, err := EncryptGCMWithIV(key, iv, [][]byte{mustHex(t, "00112233445566778899aabbccddeeff")})
	require.NoError(t, err)
	ct.Tag[0] ^= 0xff
	_, err = DecryptGCM(key, ct)
	require.Error(t, err, "corrupted tag must fail authentication")
}

func TestGCMVariableBlockSizes(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	// 4 blocks including a variable-length memo block, as the note layer uses.
	blocks := [][]byte{
		mustHex(t, "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d"),
		mustHex(t, "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192"),
		mustHex(t, "85b08a7cd73ee433072f1d410aeb4801000000000000000000000000e61ccb53"),
		[]byte("a variable length memo"),
	}
	ct, err := EncryptGCMWithIV(key, iv, blocks)
	require.NoError(t, err)
	got, err := DecryptGCM(key, ct)
	require.NoError(t, err)
	for i := range blocks {
		require.True(t, bytes.Equal(blocks[i], got[i]))
	}
}

func TestCTRRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	blocks := [][]byte{mustHex(t, "9902564685f24f396263c64f582aa9a87499704509c60862930b1f9f7d258e8e")}
	iv, data, err := EncryptCTR(key, blocks)
	require.NoError(t, err)
	got, err := DecryptCTR(key, iv, data)
	require.NoError(t, err)
	require.True(t, bytes.Equal(blocks[0], got[0]))
}
