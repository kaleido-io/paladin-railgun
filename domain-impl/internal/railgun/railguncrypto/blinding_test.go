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
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

// senderRandomNull mirrors MEMO_SENDER_RANDOM_NULL (15 zero bytes).
var senderRandomNull = make([]byte, 15)

func viewingPub(seed []byte) []byte {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

func seed32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// TestBlindedKeysSharedKeyConsistency mirrors the engine "Should get shared key
// from two note keys" tests: after blinding, the receiver (with the blinded
// SENDER key) and the sender (with the blinded RECEIVER key) derive the same
// shared symmetric key.
func TestBlindedKeysSharedKeyConsistency(t *testing.T) {
	senderSeed := seed32(1)
	receiverSeed := seed32(100)
	senderPub := viewingPub(senderSeed)
	receiverPub := viewingPub(receiverSeed)
	random := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01} // 16 bytes

	for _, tc := range []struct {
		name        string
		senderRand  []byte
	}{
		{"senderRandomNull", senderRandomNull},
		{"senderRandom15", []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blindedSender, blindedReceiver, err := BlindNoteKeys(senderPub, receiverPub, random, tc.senderRand)
			require.NoError(t, err)

			k1, err := SharedKey(receiverSeed, blindedSender)
			require.NoError(t, err)
			k2, err := SharedKey(senderSeed, blindedReceiver)
			require.NoError(t, err)
			require.Equal(t, k1, k2, "sender and receiver must derive the same shared key")
		})
	}
}

// TestUnblindNoteKey mirrors the engine "Should unblind note keys" test: blinding
// then unblinding recovers the original viewing public key.
func TestUnblindNoteKey(t *testing.T) {
	senderPub := viewingPub(seed32(3))
	receiverPub := viewingPub(seed32(200))
	random := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	blindedSender, blindedReceiver, err := BlindNoteKeys(senderPub, receiverPub, random, senderRandomNull)
	require.NoError(t, err)

	unblindedSender, err := UnblindNoteKey(blindedSender, random, senderRandomNull)
	require.NoError(t, err)
	unblindedReceiver, err := UnblindNoteKey(blindedReceiver, random, senderRandomNull)
	require.NoError(t, err)

	require.Equal(t, []byte(senderPub), unblindedSender)
	require.Equal(t, []byte(receiverPub), unblindedReceiver)
}
