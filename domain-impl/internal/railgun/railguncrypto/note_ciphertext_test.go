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
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTransactNoteRoundTrip encrypts a note to a recipient's viewing key and
// decrypts it back — the send-side sharedKey (from the blinded receiver key) and
// the receive-side sharedKey (from the blinded sender key) must agree, and all
// note fields must survive, with the sender address recoverable in address-visible
// mode (encodedMPK XOR receiverMPK == senderMPK).
func TestTransactNoteRoundTrip(t *testing.T) {
	senderSeed := seed32(1)
	receiverSeed := seed32(100)
	receiverPub := ed25519.NewKeyFromSeed(receiverSeed).Public().(ed25519.PublicKey)

	note := TransactNote{
		ReceiverMPK: bigFromHex(t, "3049bce13a3ba76cd96e5dc0287061ebf92df2fa3badf68d55d6a5dbc806a0f0"),
		SenderMPK:   bigFromHex(t, "0aa1bce13a3ba76cd96e5dc0287061ebf92df2fa3badf68d55d6a5dbc8010203"),
		TokenHash:   mustHex(t, "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192"),
		Random:      mustHex(t, "85b08a7cd73ee433072f1d410aeb4801"),
		Value:       mustHex(t, "0000000000000000086aa1ade61ccb53"),
	}

	ec, err := EncryptTransactNote(senderSeed, receiverPub, note)
	require.NoError(t, err)
	require.Len(t, ec.Ciphertext[0], 32) // iv‖tag
	require.Len(t, ec.Ciphertext[1], 32)
	require.Len(t, ec.Ciphertext[2], 32)
	require.Len(t, ec.Ciphertext[3], 32)
	require.Len(t, ec.BlindedSenderViewingKey, 32)
	require.Len(t, ec.BlindedReceiverViewingKey, 32)

	encodedMPK, tokenHash, random, value, _, err := DecryptTransactNote(receiverSeed, ec)
	require.NoError(t, err)
	require.Equal(t, note.TokenHash, tokenHash)
	require.Equal(t, note.Random, random)
	require.Equal(t, note.Value, value)

	// Address-visible: recover sender MPK by XOR with the known receiver MPK.
	recoveredSender := new(big.Int).Xor(new(big.Int).SetBytes(encodedMPK), note.ReceiverMPK)
	require.Equal(t, 0, recoveredSender.Cmp(note.SenderMPK), "sender address must be recoverable")
}

// TestTransactNoteWrongReceiverFails ensures a different viewing key cannot decrypt.
func TestTransactNoteWrongReceiverFails(t *testing.T) {
	receiverPub := ed25519.NewKeyFromSeed(seed32(100)).Public().(ed25519.PublicKey)
	note := TransactNote{
		ReceiverMPK: big.NewInt(0x1234),
		SenderMPK:   big.NewInt(0x5678),
		TokenHash:   make([]byte, 32),
		Random:      mustHex(t, "85b08a7cd73ee433072f1d410aeb4801"),
		Value:       mustHex(t, "0000000000000000086aa1ade61ccb53"),
	}
	ec, err := EncryptTransactNote(seed32(1), receiverPub, note)
	require.NoError(t, err)

	_, _, _, _, _, err = DecryptTransactNote(seed32(200) /* wrong */, ec)
	require.Error(t, err, "a non-recipient must not be able to decrypt")
}

// TestShieldRoundTrip encrypts a shield note's random and recovers it.
func TestShieldRoundTrip(t *testing.T) {
	receiverSeed := seed32(42)
	receiverPub := ed25519.NewKeyFromSeed(receiverSeed).Public().(ed25519.PublicKey)
	random := mustHex(t, "85b08a7cd73ee433072f1d410aeb4801")

	sc, err := EncryptShield(receiverPub, random)
	require.NoError(t, err)
	require.Len(t, sc.EncryptedBundle[0], 32)
	require.Len(t, sc.EncryptedBundle[1], 32)
	require.Len(t, sc.EncryptedBundle[2], 32)
	require.Len(t, sc.ShieldKey, 32)

	got, err := DecryptShieldRandom(receiverSeed, sc)
	require.NoError(t, err)
	require.Equal(t, random, got)
}

func bigFromHex(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	require.True(t, ok)
	return v
}
