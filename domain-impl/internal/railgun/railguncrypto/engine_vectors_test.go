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
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// engineVectors are cross-implementation known-answers generated from the real
// @railgun-community/engine. Every value here was produced by the engine's own
// ECDH, blinding, AES-256-GCM, and commitment-ciphertext packing. Byte-exact
// agreement proves this Go pipeline is wire-compatible with real Railgun wallets.
//
// Regenerate: in a scratch dir, `npm i @railgun-community/engine`, then run
// testdata/gen_fixtures.js (committed alongside the fixture) and write its stdout
// to testdata/engine_vectors.json.
type engineVectors struct {
	ECDH []struct {
		Seed       string `json:"seed"`
		BlindedPub string `json:"blindedPub"`
		SharedKey  string `json:"sharedKey"`
	} `json:"ecdh"`
	Blinding []struct {
		SenderPub                 string `json:"senderPub"`
		ReceiverPub               string `json:"receiverPub"`
		Random                    string `json:"random"`
		SenderRandom              string `json:"senderRandom"`
		BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
		BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
	} `json:"blinding"`
	GCM []struct {
		Key    string   `json:"key"`
		Blocks []string `json:"blocks"`
		IV     string   `json:"iv"`
		Tag    string   `json:"tag"`
		Data   []string `json:"data"`
	} `json:"gcm"`
	Notes []struct {
		SenderSeed                string   `json:"senderSeed"`
		ReceiverSeed              string   `json:"receiverSeed"`
		ReceiverPub               string   `json:"receiverPub"`
		SenderMPK                 string   `json:"senderMPK"`
		ReceiverMPK               string   `json:"receiverMPK"`
		Random                    string   `json:"random"`
		Value                     string   `json:"value"`
		TokenHash                 string   `json:"tokenHash"`
		Ciphertext                []string `json:"ciphertext"`
		Memo                      string   `json:"memo"`
		BlindedSenderViewingKey   string   `json:"blindedSenderViewingKey"`
		BlindedReceiverViewingKey string   `json:"blindedReceiverViewingKey"`
	} `json:"notes"`
}

func loadEngineVectors(t *testing.T) *engineVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/engine_vectors.json")
	require.NoError(t, err)
	var v engineVectors
	require.NoError(t, json.Unmarshal(data, &v))
	return &v
}

func TestEngineVectorsECDH(t *testing.T) {
	v := loadEngineVectors(t)
	require.NotEmpty(t, v.ECDH)
	for i, tc := range v.ECDH {
		got, err := SharedKey(mustHex(t, tc.Seed), mustHex(t, tc.BlindedPub))
		require.NoError(t, err, "ecdh %d", i)
		require.Equal(t, tc.SharedKey, hex.EncodeToString(got), "ecdh %d", i)
	}
}

func TestEngineVectorsBlinding(t *testing.T) {
	v := loadEngineVectors(t)
	require.NotEmpty(t, v.Blinding)
	for i, tc := range v.Blinding {
		bs, br, err := BlindNoteKeys(mustHex(t, tc.SenderPub), mustHex(t, tc.ReceiverPub), mustHex(t, tc.Random), mustHex(t, tc.SenderRandom))
		require.NoError(t, err, "blinding %d", i)
		require.Equal(t, tc.BlindedSenderViewingKey, hex.EncodeToString(bs), "blinding %d sender", i)
		require.Equal(t, tc.BlindedReceiverViewingKey, hex.EncodeToString(br), "blinding %d receiver", i)

		// Unblind recovers the original public keys.
		us, err := UnblindNoteKey(bs, mustHex(t, tc.Random), mustHex(t, tc.SenderRandom))
		require.NoError(t, err)
		require.Equal(t, tc.SenderPub, hex.EncodeToString(us), "unblind %d sender", i)
	}
}

func TestEngineVectorsGCMDecrypt(t *testing.T) {
	v := loadEngineVectors(t)
	require.NotEmpty(t, v.GCM)
	for i, tc := range v.GCM {
		ct := &Ciphertext{IV: mustHex(t, tc.IV), Tag: mustHex(t, tc.Tag)}
		for _, d := range tc.Data {
			ct.Data = append(ct.Data, mustHex(t, d))
		}
		blocks, err := DecryptGCM(mustHex(t, tc.Key), ct)
		require.NoError(t, err, "gcm %d", i)
		require.Len(t, blocks, len(tc.Blocks))
		for j, b := range tc.Blocks {
			require.Equal(t, b, hex.EncodeToString(blocks[j]), "gcm %d block %d", i, j)
		}
	}
}

// TestEngineVectorsNoteDecrypt decrypts a full on-chain commitment ciphertext
// produced by the engine — the definitive interop check that this domain can
// decode a note exactly as a real Railgun wallet emitted it.
func TestEngineVectorsNoteDecrypt(t *testing.T) {
	v := loadEngineVectors(t)
	require.NotEmpty(t, v.Notes)
	for i, tc := range v.Notes {
		ec := engineNoteToEC(t, tc.Ciphertext, tc.Memo, tc.BlindedSenderViewingKey, tc.BlindedReceiverViewingKey)
		encodedMPK, tokenHash, random, value, _, err := DecryptTransactNote(mustHex(t, tc.ReceiverSeed), ec)
		require.NoError(t, err, "note %d decrypt", i)

		require.Equal(t, tc.Random, hex.EncodeToString(random), "note %d random", i)
		require.Equal(t, tc.Value, hex.EncodeToString(value), "note %d value", i)
		require.Equal(t, tc.TokenHash, hex.EncodeToString(tokenHash), "note %d token", i)

		receiverMPK := bigFromHex(t, tc.ReceiverMPK)
		recoveredSender := new(big.Int).Xor(new(big.Int).SetBytes(encodedMPK), receiverMPK)
		require.Equal(t, tc.SenderMPK, recoveredSender.Text(16), "note %d sender addr", i)
	}
}

// TestEngineVectorsNoteEncryptMatches proves this domain's send-side encryption
// reproduces the engine's blinded viewing keys byte-for-byte, and that the
// ciphertext it emits round-trips back to the same note fields.
func TestEngineVectorsNoteEncryptMatches(t *testing.T) {
	v := loadEngineVectors(t)
	for i, tc := range v.Notes {
		ec, err := EncryptTransactNote(mustHex(t, tc.SenderSeed), mustHex(t, tc.ReceiverPub), TransactNote{
			ReceiverMPK: bigFromHex(t, tc.ReceiverMPK),
			SenderMPK:   bigFromHex(t, tc.SenderMPK),
			TokenHash:   mustHex(t, tc.TokenHash),
			Random:      mustHex(t, tc.Random),
			Value:       mustHex(t, tc.Value),
		})
		require.NoError(t, err, "note %d encrypt", i)

		// Blinded keys are deterministic (independent of the random GCM IV) and
		// must match the engine byte-for-byte.
		require.Equal(t, tc.BlindedSenderViewingKey, hex.EncodeToString(ec.BlindedSenderViewingKey), "note %d blinded sender", i)
		require.Equal(t, tc.BlindedReceiverViewingKey, hex.EncodeToString(ec.BlindedReceiverViewingKey), "note %d blinded receiver", i)

		// And the emitted ciphertext decrypts back to the note for the recipient.
		_, _, random, value, _, err := DecryptTransactNote(mustHex(t, tc.ReceiverSeed), ec)
		require.NoError(t, err)
		require.Equal(t, tc.Random, hex.EncodeToString(random), "note %d round-trip random", i)
		require.Equal(t, tc.Value, hex.EncodeToString(value), "note %d round-trip value", i)
	}
}

func engineNoteToEC(t *testing.T, ciphertext []string, memo, bs, br string) *EncryptedCommitment {
	t.Helper()
	require.Len(t, ciphertext, 4)
	return &EncryptedCommitment{
		Ciphertext: [4][]byte{
			mustHex(t, ciphertext[0]), mustHex(t, ciphertext[1]),
			mustHex(t, ciphertext[2]), mustHex(t, ciphertext[3]),
		},
		BlindedSenderViewingKey:   mustHex(t, bs),
		BlindedReceiverViewingKey: mustHex(t, br),
		Memo:                      mustHex(t, memo),
	}
}
