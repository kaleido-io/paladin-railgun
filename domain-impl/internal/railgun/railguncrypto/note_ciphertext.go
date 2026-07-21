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
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
)

// This file assembles Railgun's V2 note ciphertext from the ECDH, blinding, and
// AES-256-GCM primitives — the on-chain CommitmentCiphertext (transact) and
// ShieldCiphertext (shield) that let an external Railgun wallet recover a note's
// secrets from chain data alone.
//
// Address-visible mode: we always use senderRandom = MEMO_SENDER_RANDOM_NULL, so
// the encoded master public key = receiverMPK XOR senderMPK (the recipient, who
// knows its own MPK, can recover the sender's), matching getEncodedMasterPublicKey.

// senderRandomNullBytes is MEMO_SENDER_RANDOM_NULL: 15 zero bytes.
var senderRandomNullBytes = make([]byte, 15)

// TransactNote is the plaintext of a Railgun transact note.
type TransactNote struct {
	ReceiverMPK *big.Int // recipient master public key
	SenderMPK   *big.Int // sender master public key (for the visible-address encoding)
	TokenHash   []byte   // 32-byte token id (ERC-20: left-padded address)
	Random      []byte   // 16 bytes
	Value       []byte   // 16 bytes (128-bit)
	Memo        []byte   // optional; empty for no memo
}

// EncryptedCommitment is the on-chain CommitmentCiphertext payload for a transact
// output: ciphertext[4] = [iv‖tag, encodedMPK, tokenHash, random‖value], plus the
// blinded viewing keys and (encrypted) memo. AnnotationData is left for the caller.
type EncryptedCommitment struct {
	Ciphertext                [4][]byte
	BlindedSenderViewingKey   []byte
	BlindedReceiverViewingKey []byte
	Memo                      []byte
}

// EncryptTransactNote encrypts a transact note to the recipient's Ed25519 viewing
// key, producing the on-chain CommitmentCiphertext fields. senderViewingSeed is
// the sender's 32-byte Ed25519 viewing key; receiverViewingPub is the recipient's
// 32-byte Ed25519 viewing public key (from their 0zk address).
func EncryptTransactNote(senderViewingSeed, receiverViewingPub []byte, n TransactNote) (*EncryptedCommitment, error) {
	if len(n.Random) != 16 {
		return nil, fmt.Errorf("note random must be 16 bytes, got %d", len(n.Random))
	}
	if len(n.Value) != 16 {
		return nil, fmt.Errorf("note value must be 16 bytes, got %d", len(n.Value))
	}
	if len(n.TokenHash) != 32 {
		return nil, fmt.Errorf("token hash must be 32 bytes, got %d", len(n.TokenHash))
	}
	senderViewingPub := ed25519.NewKeyFromSeed(senderViewingSeed).Public().(ed25519.PublicKey)

	// Blind the viewing keys with sharedRandom = note random, senderRandom = NULL.
	blindedSender, blindedReceiver, err := BlindNoteKeys(senderViewingPub, receiverViewingPub, n.Random, senderRandomNullBytes)
	if err != nil {
		return nil, err
	}
	// Sender derives the shared key from the blinded RECEIVER key.
	sharedKey, err := SharedKey(senderViewingSeed, blindedReceiver)
	if err != nil {
		return nil, err
	}

	encodedMPK := to32Bytes(new(big.Int).Xor(n.ReceiverMPK, n.SenderMPK))
	randomValue := append(append([]byte{}, n.Random...), n.Value...) // 32 bytes
	memo := n.Memo
	if memo == nil {
		memo = []byte{}
	}

	ct, err := EncryptGCM(sharedKey, [][]byte{encodedMPK, n.TokenHash, randomValue, memo})
	if err != nil {
		return nil, err
	}
	ivTag := append(append([]byte{}, ct.IV...), ct.Tag...) // 32 bytes
	return &EncryptedCommitment{
		Ciphertext:                [4][]byte{ivTag, ct.Data[0], ct.Data[1], ct.Data[2]},
		BlindedSenderViewingKey:   blindedSender,
		BlindedReceiverViewingKey: blindedReceiver,
		Memo:                      ct.Data[3],
	}, nil
}

// DecryptTransactNote recovers a transact note using the recipient's viewing seed.
// It returns the recovered token hash, random, value, and the encoded MPK (the
// caller XORs its own MPK to recover the sender's). Used by the receive path and
// by round-trip tests.
func DecryptTransactNote(receiverViewingSeed []byte, ec *EncryptedCommitment) (encodedMPK, tokenHash, random, value, memo []byte, err error) {
	if len(ec.Ciphertext[0]) != 32 {
		return nil, nil, nil, nil, nil, fmt.Errorf("iv‖tag must be 32 bytes, got %d", len(ec.Ciphertext[0]))
	}
	sharedKey, err := SharedKey(receiverViewingSeed, ec.BlindedSenderViewingKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ct := &Ciphertext{
		IV:   ec.Ciphertext[0][:16],
		Tag:  ec.Ciphertext[0][16:32],
		Data: [][]byte{ec.Ciphertext[1], ec.Ciphertext[2], ec.Ciphertext[3], ec.Memo},
	}
	blocks, err := DecryptGCM(sharedKey, ct)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	randomValue := blocks[2]
	if len(randomValue) != 32 {
		return nil, nil, nil, nil, nil, fmt.Errorf("random‖value must be 32 bytes, got %d", len(randomValue))
	}
	return blocks[0], blocks[1], randomValue[:16], randomValue[16:], blocks[3], nil
}

// ShieldCiphertext is the on-chain ShieldCiphertext for a shield output: an
// encrypted bundle (3 × 32 bytes) plus the ephemeral shield public key.
type ShieldCiphertext struct {
	EncryptedBundle [3][]byte
	ShieldKey       []byte // 32-byte Ed25519 public key of the ephemeral shield key
}

// EncryptShield encrypts a shield note's random to the recipient's Ed25519 viewing
// key using a fresh ephemeral shield key, matching shield-note.serialize. No sender
// private key is required (the ephemeral key is generated here).
func EncryptShield(receiverViewingPub, random []byte) (*ShieldCiphertext, error) {
	if len(random) != 16 {
		return nil, fmt.Errorf("shield random must be 16 bytes, got %d", len(random))
	}
	shieldPrivateKey := make([]byte, 32)
	if _, err := cryptorand.Read(shieldPrivateKey); err != nil {
		return nil, err
	}
	return encryptShieldWithKey(receiverViewingPub, random, shieldPrivateKey)
}

func encryptShieldWithKey(receiverViewingPub, random, shieldPrivateKey []byte) (*ShieldCiphertext, error) {
	sharedKey, err := SharedKey(shieldPrivateKey, receiverViewingPub)
	if err != nil {
		return nil, err
	}
	encRandom, err := EncryptGCM(sharedKey, [][]byte{random})
	if err != nil {
		return nil, err
	}
	ctrIV, encReceiver, err := EncryptCTR(shieldPrivateKey, [][]byte{receiverViewingPub})
	if err != nil {
		return nil, err
	}
	shieldKey := ed25519.NewKeyFromSeed(shieldPrivateKey).Public().(ed25519.PublicKey)
	return &ShieldCiphertext{
		EncryptedBundle: [3][]byte{
			append(append([]byte{}, encRandom.IV...), encRandom.Tag...), // iv‖tag (32)
			append(append([]byte{}, encRandom.Data[0]...), ctrIV...),    // encryptedRandom‖ctrIV (32)
			encReceiver[0],                                              // AES-CTR(receiverViewingPub) (32)
		},
		ShieldKey: shieldKey,
	}, nil
}

// DecryptShieldRandom recovers a shield note's random using the recipient's
// viewing seed (round-trip / receive helper).
func DecryptShieldRandom(receiverViewingSeed []byte, sc *ShieldCiphertext) ([]byte, error) {
	sharedKey, err := SharedKey(receiverViewingSeed, sc.ShieldKey)
	if err != nil {
		return nil, err
	}
	ct := &Ciphertext{
		IV:   sc.EncryptedBundle[0][:16],
		Tag:  sc.EncryptedBundle[0][16:32],
		Data: [][]byte{sc.EncryptedBundle[1][:16]},
	}
	blocks, err := DecryptGCM(sharedKey, ct)
	if err != nil {
		return nil, err
	}
	return blocks[0], nil
}

func to32Bytes(v *big.Int) []byte {
	return v.FillBytes(make([]byte, 32))
}
