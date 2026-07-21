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
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"fmt"
)

// gcmIVLength is Railgun's AES-GCM IV size — 16 bytes, not the 12-byte default
// (the engine uses a 16-byte random IV; Node/OpenSSL and Go both follow the GCM
// spec for non-96-bit IVs, so this stays interoperable).
const gcmIVLength = 16

// Ciphertext mirrors the engine's Ciphertext bundle: a 16-byte IV, 16-byte GCM
// tag, and the encrypted data split into the same blocks it was given. AES-GCM is
// a stream (CTR) cipher, so encrypting blocks separately is equivalent to
// encrypting their concatenation and splitting at the same offsets.
type Ciphertext struct {
	IV   []byte
	Tag  []byte
	Data [][]byte
}

// EncryptGCM AES-256-GCM encrypts blocks under key with a fresh random 16-byte IV.
func EncryptGCM(key []byte, blocks [][]byte) (*Ciphertext, error) {
	iv := make([]byte, gcmIVLength)
	if _, err := cryptorand.Read(iv); err != nil {
		return nil, err
	}
	return EncryptGCMWithIV(key, iv, blocks)
}

// EncryptGCMWithIV is EncryptGCM with a caller-supplied IV (for deterministic tests).
func EncryptGCMWithIV(key, iv []byte, blocks [][]byte) (*Ciphertext, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcmIVLength {
		return nil, fmt.Errorf("iv must be %d bytes, got %d", gcmIVLength, len(iv))
	}
	plaintext, sizes := concat(blocks)
	sealed := gcm.Seal(nil, iv, plaintext, nil) // ciphertext || 16-byte tag
	ct := sealed[:len(plaintext)]
	tag := sealed[len(plaintext):]
	return &Ciphertext{IV: iv, Tag: tag, Data: split(ct, sizes)}, nil
}

// DecryptGCM AES-256-GCM decrypts, returning the plaintext split into blocks with
// the same sizes as the ciphertext blocks. Returns an error if authentication fails.
func DecryptGCM(key []byte, ct *Ciphertext) ([][]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ct.IV) != gcmIVLength {
		return nil, fmt.Errorf("iv must be %d bytes, got %d", gcmIVLength, len(ct.IV))
	}
	if len(ct.Tag) != 16 {
		return nil, fmt.Errorf("tag must be 16 bytes, got %d", len(ct.Tag))
	}
	data, sizes := concat(ct.Data)
	plaintext, err := gcm.Open(nil, ct.IV, append(data, ct.Tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("gcm authentication failed: %w", err)
	}
	return split(plaintext, sizes), nil
}

// EncryptCTR AES-256-CTR encrypts blocks with a fresh random 16-byte IV, used for
// the shield receiver-key bundle. Returns the IV and per-block ciphertext.
func EncryptCTR(key []byte, blocks [][]byte) (iv []byte, data [][]byte, err error) {
	iv = make([]byte, aes.BlockSize)
	if _, err = cryptorand.Read(iv); err != nil {
		return nil, nil, err
	}
	return encryptCTRWithIV(key, iv, blocks)
}

func encryptCTRWithIV(key, iv []byte, blocks [][]byte) ([]byte, [][]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext, sizes := concat(blocks)
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
	return iv, split(out, sizes), nil
}

// DecryptCTR reverses EncryptCTR.
func DecryptCTR(key, iv []byte, blocks [][]byte) ([][]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data, sizes := concat(blocks)
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return split(out, sizes), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, gcmIVLength)
}

func concat(blocks [][]byte) ([]byte, []int) {
	sizes := make([]int, len(blocks))
	var out []byte
	for i, b := range blocks {
		sizes[i] = len(b)
		out = append(out, b...)
	}
	return out, sizes
}

func split(data []byte, sizes []int) [][]byte {
	out := make([][]byte, len(sizes))
	pos := 0
	for i, n := range sizes {
		out[i] = data[pos : pos+n]
		pos += n
	}
	return out
}
