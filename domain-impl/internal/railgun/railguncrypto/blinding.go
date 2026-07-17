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
	"crypto/sha512"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
)

// ed25519L is the order of the Ed25519 prime-order subgroup (CURVE.n / CURVE.l).
var ed25519L, _ = new(big.Int).SetString(
	"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

// blindingScalar computes the note blinding scalar, matching the engine's
// getBlindingScalar/seedToScalar:
//
//	finalRandom   = 32-byte-BE( bigEndian(sharedRandom) XOR bigEndian(senderRandom) )
//	blindingScalar = bigEndian(sha512(finalRandom)) mod L
//
// sharedRandom is the note's random; senderRandom is the sender's random (or the
// 15-byte MEMO_SENDER_RANDOM_NULL). Both are interpreted as big-endian values.
func blindingScalar(sharedRandom, senderRandom []byte) (*edwards25519.Scalar, error) {
	x := new(big.Int).Xor(
		new(big.Int).SetBytes(sharedRandom),
		new(big.Int).SetBytes(senderRandom),
	)
	final := x.FillBytes(make([]byte, 32)) // 32-byte big-endian
	h := sha512.Sum512(final)
	n := new(big.Int).SetBytes(h[:]) // big-endian
	return scalarFromBigEndianReduced(n)
}

// scalarFromBigEndianReduced builds an Ed25519 scalar from (n mod L). filippo's
// SetCanonicalBytes expects little-endian canonical bytes, so we reduce, encode
// big-endian, and reverse.
func scalarFromBigEndianReduced(n *big.Int) (*edwards25519.Scalar, error) {
	r := new(big.Int).Mod(n, ed25519L)
	be := r.FillBytes(make([]byte, 32))
	le := reverseBytes(be)
	return edwards25519.NewScalar().SetCanonicalBytes(le)
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// BlindNoteKeys blinds the sender and receiver viewing public keys by the note
// blinding scalar, matching the engine's getNoteBlindingKeys. Inputs are 32-byte
// compressed Ed25519 public keys; outputs are 32-byte compressed points.
func BlindNoteKeys(senderPub, receiverPub, sharedRandom, senderRandom []byte) (blindedSender, blindedReceiver []byte, err error) {
	s, err := blindingScalar(sharedRandom, senderRandom)
	if err != nil {
		return nil, nil, err
	}
	blindedSender, err = mulPoint(senderPub, s)
	if err != nil {
		return nil, nil, fmt.Errorf("blinding sender key: %w", err)
	}
	blindedReceiver, err = mulPoint(receiverPub, s)
	if err != nil {
		return nil, nil, fmt.Errorf("blinding receiver key: %w", err)
	}
	return blindedSender, blindedReceiver, nil
}

// UnblindNoteKey inverts the blinding to recover an original viewing public key
// from a blinded one, matching the engine's unblindNoteKey.
func UnblindNoteKey(blindedKey, sharedRandom, senderRandom []byte) ([]byte, error) {
	s, err := blindingScalar(sharedRandom, senderRandom)
	if err != nil {
		return nil, err
	}
	inv := edwards25519.NewScalar().Invert(s)
	return mulPoint(blindedKey, inv)
}

// mulPoint decompresses a 32-byte Ed25519 point and multiplies it by s, returning
// the compressed result.
func mulPoint(pub []byte, s *edwards25519.Scalar) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid point: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(s, p).Bytes(), nil
}
