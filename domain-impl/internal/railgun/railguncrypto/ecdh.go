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

// Package railguncrypto implements Railgun's note-secret encryption pipeline —
// the Ed25519 ECDH + key blinding + AES-256-GCM layers that let a sender encrypt
// note data (random, value, token) on-chain to a recipient's viewing key, and a
// recipient recover it. It mirrors @railgun-community/engine (V2 / AES-256-GCM)
// byte-for-byte so that notes are interoperable with real Railgun wallets, and is
// validated against the engine's own known-answer test vectors.
package railguncrypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// SharedKey derives the Railgun ECDH shared symmetric key:
//
//	sha256( edwards25519Point(blindedPub) · clamp(sha512(viewingSeed)[:32]) )
//
// matching @railgun-community/engine getSharedSymmetricKey. viewingSeed is the
// 32-byte Ed25519 viewing private key; blindedPub is a 32-byte compressed
// Ed25519 point (typically a blinded viewing public key). The multiplication is
// on the Edwards curve (NOT Montgomery X25519), and the shared secret is the
// SHA-256 of the compressed resulting point.
func SharedKey(viewingSeed, blindedPub []byte) ([]byte, error) {
	scalar, err := ViewingScalar(viewingSeed)
	if err != nil {
		return nil, err
	}
	p, err := new(edwards25519.Point).SetBytes(blindedPub)
	if err != nil {
		return nil, fmt.Errorf("invalid blinded public key point: %w", err)
	}
	shared := new(edwards25519.Point).ScalarMult(scalar, p)
	h := sha256.Sum256(shared.Bytes())
	return h[:], nil
}

// ViewingScalar derives the Ed25519 scalar from a 32-byte viewing seed:
// clamp(sha512(seed)[:32]) reduced mod L, per RFC 8032 §5.1.5. This matches the
// engine's getPrivateScalarFromPrivateKey.
func ViewingScalar(seed []byte) (*edwards25519.Scalar, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("viewing seed must be 32 bytes, got %d", len(seed))
	}
	h := sha512.Sum512(seed)
	return edwards25519.NewScalar().SetBytesWithClamping(h[:32])
}
