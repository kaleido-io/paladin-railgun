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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

// Key-derivation domain tags. The spending and viewing keys are derived from the
// same seed along SEPARATE domain-separated paths, so that neither key can be
// computed from the other's public output. This mirrors Railgun's own wallet
// model, where both keys derive from a single mnemonic along distinct BIP-32
// paths — and is what makes the viewing key shareable for view-only access
// without ever exposing the spending key.
var (
	spendingKeyDomainTag = []byte("railgun:spending-key:v1")
	viewingKeyDomainTag  = []byte("railgun:viewing-key:v1")
)

// IdentityFromSeed builds a Railgun identity from the 32-byte master seed
// managed by Paladin. Both the BabyJubJub spending key and the viewing key are
// derived deterministically from the seed via independent domain-separated
// derivations — the viewing key is NOT derived from the spending key. Every node
// derives the same identity (and therefore the same masterPublicKey /
// nullifiers) for a given seed, without needing a separately-managed key.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}
	id := &Identity{}

	// Spending key: 32 bytes of entropy for the BabyJubJub private key. The
	// babyjub package derives the actual scalar (Blake-512 hash + pruning) from
	// these bytes internally, so any 32-byte value is a valid spending key.
	copy(id.SpendingKey[:], deriveSeedKey(spendingKeyDomainTag, seed))

	// Viewing key: a raw 32-byte Ed25519 seed, derived from the SAME seed along a
	// different path (not from the spending key). Railgun's viewing key is Ed25519
	// (used for the viewing public key in a 0zk address and for note-ciphertext
	// ECDH); the nullifying key reduces this secret into the field via Poseidon.
	copy(id.ViewingKey[:], deriveSeedKey(viewingKeyDomainTag, seed))
	return id, nil
}

// deriveSeedKey mixes a domain tag with the seed to produce 32 bytes of
// key material. Distinct tags yield independent keys from one seed.
func deriveSeedKey(tag, seed []byte) []byte {
	h := sha256.Sum256(append(append([]byte{}, tag...), seed...))
	return h[:]
}

// MasterPublicKeyHex returns the identity's masterPublicKey as a 0x-prefixed,
// zero-padded 32-byte hex string. This is the Railgun "address" used as the
// domain verifier: a sender resolves a recipient to this value and forms the
// recipient's note public key as Poseidon(mpk, random).
func (id *Identity) MasterPublicKeyHex() (string, error) {
	mpk, err := id.MasterPublicKey()
	if err != nil {
		return "", err
	}
	return EncodeField(mpk), nil
}

// EncodeField renders a field element as a 0x-prefixed 32-byte hex string.
func EncodeField(v *big.Int) string {
	return "0x" + hex.EncodeToString(v.FillBytes(make([]byte, 32)))
}

// DecodeField parses a 0x-prefixed (or bare) hex / decimal field element.
func DecodeField(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex field element: %s", s)
		}
		return v, nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid field element: %s", s)
	}
	return v, nil
}

// SpendingPublicKeyCompressed returns the compressed BabyJubJub spending public
// key (informational; the domain addresses notes by masterPublicKey).
func (id *Identity) SpendingPublicKeyCompressed() babyjub.PublicKeyComp {
	return id.SpendingKey.Public().Compress()
}

// ViewingKeyScalar returns the viewing key reduced into the scalar field — the
// value Poseidon hashes to produce the nullifyingKey. The raw viewing key
// (id.ViewingKey) is a 32-byte Ed25519 seed; this reduction matches the
// reference (circomlibjs reduces Poseidon inputs into the field internally).
func (id *Identity) ViewingKeyScalar() *big.Int {
	return reduce(new(big.Int).SetBytes(id.ViewingKey[:]))
}

// ViewingPrivateKey returns the Ed25519 private key seeded by the viewing key.
func (id *Identity) ViewingPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(id.ViewingKey[:])
}

// ViewingPublicKey returns the 32-byte Ed25519 viewing public key. It is the
// recipient-facing half of a Railgun (0zk) address — the other half being
// masterPublicKey — used so a sender can address notes to a recipient, and is
// derived independently of the spending key. Byte-for-byte compatible with
// Railgun's viewing public key (@noble/ed25519 getPublicKey), so it can be
// embedded in an interoperable 0zk address.
func (id *Identity) ViewingPublicKey() ed25519.PublicKey {
	return id.ViewingPrivateKey().Public().(ed25519.PublicKey)
}
