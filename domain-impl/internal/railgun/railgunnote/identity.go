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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

// viewingKeyDomainTag separates the deterministic viewing-key derivation from
// any other use of the spending key.
var viewingKeyDomainTag = []byte("railgun:viewing-key:v1")

// IdentityFromSpendingKey builds a Railgun identity from the 32-byte spending
// key managed by Paladin. The viewing key is derived deterministically from the
// spending key (reduced into the scalar field) so that every node derives the
// same identity — and therefore the same masterPublicKey / nullifiers — for a
// given key, without needing a separately-managed viewing key.
func IdentityFromSpendingKey(spendingKey []byte) (*Identity, error) {
	if len(spendingKey) != 32 {
		return nil, fmt.Errorf("spending key must be 32 bytes, got %d", len(spendingKey))
	}
	id := &Identity{}
	copy(id.SpendingKey[:], spendingKey)

	h := sha256.Sum256(append(append([]byte{}, viewingKeyDomainTag...), spendingKey...))
	vk := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), SnarkScalarField)
	vk.FillBytes(id.ViewingKey[:])
	return id, nil
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
