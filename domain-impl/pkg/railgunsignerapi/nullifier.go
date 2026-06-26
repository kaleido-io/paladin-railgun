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

package railgunsignerapi

import (
	"context"
	"encoding/json"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
)

// noteForNullifier extracts the leaf index from a Railgun note's state data.
// The nullifier depends only on the owner's nullifying key (from the private
// key) and the note's on-chain leaf index.
type noteForNullifier struct {
	LeafIndex string `json:"leafIndex"`
}

// ComputeNullifier derives the Railgun nullifier for a note:
//
//	Poseidon(nullifyingKey, leafIndex)
//
// where nullifyingKey = Poseidon(viewingKey) is derived from the owner's
// spending key (privateKey). Paladin invokes this via the note's NullifierSpec
// with the owner's key, persisting the nullifier so it can be matched against
// on-chain Nullified events.
func ComputeNullifier(_ context.Context, privateKey []byte, payload []byte) ([]byte, error) {
	var n noteForNullifier
	if err := json.Unmarshal(payload, &n); err != nil {
		return nil, err
	}
	leafIndex, err := railgunnote.DecodeField(n.LeafIndex)
	if err != nil {
		return nil, err
	}

	id, err := railgunnote.IdentityFromSpendingKey(privateKey)
	if err != nil {
		return nil, err
	}
	nullifyingKey, err := id.NullifyingKey()
	if err != nil {
		return nil, err
	}
	nullifier, err := railgunnote.Nullifier(nullifyingKey, leafIndex.Uint64())
	if err != nil {
		return nil, err
	}
	return nullifier.FillBytes(make([]byte, 32)), nil
}

// MasterPublicKey returns the Railgun masterPublicKey (the domain verifier) for
// a spending key, as a 0x-prefixed 32-byte hex string.
func MasterPublicKey(privateKey []byte) (string, error) {
	id, err := railgunnote.IdentityFromSpendingKey(privateKey)
	if err != nil {
		return "", err
	}
	return id.MasterPublicKeyHex()
}
