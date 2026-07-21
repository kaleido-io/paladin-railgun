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

package types

import (
	"context"
	"encoding/json"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

// RailgunNoteABI is the schema for a Railgun private note (a shielded UTXO).
//
//   - owner:     the recipient's masterPublicKey (Railgun address), a field element
//   - random:    the note's random scalar (npk = Poseidon(owner, random))
//   - token:     the ERC-20 token address backing the note
//   - value:     the note value
//   - leafIndex: the note's position in the on-chain commitment tree, needed to
//     derive the nullifier (Poseidon(nullifyingKey, leafIndex))
var RailgunNoteABI = &abi.Parameter{
	Name:         "RailgunNote",
	Type:         "tuple",
	InternalType: "struct RailgunNote",
	Components: abi.ParameterArray{
		{Name: "owner", Type: "uint256", Indexed: true},
		{Name: "random", Type: "uint256"},
		{Name: "token", Type: "address", Indexed: true},
		{Name: "value", Type: "uint256", Indexed: true},
		{Name: "leafIndex", Type: "uint256", Indexed: true},
	},
}

// RailgunNote is the off-chain representation of a shielded note. Its on-chain
// identity (state id) is the Poseidon commitment Poseidon(npk, tokenID, value).
type RailgunNote struct {
	Owner     *pldtypes.HexUint256 `json:"owner"` // masterPublicKey
	Random    *pldtypes.HexUint256 `json:"random"`
	Token     pldtypes.EthAddress  `json:"token"`
	Value     *pldtypes.HexUint256 `json:"value"`
	LeafIndex *pldtypes.HexUint256 `json:"leafIndex"`

	hash *pldtypes.HexUint256
}

// NotePublicKey returns npk = Poseidon(owner, random).
func (n *RailgunNote) NotePublicKey() (*pldtypes.HexUint256, error) {
	npk, err := railgunnote.NotePublicKey(n.Owner.Int(), n.Random.Int())
	if err != nil {
		return nil, err
	}
	return (*pldtypes.HexUint256)(npk), nil
}

// TokenID returns the circuit token id for this note's ERC-20 token.
func (n *RailgunNote) TokenID() *pldtypes.HexUint256 {
	var addr [20]byte
	copy(addr[:], n.Token[:])
	return (*pldtypes.HexUint256)(railgunnote.TokenIDERC20(addr))
}

// Hash computes the Poseidon commitment Poseidon(npk, tokenID, value) — the
// note's on-chain leaf and Paladin state id.
func (n *RailgunNote) Hash(ctx context.Context) (*pldtypes.HexUint256, error) {
	if n.hash == nil {
		npk, err := n.NotePublicKey()
		if err != nil {
			return nil, err
		}
		commitment, err := railgunnote.Commitment(npk.Int(), n.TokenID().Int(), n.Value.Int())
		if err != nil {
			return nil, err
		}
		n.hash = (*pldtypes.HexUint256)(commitment)
	}
	return n.hash, nil
}

// NoteState wraps a RailgunNote with its chain-level identity (for queries).
type NoteState struct {
	ID              pldtypes.HexUint256 `json:"id"`
	Created         pldtypes.Timestamp  `json:"created"`
	ContractAddress pldtypes.EthAddress `json:"contractAddress"`
	Data            RailgunNote         `json:"data"`
}

// RailgunTreeLeafABI is the schema for a single leaf of the on-chain commitment
// tree, recorded from Shield/Transact events so the domain can rebuild the tree
// and generate Merkle proofs when spending.
var RailgunTreeLeafABI = &abi.Parameter{
	Name:         "RailgunTreeLeaf",
	Type:         "tuple",
	InternalType: "struct RailgunTreeLeaf",
	Components: abi.ParameterArray{
		{Name: "leafIndex", Type: "uint256", Indexed: true},
		{Name: "commitment", Type: "uint256", Indexed: true},
	},
}

// RailgunTreeLeaf records a commitment's position in the on-chain tree.
type RailgunTreeLeaf struct {
	LeafIndex  *pldtypes.HexUint256 `json:"leafIndex"`
	Commitment *pldtypes.HexUint256 `json:"commitment"`
}

// GetStateSchemas returns the domain's state schemas in the order the runtime
// indexes them: [0] note, [1] tree leaf.
func GetStateSchemas() ([]string, error) {
	noteJSON, err := json.Marshal(RailgunNoteABI)
	if err != nil {
		return nil, err
	}
	treeLeafJSON, err := json.Marshal(RailgunTreeLeafABI)
	if err != nil {
		return nil, err
	}
	return []string{
		string(noteJSON),
		string(treeLeafJSON),
	}, nil
}
