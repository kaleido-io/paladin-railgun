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

package fungible

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	pb "github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// -----------------------------------------------------------------------
// Note helpers
// -----------------------------------------------------------------------

func makeNote(stateData string) (*types.RailgunNote, error) {
	note := &types.RailgunNote{}
	err := json.Unmarshal([]byte(stateData), note)
	return note, err
}

// newRandom generates a fresh 16-byte (128-bit) note random. Railgun notes use a
// 16-byte random (it is one field of the on-chain note ciphertext, random‖value),
// so keeping it 16 bytes makes commitments and ciphertext interoperable with real
// Railgun wallets. 16 bytes is always < the scalar field, so npk = Poseidon(mpk,
// random) needs no reduction.
func newRandom() *pldtypes.HexUint256 {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		panic(err)
	}
	return (*pldtypes.HexUint256)(new(big.Int).SetBytes(b))
}

// makeNoteState builds a prototk.NewState for a note, attaching the nullifier
// spec so Paladin records the note's nullifier (Poseidon(nullifyingKey,
// leafIndex)) — computed by the owner via Sign — and matches it against on-chain
// Nullified events to detect spends.
func makeNoteState(ctx context.Context, schemas *StateSchemas, domainName string, note *types.RailgunNote, ownerLookup string) (*pb.NewState, error) {
	noteJSON, err := json.Marshal(note)
	if err != nil {
		return nil, err
	}
	hash, err := note.Hash(ctx)
	if err != nil {
		return nil, err
	}
	hashStr := hexUint256To32ByteHex(hash)
	ns := &pb.NewState{
		Id:            &hashStr,
		SchemaId:      schemas.NoteSchema.Id,
		StateDataJson: string(noteJSON),
	}
	// An external "0zk" recipient (empty ownerLookup) is not a Paladin party: the
	// note is not distributed to anyone and carries no NullifierSpec (we cannot
	// compute a foreign owner's nullifier). Such a recipient recovers and spends
	// the note from the on-chain ciphertext with their own wallet.
	if ownerLookup != "" {
		ns.DistributionList = []string{ownerLookup}
		ns.NullifierSpecs = []*pb.NullifierSpec{
			{
				Party:        ownerLookup,
				Algorithm:    railgunsignerapi.AlgoDomainRailgunSnarkBJJ(domainName),
				VerifierType: railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY,
				PayloadType:  railgunsignerapi.PAYLOAD_DOMAIN_RAILGUN_NULLIFIER,
			},
		}
	}
	return ns, nil
}

// newNote constructs a note owned by ownerMpk with the given token/value and a
// predicted leaf index, with a fresh random.
func newNote(ownerMpk *big.Int, token pldtypes.EthAddress, value *pldtypes.HexUint256, leafIndex uint64) *types.RailgunNote {
	return &types.RailgunNote{
		Owner:     (*pldtypes.HexUint256)(ownerMpk),
		Random:    newRandom(),
		Token:     token,
		Value:     value,
		LeafIndex: (*pldtypes.HexUint256)(new(big.Int).SetUint64(leafIndex)),
	}
}

// -----------------------------------------------------------------------
// Input selection
// -----------------------------------------------------------------------

type preparedInputs struct {
	notes  []*types.RailgunNote
	states []*pb.StateRef
	total  *big.Int
}

// prepareInputsForTransfer selects unspent notes owned by senderMpk that sum to
// at least the requested total.
func prepareInputsForTransfer(
	ctx context.Context,
	callbacks plugintk.DomainCallbacks,
	schemas *StateSchemas,
	stateQueryContext, senderMpk string,
	total *big.Int,
) (*preparedInputs, bool, error) {
	var lastCreated int64
	sum := big.NewInt(0)
	var stateRefs []*pb.StateRef
	var notes []*types.RailgunNote

	useNullifiers := true
	for {
		qb := query.NewQueryBuilder().
			Limit(10).
			Sort(".created").
			Equal("owner", senderMpk)
		if lastCreated > 0 {
			qb.GreaterThan(".created", lastCreated)
		}
		res, err := callbacks.FindAvailableStates(ctx, &pb.FindAvailableStatesRequest{
			StateQueryContext: stateQueryContext,
			SchemaId:          schemas.NoteSchema.Id,
			QueryJson:         qb.Query().String(),
			UseNullifiers:     &useNullifiers,
		})
		if err != nil {
			return nil, false, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
		}
		if len(res.States) == 0 {
			return nil, true, i18n.NewError(ctx, msgs.MsgInsufficientFunds, sum.Text(10))
		}
		for _, state := range res.States {
			lastCreated = state.CreatedAt
			note, err := makeNote(state.DataJson)
			if err != nil {
				return nil, true, i18n.NewError(ctx, msgs.MsgInvalidNote, state.Id, err)
			}
			sum.Add(sum, note.Value.Int())
			stateRefs = append(stateRefs, &pb.StateRef{SchemaId: state.SchemaId, Id: state.Id})
			notes = append(notes, note)
			if sum.Cmp(total) >= 0 {
				return &preparedInputs{notes: notes, states: stateRefs, total: sum}, false, nil
			}
			if len(stateRefs) >= MAX_INPUT_COUNT {
				return nil, true, i18n.NewError(ctx, msgs.MsgMaxNotesReached, MAX_INPUT_COUNT)
			}
		}
	}
}

// -----------------------------------------------------------------------
// Commitment tree access (rebuilt from tree-leaf states)
// -----------------------------------------------------------------------

// loadTree queries all recorded tree-leaf states and rebuilds the Railgun
// commitment tree, returning the tree and the next free leaf index.
func loadTree(ctx context.Context, callbacks plugintk.DomainCallbacks, schemas *StateSchemas, stateQueryContext string) (*railgunnote.MerkleTree, uint64, error) {
	type leaf struct {
		index      uint64
		commitment *big.Int
	}
	var leaves []leaf
	var lastCreated int64
	for {
		qb := query.NewQueryBuilder().Limit(100).Sort(".created")
		if lastCreated > 0 {
			qb.GreaterThan(".created", lastCreated)
		}
		res, err := callbacks.FindAvailableStates(ctx, &pb.FindAvailableStatesRequest{
			StateQueryContext: stateQueryContext,
			SchemaId:          schemas.TreeLeafSchema.Id,
			QueryJson:         qb.Query().String(),
		})
		if err != nil {
			return nil, 0, err
		}
		if len(res.States) == 0 {
			break
		}
		for _, state := range res.States {
			lastCreated = state.CreatedAt
			var tl types.RailgunTreeLeaf
			if err := json.Unmarshal([]byte(state.DataJson), &tl); err != nil {
				return nil, 0, err
			}
			leaves = append(leaves, leaf{index: tl.LeafIndex.Int().Uint64(), commitment: tl.Commitment.Int()})
		}
		if len(res.States) < 100 {
			break
		}
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].index < leaves[j].index })

	tree, err := railgunnote.NewMerkleTree(railgunnote.MerkleDepth)
	if err != nil {
		return nil, 0, err
	}
	var next uint64
	for _, l := range leaves {
		// Defensive: only append contiguous leaves; a gap means missing events.
		if l.index != next {
			break
		}
		tree.Insert(l.commitment)
		next++
	}
	return tree, next, nil
}

// -----------------------------------------------------------------------
// Balance
// -----------------------------------------------------------------------

func getAccountBalance(
	ctx context.Context,
	callbacks plugintk.DomainCallbacks,
	schemas *StateSchemas,
	stateQueryContext, accountMpk string,
) (int, *big.Int, bool, error) {
	total := big.NewInt(0)
	useNullifiers := true
	qb := query.NewQueryBuilder().Limit(1000).Equal("owner", accountMpk)
	res, err := callbacks.FindAvailableStates(ctx, &pb.FindAvailableStatesRequest{
		StateQueryContext: stateQueryContext,
		SchemaId:          schemas.NoteSchema.Id,
		QueryJson:         qb.Query().String(),
		UseNullifiers:     &useNullifiers,
	})
	if err != nil {
		return 0, nil, false, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
	}
	for _, state := range res.States {
		note, err := makeNote(state.DataJson)
		if err != nil {
			return 0, nil, false, i18n.NewError(ctx, msgs.MsgInvalidNote, state.Id, err)
		}
		total.Add(total, note.Value.Int())
	}
	overflow := len(res.States) == 1000
	return len(res.States), total, overflow, nil
}

// -----------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------

// hexUint256To32ByteHex returns the 0x-prefixed 32-byte zero-padded hex of v,
// used as a Paladin state id.
func hexUint256To32ByteHex(v *pldtypes.HexUint256) string {
	return "0x" + hex.EncodeToString(v.Int().FillBytes(make([]byte, 32)))
}
