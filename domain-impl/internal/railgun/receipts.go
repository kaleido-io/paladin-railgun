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

package railgun

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// BuildReceipt produces a domain-specific receipt for a completed Railgun
// transaction.  It mirrors the structure of the Noto domain receipt: it lists
// the note states by role (inputs/outputs/read/info) and, where the note data
// is available, reconstructs the net value transfers between owners.
func (r *Railgun) BuildReceipt(ctx context.Context, req *prototk.BuildReceiptRequest) (*prototk.BuildReceiptResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")

	// If some states referenced by the transaction are not available locally,
	// we cannot build a complete receipt.
	if req.UnavailableStates {
		return nil, nil
	}

	receipt := &types.RailgunDomainReceipt{}
	var err error

	// Note states grouped by role
	if receipt.States.Inputs, err = r.receiptStates(ctx, r.filterSchema(req.InputStates, []string{r.noteSchema.Id})); err != nil {
		return nil, err
	}
	if receipt.States.Outputs, err = r.receiptStates(ctx, r.filterSchema(req.OutputStates, []string{r.noteSchema.Id})); err != nil {
		return nil, err
	}
	if receipt.States.ReadInputs, err = r.receiptStates(ctx, r.filterSchema(req.ReadStates, []string{r.noteSchema.Id})); err != nil {
		return nil, err
	}

	// Reconstruct the net value transfers from the note data.
	if receipt.Transfers, err = r.receiptTransfers(ctx, req); err != nil {
		return nil, err
	}

	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return &prototk.BuildReceiptResponse{
		ReceiptJson: string(receiptJSON),
	}, nil
}

// receiptStates converts a list of endorsable states into receipt state
// references carrying the raw decoded note/info data.
func (r *Railgun) receiptStates(ctx context.Context, states []*prototk.EndorsableState) ([]*types.ReceiptState, error) {
	result := make([]*types.ReceiptState, len(states))
	for i, state := range states {
		id, err := pldtypes.ParseHexBytes(ctx, state.Id)
		if err != nil {
			return nil, err
		}
		schemaID, err := pldtypes.ParseBytes32Ctx(ctx, state.SchemaId)
		if err != nil {
			return nil, err
		}
		result[i] = &types.ReceiptState{
			ID:     id,
			Schema: schemaID,
			Data:   pldtypes.RawJSON(state.StateDataJson),
		}
	}
	return result, nil
}

// receiptTransfers reconstructs the net per-owner value movement of a
// transaction from its input and output notes.  Inputs are summed against the
// sender; outputs are credited to their respective owners.  A single sender is
// assumed (as enforced by the Railgun circuits).
func (r *Railgun) receiptTransfers(ctx context.Context, req *prototk.BuildReceiptRequest) ([]*types.ReceiptTransfer, error) {
	inputNotes, err := r.parseNoteList(ctx, r.filterSchema(req.InputStates, []string{r.noteSchema.Id}))
	if err != nil {
		return nil, err
	}
	outputNotes, err := r.parseNoteList(ctx, r.filterSchema(req.OutputStates, []string{r.noteSchema.Id}))
	if err != nil {
		return nil, err
	}

	var from string
	fromAmount := big.NewInt(0)
	to := make(map[string]*big.Int)
	order := make([]string, 0) // preserve deterministic recipient ordering

	parsedOK := true
	for _, note := range inputNotes {
		owner := note.Owner.String()
		if from == "" {
			from = owner
		} else if owner != from {
			parsedOK = false
		}
		fromAmount.Add(fromAmount, note.Value.Int())
	}
	for _, note := range outputNotes {
		owner := note.Owner.String()
		amount := note.Value.Int()
		if amount.Sign() == 0 {
			continue // skip zero-value padding notes
		}
		if owner == from {
			fromAmount.Sub(fromAmount, amount)
		} else if existing, ok := to[owner]; ok {
			existing.Add(existing, amount)
		} else {
			to[owner] = new(big.Int).Set(amount)
			order = append(order, owner)
		}
	}
	if !parsedOK {
		log.L(ctx).Warnf("Failed to reconstruct transfers: multiple distinct input owners")
		return nil, nil
	}

	// Special case: a pure unshield/burn (inputs consumed, no recipients) leaves
	// a positive residual on the sender with no destination.
	if len(to) == 0 && from != "" && fromAmount.Sign() > 0 {
		return []*types.ReceiptTransfer{{
			From:   from,
			Amount: (*pldtypes.HexUint256)(fromAmount),
		}}, nil
	}

	transfers := make([]*types.ReceiptTransfer, 0, len(order))
	for _, owner := range order {
		amount := to[owner]
		if amount.Sign() > 0 {
			t := &types.ReceiptTransfer{
				To:     owner,
				Amount: (*pldtypes.HexUint256)(amount),
			}
			if from != "" {
				t.From = from
			}
			transfers = append(transfers, t)
		}
	}
	return transfers, nil
}

// parseNoteList decodes the note payload of each endorsable state.
func (r *Railgun) parseNoteList(ctx context.Context, states []*prototk.EndorsableState) ([]*types.RailgunNote, error) {
	notes := make([]*types.RailgunNote, 0, len(states))
	for _, state := range states {
		var note types.RailgunNote
		if err := json.Unmarshal([]byte(state.StateDataJson), &note); err != nil {
			return nil, err
		}
		notes = append(notes, &note)
	}
	return notes, nil
}

// filterSchema returns only the states whose schema ID is in the provided set.
func (r *Railgun) filterSchema(states []*prototk.EndorsableState, schemas []string) []*prototk.EndorsableState {
	var filtered []*prototk.EndorsableState
	for _, state := range states {
		for _, schema := range schemas {
			if state.SchemaId == schema {
				filtered = append(filtered, state)
				break
			}
		}
	}
	return filtered
}
