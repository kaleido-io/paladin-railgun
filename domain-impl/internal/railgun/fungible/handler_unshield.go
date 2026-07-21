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
	"encoding/json"
	"math/big"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguntx"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	pb "github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

var _ types.DomainHandler = &unshieldHandler{}

type unshieldHandler struct {
	baseHandler
	callbacks plugintk.DomainCallbacks
	chainID   int64
}

// NewUnshieldHandler creates the handler for unshielding: burning private notes
// to withdraw ERC-20 tokens to a public address. Expressed on-chain as a
// transact with BoundParams.unshield set.
func NewUnshieldHandler(name string, callbacks plugintk.DomainCallbacks, schemas *StateSchemas, chainID int64) *unshieldHandler {
	return &unshieldHandler{baseHandler{name: name, stateSchemas: schemas}, callbacks, chainID}
}

func (h *unshieldHandler) ValidateParams(ctx context.Context, config *types.DomainInstanceConfig, params string) (interface{}, error) {
	var p types.UnshieldParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorParseDomainConfig, err)
	}
	if p.To == nil || p.Token == nil {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamTo, 0)
	}
	if err := validateValueParam(ctx, p.Value, 0); err != nil {
		return nil, err
	}
	return &p, nil
}

func (h *unshieldHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *pb.InitTransactionRequest) (*pb.InitTransactionResponse, error) {
	return &pb.InitTransactionResponse{
		RequiredVerifiers: []*pb.ResolveVerifierRequest{
			addressVerifierRequest(tx.Transaction.From, h.getAlgo()),
		},
	}, nil
}

func (h *unshieldHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *pb.AssembleTransactionRequest) (*pb.AssembleTransactionResponse, error) {
	p := tx.Params.(*types.UnshieldParams)

	senderMpkHex, senderMpk, _, err := resolveAddress(req.ResolvedVerifiers, tx.Transaction.From, h.getAlgo())
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, tx.Transaction.From)
	}

	inputs, revert, err := prepareInputsForTransfer(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext, senderMpkHex, p.Value.Int())
	if err != nil {
		if revert {
			msg := err.Error()
			return &pb.AssembleTransactionResponse{AssemblyResult: pb.AssembleTransactionResponse_REVERT, RevertReason: &msg}, nil
		}
		return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxInputs, err)
	}

	tree, nextLeaf, err := loadTree(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
	}

	var outStates []*pb.NewState
	var payloadOutputs []PayloadOutput

	// Always emit a change note (zero-value if the unshield consumes the full
	// balance). This guarantees the transaction has a commitment ciphertext slot
	// — so it emits a Transact event carrying the tx-id used for event
	// correlation — and keeps the unshield a fixed-shape transact.
	change := new(big.Int).Sub(inputs.total, p.Value.Int())
	changeHex := pldtypes.HexUint256(*change)
	changeNote := newNote(senderMpk, *p.Token, &changeHex, nextLeaf)
	changeState, err := makeNoteState(ctx, h.stateSchemas, h.name, changeNote, tx.Transaction.From)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxChange, err)
	}
	changeNPK, err := changeNote.NotePublicKey()
	if err != nil {
		return nil, err
	}
	outStates = append(outStates, changeState)
	payloadOutputs = append(payloadOutputs, PayloadOutput{NPK: changeNPK.Int().Text(10), Value: change.Text(10)})

	// The unshield output: npk = recipient address as a field element. This is a
	// circuit output and on-chain commitment, but NOT a private note state.
	unshieldNPK := railguntx.UnshieldNPK(toArray20(*p.To))
	payloadOutputs = append(payloadOutputs, PayloadOutput{NPK: unshieldNPK.Text(10), Value: p.Value.Int().Text(10)})

	payload, err := buildProvingPayload(tree, *p.Token, inputs, payloadOutputs, h.chainID, true, p.Value.Int().Text(10), tx.Transaction.TransactionId)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFormatProvingReq, err)
	}

	return &pb.AssembleTransactionResponse{
		AssemblyResult: pb.AssembleTransactionResponse_OK,
		AssembledTransaction: &pb.AssembledTransaction{
			InputStates:  inputs.states,
			OutputStates: outStates,
		},
		AttestationPlan: []*pb.AttestationRequest{snarkAttestation(tx.Transaction.From, h.getAlgo(), payload)},
	}, nil
}

func (h *unshieldHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *pb.EndorseTransactionRequest) (*pb.EndorseTransactionResponse, error) {
	return nil, nil
}

func (h *unshieldHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *pb.PrepareTransactionRequest) (*pb.PrepareTransactionResponse, error) {
	return prepareTransact(ctx, req)
}
