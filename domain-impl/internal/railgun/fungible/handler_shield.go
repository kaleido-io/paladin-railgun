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

package fungible

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	pb "github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

var _ types.DomainHandler = &shieldHandler{}

type shieldHandler struct {
	baseHandler
	callbacks plugintk.DomainCallbacks
}

// NewShieldHandler creates the handler for shielding: depositing ERC-20 tokens
// and creating a private note for the recipient. Shield requires no zk-proof.
func NewShieldHandler(name string, callbacks plugintk.DomainCallbacks, schemas *StateSchemas) *shieldHandler {
	return &shieldHandler{baseHandler{name: name, stateSchemas: schemas}, callbacks}
}

func (h *shieldHandler) ValidateParams(ctx context.Context, config *types.DomainInstanceConfig, params string) (interface{}, error) {
	var p types.ShieldParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorParseDomainConfig, err)
	}
	if p.To == "" {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamTo, 0)
	}
	if p.Token == nil {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamValue, 0)
	}
	if err := validateValueParam(ctx, p.Value, 0); err != nil {
		return nil, err
	}
	return &p, nil
}

func (h *shieldHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *pb.InitTransactionRequest) (*pb.InitTransactionResponse, error) {
	p := tx.Params.(*types.ShieldParams)
	return &pb.InitTransactionResponse{
		RequiredVerifiers: []*pb.ResolveVerifierRequest{
			addressVerifierRequest(p.To, h.getAlgo()),
		},
	}, nil
}

func (h *shieldHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *pb.AssembleTransactionRequest) (*pb.AssembleTransactionResponse, error) {
	p := tx.Params.(*types.ShieldParams)

	_, mpk, _, err := resolveAddress(req.ResolvedVerifiers, p.To, h.getAlgo())
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorLoadOwnerPubKey, err)
	}

	// Predict the new note's leaf index = current tree size.
	_, nextLeaf, err := loadTree(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
	}

	note := newNote(mpk, *p.Token, p.Value, nextLeaf)
	state, err := makeNoteState(ctx, h.stateSchemas, h.name, note, p.To)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorCreateNewState, err)
	}

	return &pb.AssembleTransactionResponse{
		AssemblyResult: pb.AssembleTransactionResponse_OK,
		AssembledTransaction: &pb.AssembledTransaction{
			OutputStates: []*pb.NewState{state},
		},
		AttestationPlan: []*pb.AttestationRequest{}, // shield needs no proof
	}, nil
}

func (h *shieldHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *pb.EndorseTransactionRequest) (*pb.EndorseTransactionResponse, error) {
	return nil, nil
}

func (h *shieldHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *pb.PrepareTransactionRequest) (*pb.PrepareTransactionResponse, error) {
	note, err := makeNote(req.OutputStates[0].StateDataJson)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorParseOutputStates, err)
	}
	npk, err := note.NotePublicKey()
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorHashOutputState, err)
	}

	zero := "0x" + strings.Repeat("00", 32)
	// Embed the Paladin transaction id in the (otherwise unused) shieldKey so
	// HandleEventBatch can correlate the on-chain Shield event back to this
	// private transaction. The contract does not validate the ciphertext.
	shieldRequest := map[string]interface{}{
		"preimage": map[string]interface{}{
			"npk": railgunnote.EncodeField(npk.Int()),
			"token": map[string]interface{}{
				"tokenType":    0,
				"tokenAddress": note.Token.String(),
				"tokenSubID":   "0",
			},
			"value": note.Value.Int().Text(10),
		},
		"ciphertext": map[string]interface{}{
			"encryptedBundle": []string{zero, zero, zero},
			"shieldKey":       req.Transaction.TransactionId,
		},
	}
	paramsJSON, err := json.Marshal(map[string]interface{}{
		"_shieldRequests": []interface{}{shieldRequest},
	})
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorMarshalPrepedParams, err)
	}

	signer := req.Transaction.From
	return &pb.PrepareTransactionResponse{
		Transaction: &pb.PreparedTransaction{
			FunctionAbiJson: mustEntryJSON(shieldFunctionABI),
			ParamsJson:      string(paramsJSON),
			RequiredSigner:  &signer,
		},
	}, nil
}
