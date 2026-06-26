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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/domain"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	pb "github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

var _ types.DomainCallHandler = &balanceOfHandler{}

type balanceOfHandler struct {
	baseHandler
	callbacks plugintk.DomainCallbacks
}

// NewBalanceOfHandler creates a read-only call handler that sums the value of
// all available notes for the given account key.
func NewBalanceOfHandler(name string, callbacks plugintk.DomainCallbacks, schemas *StateSchemas) *balanceOfHandler {
	return &balanceOfHandler{
		baseHandler: baseHandler{name: name, stateSchemas: schemas},
		callbacks:   callbacks,
	}
}

func (h *balanceOfHandler) ValidateParams(ctx context.Context, config *types.DomainInstanceConfig, params string) (interface{}, error) {
	var p types.BalanceOfParam
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, err
	}
	if p.Account == "" {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamAccount)
	}
	return &p, nil
}

func (h *balanceOfHandler) InitCall(ctx context.Context, tx *types.ParsedTransaction, req *pb.InitCallRequest) (*pb.InitCallResponse, error) {
	p := tx.Params.(*types.BalanceOfParam)
	return &pb.InitCallResponse{
		RequiredVerifiers: []*pb.ResolveVerifierRequest{
			{
				Lookup:       p.Account,
				Algorithm:    h.getAlgo(),
				VerifierType: railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY,
			},
		},
	}, nil
}

func (h *balanceOfHandler) ExecCall(ctx context.Context, tx *types.ParsedTransaction, req *pb.ExecCallRequest) (*pb.ExecCallResponse, error) {
	p := tx.Params.(*types.BalanceOfParam)

	resolved := domain.FindVerifier(p.Account, h.getAlgo(), railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY, req.ResolvedVerifiers)
	if resolved == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, p.Account)
	}

	count, total, overflow, err := getAccountBalance(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext, resolved.Verifier)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
	}

	totalHex := (*pldtypes.HexUint256)(total)
	countHex := pldtypes.Uint64ToUint256(uint64(count))
	result := &types.BalanceOfResult{
		TotalBalance: totalHex,
		TotalStates:  countHex,
		Overflow:     overflow,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &pb.ExecCallResponse{ResultJson: string(resultJSON)}, nil
}
