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
	"math/big"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// MAX_INPUT_COUNT is the maximum number of notes that can be consumed in a
// single transfer transaction (matches the largest Railgun circuit size).
var MAX_INPUT_COUNT = 10

// MAX_TRANSFER_AMOUNT caps a note value to the circuit's 120-bit range.
var MAX_TRANSFER_AMOUNT = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(120), nil)

// StateSchemas groups the Paladin state schema descriptors used by the fungible
// handlers: the note schema and the commitment-tree-leaf schema.
type StateSchemas struct {
	NoteSchema     *prototk.StateSchema
	TreeLeafSchema *prototk.StateSchema
}

// baseHandler is embedded by every fungible operation handler, providing
// common helper methods.
type baseHandler struct {
	name         string
	stateSchemas *StateSchemas
}

func (h *baseHandler) getAlgo() string {
	return railgunsignerapi.AlgoDomainRailgunSnarkBJJ(h.name)
}

// validateTransferParams validates a list of transfer parameter entries.
func validateTransferParams(ctx context.Context, params []*types.TransferParamEntry) error {
	if len(params) == 0 {
		return i18n.NewError(ctx, msgs.MsgNoTransferParams)
	}
	total := big.NewInt(0)
	for i, p := range params {
		if p.To == "" {
			return i18n.NewError(ctx, msgs.MsgNoParamTo, i)
		}
		if err := validateValueParam(ctx, p.Value, i); err != nil {
			return err
		}
		total.Add(total, p.Value.Int())
	}
	if total.Cmp(MAX_TRANSFER_AMOUNT) >= 0 {
		return i18n.NewError(ctx, msgs.MsgParamTotalValueInRange)
	}
	return nil
}

// validateValueParam validates that a single value parameter is present and
// within the circuit's supported range.
func validateValueParam(ctx context.Context, value *pldtypes.HexUint256, i int) error {
	if value == nil {
		return i18n.NewError(ctx, msgs.MsgNoParamValue, i)
	}
	if value.Int().Sign() != 1 {
		return i18n.NewError(ctx, msgs.MsgParamValueInRange, i)
	}
	return nil
}
