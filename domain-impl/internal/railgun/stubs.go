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

package railgun

import (
	"context"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// CheckStateCompletion reports whether the transaction has all the states it
// needs. Railgun requires complete data sets, so we defer to the runtime's
// pre-computed "first unavailable" hint.
func (r *Railgun) CheckStateCompletion(ctx context.Context, req *prototk.CheckStateCompletionRequest) (*prototk.CheckStateCompletionResponse, error) {
	res := &prototk.CheckStateCompletionResponse{}
	if req.UnavailableStates != nil {
		res.NextMissingStateId = req.UnavailableStates.FirstUnavailableId
	}
	return res, nil
}

// IsBaseLedgerRevertRetryable defaults to the sequencer's retry behaviour.
func (r *Railgun) IsBaseLedgerRevertRetryable(_ context.Context, _ *prototk.IsBaseLedgerRevertRetryableRequest) (*prototk.IsBaseLedgerRevertRetryableResponse, error) {
	return &prototk.IsBaseLedgerRevertRetryableResponse{Retryable: true}, nil
}

// ConfigurePrivacyGroup is not supported by the Railgun domain.
func (r *Railgun) ConfigurePrivacyGroup(ctx context.Context, _ *prototk.ConfigurePrivacyGroupRequest) (*prototk.ConfigurePrivacyGroupResponse, error) {
	return nil, i18n.NewError(ctx, msgs.MsgNotImplemented)
}

// InitPrivacyGroup is not supported by the Railgun domain.
func (r *Railgun) InitPrivacyGroup(ctx context.Context, _ *prototk.InitPrivacyGroupRequest) (*prototk.InitPrivacyGroupResponse, error) {
	return nil, i18n.NewError(ctx, msgs.MsgNotImplemented)
}

// WrapPrivacyGroupEVMTX is not supported by the Railgun domain.
func (r *Railgun) WrapPrivacyGroupEVMTX(ctx context.Context, _ *prototk.WrapPrivacyGroupEVMTXRequest) (*prototk.WrapPrivacyGroupEVMTXResponse, error) {
	return nil, i18n.NewError(ctx, msgs.MsgNotImplemented)
}

// InvokeRPC is not supported by the Railgun domain.
func (r *Railgun) InvokeRPC(ctx context.Context, _ *prototk.InvokeRPCRequest) (*prototk.InvokeRPCResponse, error) {
	return nil, i18n.NewError(ctx, msgs.MsgNotImplemented)
}
