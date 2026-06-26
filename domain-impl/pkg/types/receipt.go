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

package types

import "github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"

// RailgunDomainReceipt is the domain-specific receipt returned for a completed
// Railgun transaction.  It summarises the note states consumed/created and the
// net value transfers between BabyJubJub owners that could be reconstructed
// from the available (decryptable) note data.
type RailgunDomainReceipt struct {
	States    ReceiptStates       `json:"states"`
	Transfers []*ReceiptTransfer  `json:"transfers,omitempty"`
	Data      pldtypes.HexBytes   `json:"data,omitempty"`
	Sender    string              `json:"sender,omitempty"`
}

// ReceiptStates groups the note states involved in a transaction by their role.
type ReceiptStates struct {
	Inputs     []*ReceiptState `json:"inputs,omitempty"`
	Outputs    []*ReceiptState `json:"outputs,omitempty"`
	ReadInputs []*ReceiptState `json:"readInputs,omitempty"`
	Info       []*ReceiptState `json:"info,omitempty"`
}

// ReceiptState is a single state reference with its decoded data payload.
type ReceiptState struct {
	ID     pldtypes.HexBytes `json:"id"`
	Schema pldtypes.Bytes32  `json:"schema"`
	Data   pldtypes.RawJSON  `json:"data"`
}

// ReceiptTransfer describes a net value movement between two Railgun owners
// (identified by their compressed BabyJubJub public keys). From/To are nil for
// shield (mint) and unshield (burn) respectively.
type ReceiptTransfer struct {
	From   string               `json:"from,omitempty"`
	To     string               `json:"to,omitempty"`
	Amount *pldtypes.HexUint256 `json:"amount"`
}
