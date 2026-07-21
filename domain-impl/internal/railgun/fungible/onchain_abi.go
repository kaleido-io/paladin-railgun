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
	_ "embed"
	"encoding/json"

	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/solutils"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

// RailgunOnChain.json carries the real on-chain function ABIs (`shield` and
// `transact`) extracted from the compiled RailgunSmartWallet artifact. The
// Railgun privacy protocol exposes exactly two state-changing entry points:
//
//   - shield(ShieldRequest[])   — deposit ERC-20 tokens, create commitments
//   - transact(Transaction[])   — private transfer and/or unshield (withdraw)
//
// There is no `mint`: new notes always originate from a shield. Withdrawals are
// expressed as a `transact` with BoundParams.unshield set.
//
//go:embed abis/RailgunOnChain.json
var railgunOnChainABIBytes []byte

var railgunOnChainABI = solutils.MustParseBuildABI(railgunOnChainABIBytes)

// shieldFunctionABI is the on-chain `shield(ShieldRequest[])` entry.
var shieldFunctionABI = railgunOnChainABI.Functions()["shield"]

// transactFunctionABI is the on-chain `transact(Transaction[])` entry, used for
// both private transfers and unshields.
var transactFunctionABI = railgunOnChainABI.Functions()["transact"]

// mustEntryJSON marshals an ABI entry to JSON for the PreparedTransaction's
// FunctionAbiJson field, panicking on the (impossible) marshal error so callers
// stay terse.
func mustEntryJSON(e *abi.Entry) string {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return string(b)
}
