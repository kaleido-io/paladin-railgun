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

import (
	_ "embed"

	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/solutils"
)

//go:embed abis/IRailgun.json
var railgunABIJSON []byte

// RailgunABI is the Paladin domain interface that clients use to invoke
// shield, unshield, transfer, and balanceOf operations.
var RailgunABI = solutils.MustParseBuildABI(railgunABIJSON)

// Operation method names as used in function dispatch. These mirror the real
// Railgun protocol: there is no mint — new notes always originate from a shield.
const (
	METHOD_SHIELD     = "shield"
	METHOD_TRANSFER   = "transfer"
	METHOD_UNSHIELD   = "unshield"
	METHOD_BALANCE_OF = "balanceOf"
)
