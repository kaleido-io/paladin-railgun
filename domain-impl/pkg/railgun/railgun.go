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

// Package railgun exposes the public entry-point for the Railgun Paladin domain.
// Callers only need to import this package and call New() to obtain a fully
// configured plugintk.DomainAPI implementation.
package railgun

import (
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
)

// New creates and returns a new Railgun domain that implements plugintk.DomainAPI.
// Pass the Paladin-provided DomainCallbacks so that the domain can interact with
// the node's state store and verifier registry.
func New(callbacks plugintk.DomainCallbacks) plugintk.DomainAPI {
	return railgun.New(callbacks)
}
