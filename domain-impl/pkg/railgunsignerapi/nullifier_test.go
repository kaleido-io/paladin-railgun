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

package railgunsignerapi

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/stretchr/testify/require"
)

// TestComputeNullifierMatchesWitness verifies the nullifier persisted via a
// note's NullifierSpec (ComputeNullifier from note state data) equals the
// nullifier the spend proof witness produces — so on-chain Nullified events
// match the recorded note states.
func TestComputeNullifierMatchesWitness(t *testing.T) {
	skBytes, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	id, err := railgunnote.IdentityFromSpendingKey(skBytes)
	require.NoError(t, err)

	const leafIndex = uint64(7)

	// As recorded in a note state (owner + leafIndex are what matter).
	noteJSON := `{"owner":"0x01","random":"0x02","token":"0x00000000000000000000000000000000000000aa","value":"0x03e8","leafIndex":"0x7"}`
	got, err := ComputeNullifier(context.Background(), skBytes, []byte(noteJSON))
	require.NoError(t, err)

	// As produced by the spend witness.
	nullifyingKey, err := id.NullifyingKey()
	require.NoError(t, err)
	want, err := railgunnote.Nullifier(nullifyingKey, leafIndex)
	require.NoError(t, err)

	require.Equal(t, 0, new(big.Int).SetBytes(got).Cmp(want), "persisted nullifier must equal witness nullifier")
}
