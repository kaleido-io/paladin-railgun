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

package railguntx

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func b32(h byte) string {
	hexDigit := "0123456789abcdef"
	pair := string(hexDigit[h>>4]) + string(hexDigit[h&0xf])
	return "0x" + strings.Repeat(pair, 32)
}

func TestBoundParamsHashMatchesReference(t *testing.T) {
	bp := &BoundParams{
		TreeNumber:    0,
		MinGasPrice:   "0",
		Unshield:      UnshieldNormal,
		ChainID:       "31337",
		AdaptContract: "0x0000000000000000000000000000000000000000",
		AdaptParams:   b32(0x00),
		CommitmentCiphertext: []CommitmentCiphertext{
			{
				Ciphertext:                [4]string{b32(0x11), b32(0x22), b32(0x33), b32(0x44)},
				BlindedSenderViewingKey:   b32(0x55),
				BlindedReceiverViewingKey: b32(0x66),
				AnnotationData:            "0x",
				Memo:                      "0x",
			},
		},
	}
	h, err := BoundParamsHash(context.Background(), bp)
	require.NoError(t, err)
	require.Equal(t, "1a52532cbdf8ec493ea5d340c32989a5fc9515cfc9228b23759742d3aff7288f", h.Text(16))
}
