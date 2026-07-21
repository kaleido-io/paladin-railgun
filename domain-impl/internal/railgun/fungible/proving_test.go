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
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunprover"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguntx"
	"github.com/stretchr/testify/require"
)

// TestGenerateTransactionProofFromPayload exercises the exact Sign-side path the
// domain runs: a handler-built ProvingPayload + a spending key -> identity ->
// witness -> Groth16 proof -> assembled on-chain Transaction.
func TestGenerateTransactionProofFromPayload(t *testing.T) {
	circuitsDir := os.Getenv("RAILGUN_CIRCUITS_DIR")
	if circuitsDir == "" {
		t.Skip("set RAILGUN_CIRCUITS_DIR to run the proving test")
	}

	skBytes, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	id, err := railgunnote.IdentityFromSeed(skBytes)
	require.NoError(t, err)
	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)

	var addr [20]byte
	addr[19] = 0xaa
	token := railgunnote.TokenIDERC20(addr)

	// One input note owned by this identity, inserted into the tree at leaf 0.
	inRandom := big.NewInt(0x33)
	inNPK, err := railgunnote.NotePublicKey(mpk, inRandom)
	require.NoError(t, err)
	inCommitment, err := railgunnote.Commitment(inNPK, token, big.NewInt(1000))
	require.NoError(t, err)
	tree, err := railgunnote.NewMerkleTree(railgunnote.MerkleDepth)
	require.NoError(t, err)
	leafIndex := tree.Insert(inCommitment)
	root := tree.Root()
	path := tree.Proof(leafIndex)
	pathStr := make([]string, len(path))
	for i, e := range path {
		pathStr[i] = e.Text(10)
	}

	// Two outputs back to self (600 + 400) — a 1x2 transfer.
	out1, err := railgunnote.NotePublicKey(mpk, big.NewInt(0x44))
	require.NoError(t, err)
	out2, err := railgunnote.NotePublicKey(mpk, big.NewInt(0x55))
	require.NoError(t, err)

	z := "0x" + strings.Repeat("00", 32)
	payload := &ProvingPayload{
		Token:        token.Text(10),
		TokenAddress: "0x00000000000000000000000000000000000000aa",
		MerkleRoot:   root.Text(10),
		Inputs: []PayloadInput{
			{Random: inRandom.Text(10), Value: "1000", LeafIndex: uint64(leafIndex), PathElements: pathStr},
		},
		Outputs: []PayloadOutput{
			{NPK: out1.Text(10), Value: "600"},
			{NPK: out2.Text(10), Value: "400"},
		},
		BoundParams: railguntx.BoundParams{
			TreeNumber: 0, MinGasPrice: "0", Unshield: railguntx.UnshieldNone, ChainID: "31337",
			AdaptContract: "0x0000000000000000000000000000000000000000",
			AdaptParams:   z,
			CommitmentCiphertext: []railguntx.CommitmentCiphertext{
				{Ciphertext: [4]string{z, z, z, z}, BlindedSenderViewingKey: z, BlindedReceiverViewingKey: z, AnnotationData: "0x", Memo: "0x"},
				{Ciphertext: [4]string{z, z, z, z}, BlindedSenderViewingKey: z, BlindedReceiverViewingKey: z, AnnotationData: "0x", Memo: "0x"},
			},
		},
	}
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	prover := railgunprover.NewProver(circuitsDir)
	txnJSON, err := GenerateTransactionProof(context.Background(), prover, skBytes, payloadJSON)
	require.NoError(t, err, "Sign-side proof generation must succeed")

	var txn railguntx.Transaction
	require.NoError(t, json.Unmarshal(txnJSON, &txn))
	require.NotNil(t, txn.Proof)
	require.Len(t, txn.Nullifiers, 1, "one input -> one nullifier")
	require.Len(t, txn.Commitments, 2, "two outputs -> two commitments")
	require.Equal(t, root.Text(10), txn.MerkleRoot)

	// The on-chain ABI object is well-formed (proof a/b/c + bytes32 fields).
	obj := txn.ABIObject()
	require.Contains(t, obj, "proof")
	require.Contains(t, obj, "nullifiers")
	require.Contains(t, obj, "boundParams")
}
