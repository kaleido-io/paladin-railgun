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

package railguntx

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunprover"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/require"
)

// TestBuildTransactProducesValidProof drives the full transaction builder for a
// 1-input / 2-output transfer (real boundParamsHash binding), generates the
// proof, and verifies it with snarkjs against the circuit vkey — the exact
// check the on-chain RailgunSmartWallet verifier performs.
func TestBuildTransactProducesValidProof(t *testing.T) {
	circuitsDir := os.Getenv("RAILGUN_CIRCUITS_DIR")
	if circuitsDir == "" {
		t.Skip("set RAILGUN_CIRCUITS_DIR to run the proving test")
	}

	var sk babyjub.PrivateKey
	skb, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	copy(sk[:], skb)
	id := &railgunnote.Identity{SpendingKey: sk}
	vk, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	copy(id.ViewingKey[:], vk)

	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)

	var addr [20]byte
	addr[19] = 0xaa
	token := railgunnote.TokenIDERC20(addr)

	// Input note value 1000 at leaf 0
	inRandom := big.NewInt(0x33)
	inNPK, err := railgunnote.NotePublicKey(mpk, inRandom)
	require.NoError(t, err)
	inCommitment, err := railgunnote.Commitment(inNPK, token, big.NewInt(1000))
	require.NoError(t, err)
	tree, err := railgunnote.NewMerkleTree(railgunnote.MerkleDepth)
	require.NoError(t, err)
	leafIndex := tree.Insert(inCommitment)

	// Two output notes (600 + 400)
	out1, err := railgunnote.NotePublicKey(mpk, big.NewInt(0x44))
	require.NoError(t, err)
	out2, err := railgunnote.NotePublicKey(mpk, big.NewInt(0x55))
	require.NoError(t, err)

	bp := &BoundParams{
		TreeNumber: 0, MinGasPrice: "0", Unshield: UnshieldNone, ChainID: "31337",
		AdaptContract: "0x0000000000000000000000000000000000000000",
		AdaptParams:   "0x" + strings.Repeat("00", 32),
		CommitmentCiphertext: []CommitmentCiphertext{
			placeholderCT(), placeholderCT(), // one per output commitment (transfer)
		},
	}

	p := railgunprover.NewProver(circuitsDir)
	tx, w, err := BuildTransact(context.Background(), p, &TransactBuild{
		Spender:      id,
		Token:        token,
		TokenAddress: addr,
		Tree:         tree,
		Inputs:       []SpendNote{{Random: inRandom, Value: big.NewInt(1000), LeafIndex: leafIndex}},
		Outputs:      []OutNote{{NPK: out1, Value: big.NewInt(600)}, {NPK: out2, Value: big.NewInt(400)}},
		BoundParams:  bp,
	})
	require.NoError(t, err)
	require.NotNil(t, tx.Proof)
	require.Len(t, tx.Nullifiers, 1)
	require.Len(t, tx.Commitments, 2)
	require.Equal(t, tree.Root().Text(10), tx.MerkleRoot)

	// Verify the underlying proof with snarkjs (public signals from the witness).
	verifyProofWithSnarkjs(t, circuitsDir, 1, 2, p, w)
}

func placeholderCT() CommitmentCiphertext {
	z := "0x" + strings.Repeat("00", 32)
	return CommitmentCiphertext{
		Ciphertext:                [4]string{z, z, z, z},
		BlindedSenderViewingKey:   z,
		BlindedReceiverViewingKey: z,
		AnnotationData:            "0x",
		Memo:                      "0x",
	}
}

func verifyProofWithSnarkjs(t *testing.T, circuitsDir string, nIn, nOut int, p *railgunprover.Prover, w *railgunnote.Witness) {
	proof, err := p.Prove(context.Background(), railgunprover.CircuitName(nIn, nOut), w.Inputs)
	require.NoError(t, err)
	dir := t.TempDir()
	proofJSON, _ := json.Marshal(proof.Proof)
	pubJSON, _ := json.Marshal(proof.PubSignals)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proof.json"), proofJSON, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "public.json"), pubJSON, 0o600))
	vkeyPath := filepath.Join(circuitsDir, railgunprover.CircuitName(nIn, nOut), "vkey.json")
	var cmd *exec.Cmd
	if snarkjs := os.Getenv("SNARKJS"); snarkjs != "" {
		cmd = exec.Command(snarkjs, "groth16", "verify", vkeyPath, filepath.Join(dir, "public.json"), filepath.Join(dir, "proof.json"))
	} else {
		cmd = exec.Command("npx", "--no-install", "snarkjs", "groth16", "verify", vkeyPath, filepath.Join(dir, "public.json"), filepath.Join(dir, "proof.json"))
	}
	out, err := cmd.CombinedOutput()
	t.Logf("snarkjs: %s", out)
	require.NoError(t, err)
	require.Contains(t, strings.ToUpper(string(out)), "OK")
}
