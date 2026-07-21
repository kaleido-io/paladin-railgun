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

package railgunprover

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
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/require"
)

// TestProveAndVerify1x2 builds a real 1-input / 2-output transfer witness,
// generates a Groth16 proof with go-rapidsnark, and verifies it with snarkjs
// against the circuit's verification key. A verified proof here is exactly what
// the on-chain RailgunSmartWallet verifier will accept.
//
// Requires:
//   - RAILGUN_CIRCUITS_DIR pointing at <dir>/01x02/{wasm,zkey,vkey.json}
//   - SNARKJS (path to snarkjs CLI) or `npx snarkjs` available
func TestProveAndVerify1x2(t *testing.T) {
	circuitsDir := os.Getenv("RAILGUN_CIRCUITS_DIR")
	if circuitsDir == "" {
		t.Skip("set RAILGUN_CIRCUITS_DIR to run the proving test")
	}

	// Spender identity
	var sk babyjub.PrivateKey
	skb, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	copy(sk[:], skb)
	id := &railgunnote.Identity{SpendingKey: sk}
	vk, _ := hex.DecodeString("2222222222222222222222222222222222222222222222222222222222222222")
	copy(id.ViewingKey[:], vk)

	mpk, err := id.MasterPublicKey()
	require.NoError(t, err)

	// One input note of value 1000 at leaf 0
	inRandom := big.NewInt(0x33)
	inNPK, err := railgunnote.NotePublicKey(mpk, inRandom)
	require.NoError(t, err)
	var addr [20]byte
	addr[19] = 0xaa
	token := railgunnote.TokenIDERC20(addr)
	inValue := big.NewInt(1000)
	inCommitment, err := railgunnote.Commitment(inNPK, token, inValue)
	require.NoError(t, err)

	tree, err := railgunnote.NewMerkleTree(railgunnote.MerkleDepth)
	require.NoError(t, err)
	leafIndex := tree.Insert(inCommitment)
	root := tree.Root()
	path := tree.Proof(leafIndex)

	// Two output notes: 600 to a recipient + 400 change, summing to 1000
	outRandom1 := big.NewInt(0x44)
	outRandom2 := big.NewInt(0x55)
	outNPK1, err := railgunnote.NotePublicKey(mpk, outRandom1)
	require.NoError(t, err)
	outNPK2, err := railgunnote.NotePublicKey(mpk, outRandom2)
	require.NoError(t, err)

	w, err := railgunnote.BuildWitness(&railgunnote.WitnessInputs{
		Identity:        id,
		Token:           token,
		MerkleRoot:      root,
		BoundParamsHash: big.NewInt(123456789),
		Inputs:          []railgunnote.SpendInput{{Random: inRandom, Value: inValue, LeafIndex: leafIndex, PathElements: path}},
		Outputs: []railgunnote.SpendOutput{
			{NPK: outNPK1, Value: big.NewInt(600)},
			{NPK: outNPK2, Value: big.NewInt(400)},
		},
	})
	require.NoError(t, err)

	p := NewProver(circuitsDir)
	proof, err := p.Prove(context.Background(), CircuitName(1, 2), w.Inputs)
	require.NoError(t, err, "proof generation must succeed")
	require.NotNil(t, proof.Proof)
	require.Equal(t, "groth16", strings.ToLower(proof.Proof.Protocol))

	// The first 4 public signals are [merkleRoot, boundParamsHash, nullifier, commitmentOut...].
	require.Equal(t, root.Text(10), proof.PubSignals[0], "public signal 0 = merkleRoot")

	// Verify with snarkjs against the circuit's vkey.
	dir := t.TempDir()
	proofJSON, err := json.Marshal(proof.Proof)
	require.NoError(t, err)
	pubJSON, err := json.Marshal(proof.PubSignals)
	require.NoError(t, err)
	proofPath := filepath.Join(dir, "proof.json")
	publicPath := filepath.Join(dir, "public.json")
	require.NoError(t, os.WriteFile(proofPath, proofJSON, 0o600))
	require.NoError(t, os.WriteFile(publicPath, pubJSON, 0o600))
	vkeyPath := filepath.Join(circuitsDir, CircuitName(1, 2), "vkey.json")

	var cmd *exec.Cmd
	if snarkjs := os.Getenv("SNARKJS"); snarkjs != "" {
		cmd = exec.Command(snarkjs, "groth16", "verify", vkeyPath, publicPath, proofPath)
	} else {
		cmd = exec.Command("npx", "--no-install", "snarkjs", "groth16", "verify", vkeyPath, publicPath, proofPath)
	}
	out, err := cmd.CombinedOutput()
	t.Logf("snarkjs output: %s", out)
	require.NoError(t, err, "snarkjs verification must pass")
	require.Contains(t, strings.ToUpper(string(out)), "OK", "snarkjs must report the proof valid")
}
