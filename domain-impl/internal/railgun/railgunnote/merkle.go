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

package railgunnote

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"golang.org/x/crypto/sha3"
)

// MerkleDepth is the depth of the Railgun commitment tree (Commitments.sol).
const MerkleDepth = 16

// ZeroValue is the leaf zero value of the Railgun tree:
//
//	keccak256("Railgun") % SNARK_SCALAR_FIELD
func ZeroValue() *big.Int {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("Railgun"))
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), SnarkScalarField)
}

// zeroLevels returns the zero node value at each level 0..depth, where
// zeros[0] = ZeroValue and zeros[i+1] = Poseidon(zeros[i], zeros[i]).
func zeroLevels(depth int) ([]*big.Int, error) {
	zeros := make([]*big.Int, depth+1)
	zeros[0] = ZeroValue()
	for i := 1; i <= depth; i++ {
		h, err := poseidon.Hash([]*big.Int{zeros[i-1], zeros[i-1]})
		if err != nil {
			return nil, err
		}
		zeros[i] = h
	}
	return zeros, nil
}

// MerkleTree is an append-only Poseidon binary Merkle tree mirroring the
// RailgunSmartWallet's on-chain commitment accumulator. Leaves are inserted
// left-to-right; empty positions hash with the per-level zero value.
type MerkleTree struct {
	depth  int
	zeros  []*big.Int
	leaves []*big.Int
}

// NewMerkleTree creates an empty tree of the given depth.
func NewMerkleTree(depth int) (*MerkleTree, error) {
	zeros, err := zeroLevels(depth)
	if err != nil {
		return nil, err
	}
	return &MerkleTree{depth: depth, zeros: zeros}, nil
}

// Insert appends a leaf and returns its leaf index.
func (m *MerkleTree) Insert(leaf *big.Int) int {
	idx := len(m.leaves)
	m.leaves = append(m.leaves, new(big.Int).Set(leaf))
	return idx
}

// NumLeaves returns the number of inserted leaves.
func (m *MerkleTree) NumLeaves() int { return len(m.leaves) }

// build computes the non-zero (occupied) nodes per level. A node is occupied if
// any leaf lies beneath it; all other nodes equal the level's zero value.
func (m *MerkleTree) build() []map[int]*big.Int {
	levels := make([]map[int]*big.Int, m.depth+1)
	levels[0] = make(map[int]*big.Int, len(m.leaves))
	for i, leaf := range m.leaves {
		levels[0][i] = leaf
	}
	for lvl := 0; lvl < m.depth; lvl++ {
		levels[lvl+1] = make(map[int]*big.Int)
		parents := make(map[int]struct{})
		for idx := range levels[lvl] {
			parents[idx/2] = struct{}{}
		}
		for p := range parents {
			left := m.nodeFrom(levels[lvl], lvl, 2*p)
			right := m.nodeFrom(levels[lvl], lvl, 2*p+1)
			h, _ := poseidon.Hash([]*big.Int{left, right})
			levels[lvl+1][p] = h
		}
	}
	return levels
}

func (m *MerkleTree) nodeFrom(level map[int]*big.Int, lvl, idx int) *big.Int {
	if v, ok := level[idx]; ok {
		return v
	}
	return m.zeros[lvl]
}

// Root returns the current Merkle root.
func (m *MerkleTree) Root() *big.Int {
	if len(m.leaves) == 0 {
		return m.zeros[m.depth]
	}
	levels := m.build()
	if v, ok := levels[m.depth][0]; ok {
		return v
	}
	return m.zeros[m.depth]
}

// Proof returns the sibling path (pathElements) for the leaf at leafIndex,
// of length depth, suitable for the joinsplit circuit's MerkleProofVerifier.
func (m *MerkleTree) Proof(leafIndex int) []*big.Int {
	levels := m.build()
	path := make([]*big.Int, m.depth)
	idx := leafIndex
	for lvl := 0; lvl < m.depth; lvl++ {
		sibling := idx ^ 1
		path[lvl] = m.nodeFrom(levels[lvl], lvl, sibling)
		idx /= 2
	}
	return path
}

// VerifyProof recomputes the root from a leaf + sibling path (mirrors the
// circuit's MerkleProofVerifier) — used in tests.
func VerifyProof(leaf *big.Int, leafIndex int, path []*big.Int) (*big.Int, error) {
	cur := leaf
	idx := leafIndex
	for lvl := 0; lvl < len(path); lvl++ {
		var left, right *big.Int
		if idx&1 == 0 {
			left, right = cur, path[lvl]
		} else {
			left, right = path[lvl], cur
		}
		h, err := poseidon.Hash([]*big.Int{left, right})
		if err != nil {
			return nil, err
		}
		cur = h
		idx /= 2
	}
	return cur, nil
}
