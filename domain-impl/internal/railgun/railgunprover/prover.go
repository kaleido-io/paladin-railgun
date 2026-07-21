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

// Package railgunprover generates Groth16 proofs for the Railgun joinsplit
// circuits using go-rapidsnark. Circuits are loaded from a directory laid out
// as <dir>/<NNxMM>/{wasm,zkey} (matching the Railgun circuit naming by
// nullifier and commitment count), and the resulting proof is formatted into
// the SnarkProof tuple the RailgunSmartWallet verifier expects.
package railgunprover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/iden3/go-rapidsnark/witness/wasmer"
)

// CircuitName returns the Railgun circuit identifier for a given input/output
// count, e.g. (1, 2) -> "01x02".
func CircuitName(nInputs, nOutputs int) string {
	return fmt.Sprintf("%02dx%02d", nInputs, nOutputs)
}

// Prover loads and caches Railgun circuits from a directory and generates proofs.
type Prover struct {
	circuitsDir string

	mu       sync.Mutex
	calcs    map[string]witness.Calculator
	zkeys    map[string][]byte
}

// NewProver creates a prover that loads circuits from circuitsDir.
func NewProver(circuitsDir string) *Prover {
	return &Prover{
		circuitsDir: circuitsDir,
		calcs:       map[string]witness.Calculator{},
		zkeys:       map[string][]byte{},
	}
}

func (p *Prover) load(circuitName string) (witness.Calculator, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if calc, ok := p.calcs[circuitName]; ok {
		return calc, p.zkeys[circuitName], nil
	}
	dir := filepath.Join(p.circuitsDir, circuitName)
	wasmBytes, err := os.ReadFile(filepath.Join(dir, "wasm"))
	if err != nil {
		return nil, nil, fmt.Errorf("loading circuit %s wasm: %w", circuitName, err)
	}
	zkey, err := os.ReadFile(filepath.Join(dir, "zkey"))
	if err != nil {
		return nil, nil, fmt.Errorf("loading circuit %s zkey: %w", circuitName, err)
	}
	calc, err := witness.NewCalculator(wasmBytes, witness.WithWasmEngine(wasmer.NewCircom2WitnessCalculator))
	if err != nil {
		return nil, nil, fmt.Errorf("building witness calculator for %s: %w", circuitName, err)
	}
	p.calcs[circuitName] = calc
	p.zkeys[circuitName] = zkey
	return calc, zkey, nil
}

// Prove calculates the witness for the given circuit inputs and generates a
// Groth16 proof.
func (p *Prover) Prove(ctx context.Context, circuitName string, inputs map[string]interface{}) (*types.ZKProof, error) {
	calc, zkey, err := p.load(circuitName)
	if err != nil {
		return nil, err
	}
	wtns, err := calc.CalculateWTNSBin(inputs, true)
	if err != nil {
		return nil, fmt.Errorf("calculating witness for %s: %w", circuitName, err)
	}
	proof, err := prover.Groth16Prover(zkey, wtns)
	if err != nil {
		return nil, fmt.Errorf("generating proof for %s: %w", circuitName, err)
	}
	return proof, nil
}

// SolidityProof is the Groth16 proof in the shape expected by the
// RailgunSmartWallet verifier (struct SnarkProof). Field elements are decimal
// strings.
type SolidityProof struct {
	A [2]string
	B [2][2]string
	C [2]string
}

// FormatProof converts a go-rapidsnark proof into the SnarkProof tuple. The G2
// point coordinates are swapped (snarkjs [c0,c1] -> solidity [c1,c0]), matching
// the Railgun reference implementation's formatProof.
func FormatProof(p *types.ZKProof) *SolidityProof {
	return &SolidityProof{
		A: [2]string{p.Proof.A[0], p.Proof.A[1]},
		B: [2][2]string{
			{p.Proof.B[0][1], p.Proof.B[0][0]},
			{p.Proof.B[1][1], p.Proof.B[1][0]},
		},
		C: [2]string{p.Proof.C[0], p.Proof.C[1]},
	}
}
