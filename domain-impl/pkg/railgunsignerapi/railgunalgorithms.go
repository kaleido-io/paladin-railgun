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

import "fmt"

// AlgoDomainRailgunSnarkBJJ returns the signing algorithm identifier for this
// named Railgun domain instance. Follows the same convention as Zeto:
//
//	domain:<name>:snark:babyjubjub
func AlgoDomainRailgunSnarkBJJ(name string) string {
	return fmt.Sprintf("domain:%s:snark:babyjubjub", name)
}

// PAYLOAD_DOMAIN_RAILGUN_SNARK is the payload type used when requesting a
// Groth16 SNARK proof from the signing infrastructure.
const PAYLOAD_DOMAIN_RAILGUN_SNARK = "domain:railgun:snark"

// PAYLOAD_DOMAIN_RAILGUN_NULLIFIER is the payload type used when requesting
// a nullifier value for a note (to prove ownership without revealing identity).
const PAYLOAD_DOMAIN_RAILGUN_NULLIFIER = "domain:railgun:nullifier"

// IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X is the verifier type for a compressed
// BabyJubJub public key prefixed with 0x. Shared with Zeto.
const IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X = "iden3_pubkey_babyjubjub_compressed_0x"

// RAILGUN_MASTER_PUBLIC_KEY is the verifier type for a Railgun address: the
// masterPublicKey field element (0x-prefixed 32-byte hex). A sender resolves a
// recipient to this value and forms the note public key as Poseidon(mpk, random).
const RAILGUN_MASTER_PUBLIC_KEY = "railgun_master_public_key"

// CircuitType enumerates the available Railgun circuit categories.
type CircuitType string

const (
	Shield    CircuitType = "shield"
	Unshield  CircuitType = "unshield"
	Transfer  CircuitType = "transfer"
)

// Circuit describes a single Groth16 circuit used by the Railgun domain.
type Circuit struct {
	Name           string      `yaml:"name" json:"name"`
	Type           CircuitType `yaml:"type" json:"type"`
	UsesNullifiers bool        `yaml:"usesNullifiers" json:"usesNullifiers"` // always true for Railgun
}

// Circuits maps operation name -> circuit descriptor.
type Circuits map[string]*Circuit

// Init stamps each circuit with its map key as the circuit type.
func (cs Circuits) Init() {
	for circuitType, circuit := range cs {
		circuit.Type = CircuitType(circuitType)
		circuit.UsesNullifiers = true // Railgun always uses nullifiers
	}
}

// SnarkProverConfig carries the file-system paths to the circuit WASM and
// proving keys, plus optional concurrency tuning.
type SnarkProverConfig struct {
	CircuitsDir         string `json:"circuitsDir"`
	ProvingKeysDir      string `json:"provingKeysDir"`
	MaxProverPerCircuit *int   `json:"maxProverPerCircuit"`
}
