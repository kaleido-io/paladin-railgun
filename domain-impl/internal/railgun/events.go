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

package railgun

import "github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"

// These structs mirror the events emitted by the real RailgunSmartWallet /
// RailgunLogic contract (contracts/logic/RailgunSmartWallet.sol). They are
// decoded from the JSON form of the on-chain event data delivered by Paladin.

// TokenData identifies the underlying token of a commitment (ERC20/721/1155).
// Integer fields arrive from Paladin's ABI serializer as base-10 strings, so
// they use HexUint256 (which parses both decimal and 0x-hex).
type TokenData struct {
	TokenType    *pldtypes.HexUint256 `json:"tokenType"`
	TokenAddress pldtypes.EthAddress  `json:"tokenAddress"`
	TokenSubID   *pldtypes.HexUint256 `json:"tokenSubID"`
}

// CommitmentPreimage is the cleartext content of a shield commitment.
// The on-chain leaf is hashCommitment(npk, token, value).
type CommitmentPreimage struct {
	NPK   pldtypes.Bytes32     `json:"npk"`
	Token TokenData            `json:"token"`
	Value *pldtypes.HexUint256 `json:"value"`
}

// ShieldCiphertext carries the encrypted bundle for a shielded note (opaque to
// the domain; retained for completeness / receipts).
type ShieldCiphertext struct {
	EncryptedBundle []pldtypes.Bytes32 `json:"encryptedBundle"`
	ShieldKey       pldtypes.Bytes32   `json:"shieldKey"`
}

// CommitmentCiphertext is the encrypted note data emitted alongside Transact
// commitments (opaque to the domain).
type CommitmentCiphertext struct {
	Ciphertext                []pldtypes.Bytes32 `json:"ciphertext"`
	BlindedSenderViewingKey   pldtypes.Bytes32   `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey pldtypes.Bytes32   `json:"blindedReceiverViewingKey"`
	AnnotationData            pldtypes.HexBytes  `json:"annotationData"`
	Memo                      pldtypes.HexBytes  `json:"memo"`
}

// ShieldEvent is emitted when ERC-20 tokens are deposited and new commitments
// added to the Merkle tree.
//
//	event Shield(uint256 treeNumber, uint256 startPosition,
//	             CommitmentPreimage[] commitments,
//	             ShieldCiphertext[] shieldCiphertext, uint256[] fees)
type ShieldEvent struct {
	TreeNumber       *pldtypes.HexUint256  `json:"treeNumber"`
	StartPosition    *pldtypes.HexUint256  `json:"startPosition"`
	Commitments      []CommitmentPreimage  `json:"commitments"`
	ShieldCiphertext []ShieldCiphertext    `json:"shieldCiphertext"`
	Fees             []*pldtypes.HexUint256 `json:"fees"`
}

// TransactEvent is emitted for private transfers; the hash array holds the new
// commitment leaf hashes inserted into the tree.
//
//	event Transact(uint256 treeNumber, uint256 startPosition,
//	               bytes32[] hash, CommitmentCiphertext[] ciphertext)
type TransactEvent struct {
	TreeNumber    *pldtypes.HexUint256   `json:"treeNumber"`
	StartPosition *pldtypes.HexUint256   `json:"startPosition"`
	Hash          []pldtypes.HexUint256  `json:"hash"`
	Ciphertext    []CommitmentCiphertext `json:"ciphertext"`
}

// UnshieldEvent is emitted when tokens leave the privacy pool to a public
// address. It carries no new commitment.
//
//	event Unshield(address to, TokenData token, uint256 amount, uint256 fee)
type UnshieldEvent struct {
	To     pldtypes.EthAddress  `json:"to"`
	Token  TokenData            `json:"token"`
	Amount *pldtypes.HexUint256 `json:"amount"`
	Fee    *pldtypes.HexUint256 `json:"fee"`
}

// NullifiedEvent is emitted when notes are spent; the nullifiers mark the
// corresponding input commitments as consumed.
//
//	event Nullified(uint16 treeNumber, bytes32[] nullifier)
type NullifiedEvent struct {
	TreeNumber *pldtypes.HexUint256  `json:"treeNumber"`
	Nullifier  []pldtypes.HexUint256 `json:"nullifier"`
}
