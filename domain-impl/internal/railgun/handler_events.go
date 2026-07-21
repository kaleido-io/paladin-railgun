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

package railgun

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"golang.org/x/crypto/sha3"
)

// Railgun's on-chain events carry no Paladin transaction id, so the domain
// embeds it in an (unvalidated) field of the shield/transact calldata: shieldKey
// for shield, the first commitment ciphertext's annotationData for transact (the
// ciphertext itself is now real, encrypted to the recipient; annotationData is
// sender metadata that an external recipient never decrypts, so it is safe to
// carry the tx-id there). Each batch is processed in two passes — first building
// a tx-hash → tx-id map from Shield/Transact events, then processing every event
// (including Nullified/Unshield, which share the tx hash).

// txCorrelation builds the on-chain-tx-hash → Paladin-tx-id map for a batch.
func txCorrelation(ctx context.Context, events []*prototk.OnChainEvent, shieldSig, transactSig string) map[string]string {
	byHash := map[string]string{}
	for _, ev := range events {
		switch ev.SoliditySignature {
		case shieldSig:
			var shield ShieldEvent
			if json.Unmarshal([]byte(ev.DataJson), &shield) == nil && len(shield.ShieldCiphertext) > 0 {
				byHash[ev.Location.TransactionHash] = shield.ShieldCiphertext[0].ShieldKey.String()
			}
		case transactSig:
			var transact TransactEvent
			if json.Unmarshal([]byte(ev.DataJson), &transact) == nil && len(transact.Ciphertext) > 0 {
				byHash[ev.Location.TransactionHash] = transact.Ciphertext[0].AnnotationData.String()
			}
		}
	}
	return byHash
}

func (r *Railgun) handleShieldEvent(ctx context.Context, ev *prototk.OnChainEvent, txID string, res *prototk.HandleEventBatchResponse) error {
	var shield ShieldEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &shield); err != nil {
		log.L(ctx).Errorf("Failed to unmarshal Shield event: %s", err)
		return nil
	}
	start := shield.StartPosition.Int().Uint64()
	for i, c := range shield.Commitments {
		leaf, err := hashCommitmentPreimage(&c)
		if err != nil {
			return err
		}
		r.recordCommitment(res, txID, start+uint64(i), leaf)
	}
	r.recordComplete(res, txID, ev)
	return nil
}

func (r *Railgun) handleTransactEvent(ctx context.Context, ev *prototk.OnChainEvent, txID string, res *prototk.HandleEventBatchResponse) error {
	var transact TransactEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &transact); err != nil {
		log.L(ctx).Errorf("Failed to unmarshal Transact event: %s", err)
		return nil
	}
	start := transact.StartPosition.Int().Uint64()
	for i := range transact.Hash {
		r.recordCommitment(res, txID, start+uint64(i), transact.Hash[i].Int())
	}
	r.recordComplete(res, txID, ev)
	return nil
}

func (r *Railgun) handleUnshieldEvent(ctx context.Context, ev *prototk.OnChainEvent, txID string, res *prototk.HandleEventBatchResponse) error {
	var unshield UnshieldEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &unshield); err != nil {
		log.L(ctx).Errorf("Failed to unmarshal Unshield event: %s", err)
		return nil
	}
	log.L(ctx).Infof("Unshield to=%s amount=%s fee=%s", unshield.To, unshield.Amount, unshield.Fee)
	return nil
}

func (r *Railgun) handleNullifiedEvent(ctx context.Context, ev *prototk.OnChainEvent, txID string, res *prototk.HandleEventBatchResponse) error {
	var nullified NullifiedEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &nullified); err != nil {
		log.L(ctx).Errorf("Failed to unmarshal Nullified event: %s", err)
		return nil
	}
	for i := range nullified.Nullifier {
		res.SpentStates = append(res.SpentStates, &prototk.StateUpdate{
			Id:            fieldStateID(nullified.Nullifier[i].Int()),
			TransactionId: txID,
		})
	}
	return nil
}

// recordCommitment confirms the note state (id == commitment, owned by the
// originating transaction) and appends a tree-leaf state capturing the
// commitment's on-chain position.
func (r *Railgun) recordCommitment(res *prototk.HandleEventBatchResponse, txID string, leafIndex uint64, commitment *big.Int) {
	res.ConfirmedStates = append(res.ConfirmedStates, &prototk.StateUpdate{
		Id:            fieldStateID(commitment),
		TransactionId: txID,
	})

	leaf := &types.RailgunTreeLeaf{
		LeafIndex:  (*pldtypes.HexUint256)(new(big.Int).SetUint64(leafIndex)),
		Commitment: (*pldtypes.HexUint256)(commitment),
	}
	data, err := json.Marshal(leaf)
	if err != nil {
		return
	}
	id := treeLeafStateID(leafIndex, commitment)
	res.NewStates = append(res.NewStates, &prototk.NewConfirmedState{
		Id:            &id,
		SchemaId:      r.treeLeafSchema.Id,
		StateDataJson: string(data),
		TransactionId: txID,
	})
}

// recordComplete marks the originating private transaction complete.
func (r *Railgun) recordComplete(res *prototk.HandleEventBatchResponse, txID string, ev *prototk.OnChainEvent) {
	if txID == "" {
		return
	}
	res.TransactionsComplete = append(res.TransactionsComplete, &prototk.CompletedTransaction{
		TransactionId: txID,
		Location:      ev.Location,
	})
}

// -----------------------------------------------------------------------
// Commitment hashing (Shield events carry preimages, not leaf hashes)
// -----------------------------------------------------------------------

func hashCommitmentPreimage(c *CommitmentPreimage) (*big.Int, error) {
	tokenID := getTokenID(&c.Token)
	return railgunnote.Commitment(new(big.Int).SetBytes(c.NPK.Bytes()), tokenID, c.Value.Int())
}

// getTokenID mirrors RailgunLogic.getTokenID (ERC-20 = numeric address).
func getTokenID(t *TokenData) *big.Int {
	if t.TokenType == nil || t.TokenType.Int().Sign() == 0 { // 0 == ERC20
		return new(big.Int).SetBytes(t.TokenAddress[:])
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(t.TokenAddress[:])
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), railgunnote.SnarkScalarField)
}

// -----------------------------------------------------------------------
// State id helpers
// -----------------------------------------------------------------------

// fieldStateID renders a field element as a 0x-prefixed 32-byte hex state id,
// matching the ids the handlers assign to note states and nullifiers.
func fieldStateID(v *big.Int) string {
	return "0x" + hex.EncodeToString(v.FillBytes(make([]byte, 32)))
}

// treeLeafStateID derives a unique id for a tree-leaf state from its position
// and commitment.
func treeLeafStateID(leafIndex uint64, commitment *big.Int) string {
	id, err := railgunnote.Commitment(commitment, new(big.Int).SetUint64(leafIndex), big.NewInt(0))
	if err != nil {
		return fieldStateID(commitment)
	}
	return fieldStateID(id)
}

func formatErrors(errors []string) string {
	msg := fmt.Sprintf("(failures=%d)", len(errors))
	for i, e := range errors {
		msg = fmt.Sprintf("%s. [%d]%s", msg, i, e)
	}
	return msg
}
