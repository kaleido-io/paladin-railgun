/*
 * Copyright © 2026 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package integrationtest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguncrypto"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/solutils"
	"github.com/stretchr/testify/require"
)

// onchainCommitmentCiphertext / onchainTransact mirror the RailgunSmartWallet
// Transact event as decoded by the block indexer — the exact on-chain data an
// external Railgun wallet sees, with no help from Paladin state distribution.
type onchainCommitmentCiphertext struct {
	Ciphertext                []pldtypes.Bytes32 `json:"ciphertext"`
	BlindedSenderViewingKey   pldtypes.Bytes32   `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey pldtypes.Bytes32   `json:"blindedReceiverViewingKey"`
	AnnotationData            pldtypes.HexBytes  `json:"annotationData"`
	Memo                      pldtypes.HexBytes  `json:"memo"`
}

type onchainTransact struct {
	StartPosition *pldtypes.HexUint256          `json:"startPosition"`
	Hash          []pldtypes.HexUint256         `json:"hash"`
	Ciphertext    []onchainCommitmentCiphertext `json:"ciphertext"`
}

// newExternalWallet creates a self-custodied Railgun wallet whose seed the test
// holds (as a real external wallet would). Only its 0zk address is shared with
// the sender; the viewing seed is used to decrypt on-chain ciphertext.
func newExternalWallet(t *testing.T) (*railgunnote.Identity, string) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	id, err := railgunnote.IdentityFromSeed(seed)
	require.NoError(t, err)
	// Chain-agnostic 0zk address (valid on any network) — a realistic external form.
	addr, err := id.RailgunAddress(nil)
	require.NoError(t, err)
	return id, addr
}

// readLatestTransact fetches and decodes the most recent RailgunSmartWallet
// Transact event via the block indexer — the wallet's on-chain view.
func readLatestTransact(ctx context.Context, t *testing.T, tb testbed.Testbed) *onchainTransact {
	walletABI := solutils.MustParseBuildABI(railgunSmartWalletBuildJSON)
	transactEvent := walletABI.Events()["Transact"]
	require.NotNil(t, transactEvent, "Transact event in wallet ABI")
	topic0 := transactEvent.SignatureHashBytes().String()

	bi := tb.Components().BlockIndexer()
	events, err := bi.QueryIndexedEvents(ctx, query.NewQueryBuilder().
		Equal("signature", topic0).
		Sort("-blockNumber").Sort("-transactionIndex").Sort("-logIndex").
		Limit(1).Query())
	require.NoError(t, err)
	require.NotEmpty(t, events, "no Transact event indexed")

	decoded, err := bi.DecodeTransactionEvents(ctx, events[0].TransactionHash, walletABI, "")
	require.NoError(t, err)
	for _, d := range decoded {
		if strings.HasPrefix(d.SoliditySignature, "event Transact(") {
			var te onchainTransact
			require.NoError(t, json.Unmarshal(d.Data, &te))
			return &te
		}
	}
	t.Fatal("Transact event not found in decoded transaction events")
	return nil
}

// TestExternalWalletReceivesAndCanSpend mimics paying an EXTERNAL Railgun wallet
// by its 0zk address and the external wallet then receiving the funds purely from
// on-chain data — no Paladin private-state distribution. It proves the wallet can
// decrypt the commitment ciphertext, reconstruct the exact note (its commitment
// matches the on-chain leaf), recover the sender, and derive the nullifier needed
// to spend.
func (s *railgunE2ETestSuite) TestExternalWalletReceivesAndCanSpend() {
	ctx := context.Background()
	t := s.T()

	// Dedicated sender identity so this test does not perturb the balances the
	// other suite test asserts.
	const carolName = "carol@node1"

	// External wallet: sender only ever sees its 0zk address.
	ext, extAddr := newExternalWallet(t)
	require.True(t, railgunnote.IsRailgunAddress(extAddr))

	// Shield fresh funds to carol, then transfer 20 to the external 0zk address.
	railgunInvoke(ctx, t, s.rpc, controllerName, s.instanceAddr, "shield", mustJSON(t, &types.ShieldParams{
		To: carolName, Token: s.erc20Address, Value: hexU(50),
	}))
	carolBefore := railgunBalance(ctx, t, s.rpc, s.instanceAddr, carolName).Int64()

	railgunInvoke(ctx, t, s.rpc, carolName, s.instanceAddr, "transfer", mustJSON(t, &types.TransferParams{
		Token:     s.erc20Address,
		Transfers: []*types.TransferParamEntry{{To: extAddr, Value: hexU(20)}},
	}))
	// Carol is debited; the external note is not owned by any Paladin party.
	require.Equal(t, carolBefore-20, railgunBalance(ctx, t, s.rpc, s.instanceAddr, carolName).Int64(), "carol debited by transfer")

	// --- External wallet receives: read the on-chain Transact event. ---
	te := readLatestTransact(ctx, t, s.tb)
	require.NotEmpty(t, te.Ciphertext)
	require.Equal(t, len(te.Ciphertext), len(te.Hash))
	require.Len(t, te.Ciphertext[0].Ciphertext, 4, "ciphertext is bytes32[4]")

	// Output 0 is the recipient note (external); output 1 is alice's change.
	cc := te.Ciphertext[0]
	leafIndex := te.StartPosition.Int().Uint64()
	onchainCommitment := te.Hash[0].Int()

	// --- Decrypt with the external wallet's viewing key (chain data only). ---
	ec := &railguncrypto.EncryptedCommitment{
		Ciphertext:                [4][]byte{cc.Ciphertext[0][:], cc.Ciphertext[1][:], cc.Ciphertext[2][:], cc.Ciphertext[3][:]},
		BlindedSenderViewingKey:   cc.BlindedSenderViewingKey[:],
		BlindedReceiverViewingKey: cc.BlindedReceiverViewingKey[:],
		Memo:                      cc.Memo,
	}
	encodedMPK, tokenHash, random, value, _, err := railguncrypto.DecryptTransactNote(ext.ViewingKey[:], ec)
	require.NoError(t, err, "external wallet must decrypt the note from on-chain ciphertext alone")

	// Recovered value and token match what was sent.
	require.Equal(t, int64(20), new(big.Int).SetBytes(value).Int64(), "recovered value")
	var addr20 [20]byte
	copy(addr20[:], s.erc20Address[:])
	tokenID := railgunnote.TokenIDERC20(addr20)
	require.Equal(t, 0, new(big.Int).SetBytes(tokenHash).Cmp(tokenID), "recovered token id")

	// --- Reconstruct the private note and prove it matches the on-chain leaf. ---
	mpk, err := ext.MasterPublicKey()
	require.NoError(t, err)
	npk, err := railgunnote.NotePublicKey(mpk, new(big.Int).SetBytes(random))
	require.NoError(t, err)
	commitment, err := railgunnote.Commitment(npk, tokenID, new(big.Int).SetBytes(value))
	require.NoError(t, err)
	require.Equal(t, 0, commitment.Cmp(onchainCommitment),
		"reconstructed commitment must equal the on-chain leaf — the note is genuinely owned by the external wallet")

	// Sender address is recoverable (address-visible mode).
	carolMPK, err := railgunnote.DecodeField(resolveMpk(ctx, t, s.rpc, s.domainName, carolName))
	require.NoError(t, err)
	recoveredSender := new(big.Int).Xor(new(big.Int).SetBytes(encodedMPK), mpk)
	require.Equal(t, 0, recoveredSender.Cmp(carolMPK), "recovered sender address == carol")

	// --- Spendability: the receiver derives the note's nullifier (what a spend
	//     consumes), from the leaf index observed on-chain and its own key. ---
	nk, err := ext.NullifyingKey()
	require.NoError(t, err)
	nullifier, err := railgunnote.Nullifier(nk, leafIndex)
	require.NoError(t, err)
	require.Equal(t, 1, nullifier.Sign(), "nullifier derived — the received note is spendable by the external wallet")
}
