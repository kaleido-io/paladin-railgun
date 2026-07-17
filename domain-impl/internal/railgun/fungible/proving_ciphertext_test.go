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

package fungible

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguncrypto"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguntx"
	"github.com/stretchr/testify/require"
)

func decodeHex0x(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	return b
}

// TestSendPathCiphertextDecryptsForRecipient is the core send-path interop
// assertion: the CommitmentCiphertext produced by the send path (encryptOutput-
// Ciphertext) for a transfer output can be decrypted by the recipient using only
// the viewing key derived from their seed — exactly what an external Railgun
// wallet does when scanning. It also checks the sender address is recoverable and
// the Paladin tx-id is carried in annotationData.
func TestSendPathCiphertextDecryptsForRecipient(t *testing.T) {
	senderSeed := make([]byte, 32)
	recvSeed := make([]byte, 32)
	for i := range senderSeed {
		senderSeed[i] = byte(i + 1)
		recvSeed[i] = byte(200 - i)
	}
	senderID, err := railgunnote.IdentityFromSeed(senderSeed)
	require.NoError(t, err)
	recvID, err := railgunnote.IdentityFromSeed(recvSeed)
	require.NoError(t, err)

	senderMPK, err := senderID.MasterPublicKey()
	require.NoError(t, err)
	recvMPK, err := recvID.MasterPublicKey()
	require.NoError(t, err)
	recvViewingPub := recvID.ViewingPublicKey()

	tokenID := new(big.Int).SetBytes(decodeHex0x(t, "00000000000000000000000000000000000000aa")) // ERC-20 addr as id
	random := decodeHex0x(t, "85b08a7cd73ee433072f1d410aeb4801")                                  // 16 bytes
	value := big.NewInt(1_000_000)
	txID := "0x" + strings.Repeat("ab", 32)

	p := &ProvingPayload{
		TxID: txID,
		Outputs: []PayloadOutput{{
			NPK:             "0",
			Value:           value.Text(10),
			Random:          new(big.Int).SetBytes(random).Text(10),
			OwnerMPK:        railgunnote.EncodeField(recvMPK),
			OwnerViewingPub: hex.EncodeToString(recvViewingPub),
		}},
		BoundParams: railguntx.BoundParams{
			CommitmentCiphertext: []railguntx.CommitmentCiphertext{placeholderCiphertext()},
		},
	}

	require.NoError(t, encryptOutputCiphertext(senderID, p, tokenID))

	ct := p.BoundParams.CommitmentCiphertext[0]
	require.Equal(t, txID, ct.AnnotationData, "tx-id carried in annotationData")

	// Reconstruct the on-chain ciphertext and decrypt as the recipient would.
	ec := &railguncrypto.EncryptedCommitment{
		Ciphertext: [4][]byte{
			decodeHex0x(t, ct.Ciphertext[0]), decodeHex0x(t, ct.Ciphertext[1]),
			decodeHex0x(t, ct.Ciphertext[2]), decodeHex0x(t, ct.Ciphertext[3]),
		},
		BlindedSenderViewingKey:   decodeHex0x(t, ct.BlindedSenderViewingKey),
		BlindedReceiverViewingKey: decodeHex0x(t, ct.BlindedReceiverViewingKey),
		Memo:                      decodeHex0x(t, ct.Memo),
	}
	encodedMPK, tokenHash, gotRandom, gotValue, _, err := railguncrypto.DecryptTransactNote(recvID.ViewingKey[:], ec)
	require.NoError(t, err, "recipient must decrypt the note from chain data alone")

	require.Equal(t, random, gotRandom, "random recovered")
	require.Equal(t, tokenID.FillBytes(make([]byte, 32)), tokenHash, "token recovered")
	require.Equal(t, value, new(big.Int).SetBytes(gotValue), "value recovered")

	// Address-visible mode: recipient recovers the sender's master public key.
	recoveredSender := new(big.Int).Xor(new(big.Int).SetBytes(encodedMPK), recvMPK)
	require.Equal(t, 0, recoveredSender.Cmp(senderMPK), "sender address recoverable by recipient")
}
