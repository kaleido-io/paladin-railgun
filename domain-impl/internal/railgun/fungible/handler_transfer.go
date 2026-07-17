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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunnote"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railguntx"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/domain"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	pb "github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

var _ types.DomainHandler = &transferHandler{}

type transferHandler struct {
	baseHandler
	callbacks plugintk.DomainCallbacks
	chainID   int64
}

// NewTransferHandler creates the handler for private note-to-note transfers.
func NewTransferHandler(name string, callbacks plugintk.DomainCallbacks, schemas *StateSchemas, chainID int64) *transferHandler {
	return &transferHandler{baseHandler{name: name, stateSchemas: schemas}, callbacks, chainID}
}

func (h *transferHandler) ValidateParams(ctx context.Context, config *types.DomainInstanceConfig, params string) (interface{}, error) {
	var p types.TransferParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, err
	}
	if p.Token == nil {
		return nil, i18n.NewError(ctx, msgs.MsgNoParamValue, 0)
	}
	if err := validateTransferParams(ctx, p.Transfers); err != nil {
		return nil, err
	}
	return &p, nil
}

func (h *transferHandler) Init(ctx context.Context, tx *types.ParsedTransaction, req *pb.InitTransactionRequest) (*pb.InitTransactionResponse, error) {
	p := tx.Params.(*types.TransferParams)
	res := &pb.InitTransactionResponse{
		RequiredVerifiers: []*pb.ResolveVerifierRequest{
			addressVerifierRequest(tx.Transaction.From, h.getAlgo()),
		},
	}
	for _, t := range p.Transfers {
		// A recipient given as a literal "0zk" address is an external Railgun
		// wallet — there is no Paladin party to resolve; we decode it directly in
		// Assemble. Only Paladin-identity recipients need verifier resolution.
		if railgunnote.IsRailgunAddress(t.To) {
			continue
		}
		res.RequiredVerifiers = append(res.RequiredVerifiers, addressVerifierRequest(t.To, h.getAlgo()))
	}
	return res, nil
}

func (h *transferHandler) Assemble(ctx context.Context, tx *types.ParsedTransaction, req *pb.AssembleTransactionRequest) (*pb.AssembleTransactionResponse, error) {
	p := tx.Params.(*types.TransferParams)

	senderMpkHex, senderMpk, senderViewingPub, err := resolveAddress(req.ResolvedVerifiers, tx.Transaction.From, h.getAlgo())
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, tx.Transaction.From)
	}

	total := big.NewInt(0)
	for _, t := range p.Transfers {
		total.Add(total, t.Value.Int())
	}

	inputs, revert, err := prepareInputsForTransfer(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext, senderMpkHex, total)
	if err != nil {
		if revert {
			msg := err.Error()
			return &pb.AssembleTransactionResponse{AssemblyResult: pb.AssembleTransactionResponse_REVERT, RevertReason: &msg}, nil
		}
		return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxInputs, err)
	}

	tree, nextLeaf, err := loadTree(ctx, h.callbacks, h.stateSchemas, req.StateQueryContext)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorQueryAvailNotes, err)
	}

	// Build output notes: one per recipient, plus change back to the sender.
	var outNotes []*types.RailgunNote
	var outStates []*pb.NewState
	var payloadOutputs []PayloadOutput
	addOutput := func(mpk *big.Int, ownerViewingPub []byte, ownerLookup string, value *pldtypes.HexUint256) error {
		leafIdx := nextLeaf + uint64(len(outNotes))
		note := newNote(mpk, *p.Token, value, leafIdx)
		state, err := makeNoteState(ctx, h.stateSchemas, h.name, note, ownerLookup)
		if err != nil {
			return err
		}
		npk, err := note.NotePublicKey()
		if err != nil {
			return err
		}
		outNotes = append(outNotes, note)
		outStates = append(outStates, state)
		payloadOutputs = append(payloadOutputs, PayloadOutput{
			NPK:             npk.Int().Text(10),
			Value:           value.Int().Text(10),
			Random:          note.Random.Int().Text(10),
			OwnerMPK:        railgunnote.EncodeField(mpk),
			OwnerViewingPub: hex.EncodeToString(ownerViewingPub),
		})
		return nil
	}

	for _, t := range p.Transfers {
		var recMpk *big.Int
		var recViewingPub []byte
		// ownerLookup is the Paladin party that receives the note state; empty for
		// an external "0zk" recipient (they recover the note from on-chain ciphertext).
		ownerLookup := ""
		if railgunnote.IsRailgunAddress(t.To) {
			addr, err := railgunnote.DecodeRailgunAddress(t.To)
			if err != nil {
				return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, t.To)
			}
			recMpk, recViewingPub = addr.MasterPublicKey, addr.ViewingPublicKey
		} else {
			var err error
			_, recMpk, recViewingPub, err = resolveAddress(req.ResolvedVerifiers, t.To, h.getAlgo())
			if err != nil {
				return nil, i18n.NewError(ctx, msgs.MsgErrorResolveVerifier, t.To)
			}
			ownerLookup = t.To
		}
		if err := addOutput(recMpk, recViewingPub, ownerLookup, t.Value); err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxOutputs, err)
		}
	}
	if change := new(big.Int).Sub(inputs.total, total); change.Sign() > 0 {
		changeHex := pldtypes.HexUint256(*change)
		if err := addOutput(senderMpk, senderViewingPub, tx.Transaction.From, &changeHex); err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorPrepTxChange, err)
		}
	}

	payload, err := buildProvingPayload(tree, *p.Token, inputs, payloadOutputs, h.chainID, false, "", tx.Transaction.TransactionId)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFormatProvingReq, err)
	}

	return &pb.AssembleTransactionResponse{
		AssemblyResult: pb.AssembleTransactionResponse_OK,
		AssembledTransaction: &pb.AssembledTransaction{
			InputStates:  inputs.states,
			OutputStates: outStates,
		},
		AttestationPlan: []*pb.AttestationRequest{snarkAttestation(tx.Transaction.From, h.getAlgo(), payload)},
	}, nil
}

func (h *transferHandler) Endorse(ctx context.Context, tx *types.ParsedTransaction, req *pb.EndorseTransactionRequest) (*pb.EndorseTransactionResponse, error) {
	return nil, nil
}

func (h *transferHandler) Prepare(ctx context.Context, tx *types.ParsedTransaction, req *pb.PrepareTransactionRequest) (*pb.PrepareTransactionResponse, error) {
	return prepareTransact(ctx, req)
}

// -----------------------------------------------------------------------
// Shared transact helpers (transfer + unshield)
// -----------------------------------------------------------------------

// addressVerifierRequest asks Paladin to resolve a party to their canonical
// "0zk" Railgun address.
func addressVerifierRequest(lookup, algo string) *pb.ResolveVerifierRequest {
	return &pb.ResolveVerifierRequest{
		Lookup:       lookup,
		Algorithm:    algo,
		VerifierType: railgunsignerapi.RAILGUN_ADDRESS,
	}
}

// resolveAddress finds a party's resolved "0zk" address and decodes it. It
// returns the masterPublicKey both as the 0x-hex string used to key note owners
// (identical to the RAILGUN_MASTER_PUBLIC_KEY verifier) and as a big.Int, plus
// the owner's Ed25519 viewing public key (used to encrypt the note ciphertext).
func resolveAddress(verifiers []*pb.ResolvedVerifier, lookup, algo string) (string, *big.Int, []byte, error) {
	resolved := domain.FindVerifier(lookup, algo, railgunsignerapi.RAILGUN_ADDRESS, verifiers)
	if resolved == nil {
		return "", nil, nil, fmt.Errorf("verifier not resolved: %s", lookup)
	}
	addr, err := railgunnote.DecodeRailgunAddress(resolved.Verifier)
	if err != nil {
		return "", nil, nil, err
	}
	return railgunnote.EncodeField(addr.MasterPublicKey), addr.MasterPublicKey, addr.ViewingPublicKey, nil
}

func snarkAttestation(from, algo string, payload []byte) *pb.AttestationRequest {
	return &pb.AttestationRequest{
		Name:            "sender",
		AttestationType: pb.AttestationType_SIGN,
		Algorithm:       algo,
		VerifierType:    railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY,
		PayloadType:     railgunsignerapi.PAYLOAD_DOMAIN_RAILGUN_SNARK,
		Payload:         payload,
		Parties:         []string{from},
	}
}

// buildProvingPayload assembles the SNARK attestation payload: token, merkle
// root + per-input proofs, output npks/values, and bound params (one ciphertext
// per output commitment, minus one for an unshield).
//
// The Paladin transaction id (txID, a bytes32) is embedded into the first
// commitment ciphertext so that HandleEventBatch can correlate the on-chain
// Transact event back to the originating private transaction (the real Railgun
// events carry no transaction-id field). Because the ciphertext is part of the
// bound params, it is bound into the proof's boundParamsHash — which the
// contract re-derives identically, so the embedding does not affect validity.
func buildProvingPayload(tree *railgunnote.MerkleTree, token pldtypes.EthAddress, inputs *preparedInputs, outputs []PayloadOutput, chainID int64, unshield bool, unshieldValue, txID string) ([]byte, error) {
	root := tree.Root()
	payloadInputs := make([]PayloadInput, len(inputs.notes))
	for i, note := range inputs.notes {
		leafIndex := note.LeafIndex.Int().Uint64()
		path := tree.Proof(int(leafIndex))
		pathStr := make([]string, len(path))
		for j, e := range path {
			pathStr[j] = e.Text(10)
		}
		payloadInputs[i] = PayloadInput{
			Random:       note.Random.Int().Text(10),
			Value:        note.Value.Int().Text(10),
			LeafIndex:    leafIndex,
			PathElements: pathStr,
		}
	}

	numCiphertext := len(outputs)
	if unshield {
		numCiphertext-- // ciphertext array excludes the unshield output
	}
	// Placeholder ciphertext entries (correct count for boundParamsHash). For
	// transfers, Sign replaces each with the real note ciphertext encrypted to the
	// recipient's viewing key. The Paladin tx-id is carried in annotationData (set
	// in Sign) for on-chain event correlation.
	cts := make([]railguntx.CommitmentCiphertext, numCiphertext)
	for i := range cts {
		cts[i] = placeholderCiphertext()
	}

	unshieldType := railguntx.UnshieldNone
	if unshield {
		unshieldType = railguntx.UnshieldNormal
	}

	tokenID := railgunnote.TokenIDERC20(toArray20(token))
	payload := &ProvingPayload{
		Token:        tokenID.Text(10),
		TokenAddress: token.String(),
		MerkleRoot:   root.Text(10),
		Inputs:       payloadInputs,
		Outputs:      outputs,
		BoundParams: railguntx.BoundParams{
			TreeNumber:           0,
			MinGasPrice:          "0",
			Unshield:             unshieldType,
			ChainID:              fmt.Sprintf("%d", chainID),
			AdaptContract:        "0x0000000000000000000000000000000000000000",
			AdaptParams:          "0x" + strings.Repeat("00", 32),
			CommitmentCiphertext: cts,
		},
		UnshieldValue: unshieldValue,
		TxID:          txID,
	}
	return json.Marshal(payload)
}

func placeholderCiphertext() railguntx.CommitmentCiphertext {
	z := "0x" + strings.Repeat("00", 32)
	return railguntx.CommitmentCiphertext{
		Ciphertext:                [4]string{z, z, z, z},
		BlindedSenderViewingKey:   z,
		BlindedReceiverViewingKey: z,
		AnnotationData:            "0x",
		Memo:                      "0x",
	}
}

func toArray20(a pldtypes.EthAddress) [20]byte {
	var out [20]byte
	copy(out[:], a[:])
	return out
}

// prepareTransact assembles the on-chain transact(Transaction[]) call from the
// proof produced by Sign (returned in the "sender" attestation).
func prepareTransact(ctx context.Context, req *pb.PrepareTransactionRequest) (*pb.PrepareTransactionResponse, error) {
	result := domain.FindAttestation("sender", req.AttestationResult)
	if result == nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFindSenderAttestation)
	}
	var txn railguntx.Transaction
	if err := json.Unmarshal(result.Payload, &txn); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorUnmarshalProvingRes, err)
	}
	paramsJSON, err := json.Marshal(map[string]interface{}{
		"_transactions": []interface{}{txn.ABIObject()},
	})
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorMarshalPrepedParams, err)
	}
	signer := req.Transaction.From
	return &pb.PrepareTransactionResponse{
		Transaction: &pb.PreparedTransaction{
			FunctionAbiJson: mustEntryJSON(transactFunctionABI),
			ParamsJson:      string(paramsJSON),
			RequiredSigner:  &signer,
		},
	}, nil
}
