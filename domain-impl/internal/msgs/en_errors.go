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

package msgs

import (
	"fmt"
	"strings"
	"sync"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"golang.org/x/text/language"
)

const railgunPrefix = "PD22"

var registered sync.Once
var pde = func(key, translation string, statusHint ...int) i18n.ErrorMessageKey {
	registered.Do(func() {
		i18n.RegisterPrefix(railgunPrefix, "Railgun Domain")
	})
	if !strings.HasPrefix(key, railgunPrefix) {
		panic(fmt.Errorf("must have prefix '%s': %s", railgunPrefix, key))
	}
	return i18n.PDE(language.AmericanEnglish, key, translation, statusHint...)
}

var (
	MsgErrorParseDomainConfig           = pde("PD220000", "Failed to parse domain config json. %s")
	MsgErrorConfigRailgunDomain         = pde("PD220001", "Failed to configure Railgun domain. %s")
	MsgErrorMarshalRailgunEventAbis     = pde("PD220002", "Failed to marshal Railgun event ABIs. %s")
	MsgErrorValidateInitDeployParams    = pde("PD220003", "Failed to validate init deploy parameters. %s")
	MsgErrorValidatePrepDeployParams    = pde("PD220004", "Failed to validate prepare deploy parameters. %s")
	MsgErrorFindCircuit                 = pde("PD220005", "Failed to find circuit for operation '%s'. %s")
	MsgErrorValidateInitTxSpec          = pde("PD220006", "Failed to validate init transaction spec. %s")
	MsgErrorValidateAssembleTxSpec      = pde("PD220007", "Failed to validate assemble transaction spec. %s")
	MsgErrorValidateEndorseTxParams     = pde("PD220008", "Failed to validate endorse transaction params. %s")
	MsgErrorValidatePrepTxSpec          = pde("PD220009", "Failed to validate prepare transaction spec. %s")
	MsgErrorUnmarshalFuncAbi            = pde("PD220010", "Failed to unmarshal function ABI json. %s")
	MsgUnknownFunction                  = pde("PD220011", "Unknown function: %s")
	MsgErrorValidateFuncParams          = pde("PD220012", "Failed to validate function params. %s")
	MsgUnexpectedFuncSignature          = pde("PD220013", "Unexpected signature for function '%s': expected='%s', actual='%s'")
	MsgErrorDecodeContractAddress       = pde("PD220014", "Failed to decode contract address. %s")
	MsgErrorAbiDecodeDomainConfig       = pde("PD220015", "Failed to ABI-decode domain instance config. %s")
	MsgErrorHandleEvents                = pde("PD220016", "Failed to handle events. %s")
	MsgErrorGetVerifier                 = pde("PD220017", "Failed to get verifier. %s")
	MsgErrorSign                        = pde("PD220018", "Failed to sign. %s")
	MsgNoTransferParams                 = pde("PD220019", "No transfer parameters provided")
	MsgNoParamTo                        = pde("PD220020", "Parameter 'to' is required (index=%d)")
	MsgNoParamValue                     = pde("PD220021", "Parameter 'value' is required (index=%d)")
	MsgParamValueInRange                = pde("PD220022", "Parameter 'value' must be positive and less than 2^100 (index=%d)")
	MsgParamTotalValueInRange           = pde("PD220023", "Total value must be positive and less than 2^100")
	MsgErrorQueryAvailNotes             = pde("PD220024", "Failed to query available notes. %s")
	MsgInsufficientFunds                = pde("PD220025", "Insufficient funds (available=%s)")
	MsgInvalidNote                      = pde("PD220026", "Note %s is invalid: %s")
	MsgMaxNotesReached                  = pde("PD220027", "Need more than maximum (%d) notes to fulfill the transfer value")
	MsgErrorResolveVerifier             = pde("PD220028", "Failed to resolve verifier: %s")
	MsgErrorLoadOwnerPubKey             = pde("PD220029", "Failed to load owner public key. %s")
	MsgErrorDecodeBJJKey                = pde("PD220030", "Failed to decode BabyJubJub key. %s")
	MsgErrorCreateNewState              = pde("PD220031", "Failed to create new state. %s")
	MsgErrorPrepTxInputs                = pde("PD220032", "Failed to prepare transaction inputs. %s")
	MsgErrorPrepTxOutputs               = pde("PD220033", "Failed to prepare transaction outputs. %s")
	MsgErrorPrepTxChange                = pde("PD220034", "Failed to prepare change note. %s")
	MsgErrorFormatProvingReq            = pde("PD220035", "Failed to format proving request. %s")
	MsgErrorFindSenderAttestation       = pde("PD220036", "Did not find 'sender' attestation")
	MsgErrorUnmarshalProvingRes         = pde("PD220037", "Failed to unmarshal proving response. %s")
	MsgErrorParseInputStates            = pde("PD220038", "Failed to parse input states. %s")
	MsgErrorHashInputState              = pde("PD220039", "Failed to hash input note. %s")
	MsgErrorParseOutputStates           = pde("PD220040", "Failed to parse output states. %s")
	MsgErrorHashOutputState             = pde("PD220041", "Failed to hash output note. %s")
	MsgErrorEncodeTxData                = pde("PD220042", "Failed to encode transaction data. %s")
	MsgErrorMarshalPrepedParams         = pde("PD220043", "Failed to marshal prepared params to JSON. %s")
	MsgErrorGenerateMTP                 = pde("PD220044", "Failed to generate Merkle proofs. %s")
	MsgErrorMarshalExtraObj             = pde("PD220045", "Failed to marshal extras object. %s")
	MsgErrorConvertToCircomProof        = pde("PD220046", "Failed to convert to circom verifier proof. %s")
	MsgErrorUpdateSMT                   = pde("PD220047", "Failed to update Merkle tree for '%s' event. %s")
	MsgErrorNewSmtSpec                  = pde("PD220048", "Failed to create Merkle tree spec for %s: %s")
	MsgErrorHashMismatch                = pde("PD220049", "Note (ref=%s) found in Merkle tree but persisted hash %s (index=%s) did not match expected hash %s (index=%s)")
	MsgErrorStateHashMismatch           = pde("PD220050", "State hash mismatch (hashed vs. received): %s != %s")
	MsgErrorUnmarshalStateData          = pde("PD220051", "Failed to unmarshal state data. %s")
	MsgNullifierGenerationFailed        = pde("PD220052", "Failed to generate nullifier for note")
	MsgUnknownSignPayload               = pde("PD220053", "Sign payload type '%s' not recognised")
	MsgNotImplemented                   = pde("PD220054", "Not implemented")
	MsgNoDomainReceipt                  = pde("PD220055", "Not implemented. See state receipt for note transfers")
	MsgErrorParseTxId                   = pde("PD220056", "Failed to parse transaction id. %s")
	MsgErrorMarshalNoteValues           = pde("PD220057", "Failed to marshal note values. %s")
	MsgContractNotFound                 = pde("PD220058", "Contract '%s' not found")
	MsgErrorHandlerImplementationNotFound = pde("PD220059", "Handler implementation not found")
	MsgErrorValidateInitCallTxSpec      = pde("PD220060", "Failed to validate init call transaction spec. %s")
	MsgErrorValidateExecCallTxSpec      = pde("PD220061", "Failed to validate execute call transaction spec. %s")
	MsgNoParamAccount                   = pde("PD220062", "Parameter 'account' is required")
	MsgUnknownSmtType                   = pde("PD220063", "Unknown Merkle tree type: %d")
)
