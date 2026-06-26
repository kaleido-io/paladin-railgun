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

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/msgs"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/fungible"
	"github.com/LFDT-Paladin/paladin/domains/railgun/internal/railgun/railgunprover"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/railgunsignerapi"
	"github.com/LFDT-Paladin/paladin/domains/railgun/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/algorithms"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/plugintk"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/verifiers"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

var _ plugintk.DomainAPI = &Railgun{}

// Railgun implements plugintk.DomainAPI for the Railgun privacy-token protocol.
// Notes use the real Railgun model (masterPublicKey-addressed, Poseidon
// commitments, leaf-index nullifiers) and transfers/unshields are proven with
// the Railgun joinsplit circuits.
type Railgun struct {
	Callbacks plugintk.DomainCallbacks

	name           string
	config         *types.DomainFactoryConfig
	chainID        int64
	noteSchema     *prototk.StateSchema
	treeLeafSchema *prototk.StateSchema
	prover         *railgunprover.Prover
	events         struct {
		shield    string
		transact  string
		unshield  string
		nullified string
	}
}

// stateSchemas bundles the domain schemas for passing to handlers.
func (r *Railgun) stateSchemas() *fungible.StateSchemas {
	return &fungible.StateSchemas{
		NoteSchema:     r.noteSchema,
		TreeLeafSchema: r.treeLeafSchema,
	}
}

var railgunFactoryDeployABI = &abi.Entry{
	Type: abi.Function,
	Name: "deploy",
	Inputs: abi.ParameterArray{
		{Name: "transactionId", Type: "bytes32"},
		{Name: "tokenName",     Type: "string"},
		{Name: "name",          Type: "string"},
		{Name: "symbol",        Type: "string"},
		{Name: "initialOwner",  Type: "address"},
		{Name: "data",          Type: "bytes"},
	},
}

// New creates a Railgun domain that can be registered with a Paladin node.
func New(callbacks plugintk.DomainCallbacks) *Railgun {
	return &Railgun{Callbacks: callbacks}
}

func (r *Railgun) Name() string { return r.name }

func (r *Railgun) getAlgo() string {
	return railgunsignerapi.AlgoDomainRailgunSnarkBJJ(r.name)
}

// -----------------------------------------------------------------------
// Domain lifecycle methods
// -----------------------------------------------------------------------

func (r *Railgun) ConfigureDomain(ctx context.Context, req *prototk.ConfigureDomainRequest) (*prototk.ConfigureDomainResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	var config types.DomainFactoryConfig
	if err := json.Unmarshal([]byte(req.ConfigJson), &config); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorParseDomainConfig, err)
	}

	for _, contract := range config.DomainContracts.Implementations {
		contract.Circuits.Init()
	}

	r.name = req.Name
	r.config = &config
	r.chainID = req.ChainId

	schemas, err := types.GetStateSchemas()
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorConfigRailgunDomain, err)
	}

	events := getAllRailgunEventAbis()
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorMarshalRailgunEventAbis, err)
	}

	r.registerEventSignatures(events)

	// The domain always registers the snark signing algorithm; circuit artifacts
	// are loaded lazily from CircuitsDir when a transfer/unshield is proven.
	if config.SnarkProver.CircuitsDir != "" {
		r.prover = railgunprover.NewProver(config.SnarkProver.CircuitsDir)
	}
	signingAlgos := map[string]int32{r.getAlgo(): 32}

	return &prototk.ConfigureDomainResponse{
		DomainConfig: &prototk.DomainConfig{
			CustomHashFunction:  true,
			AbiStateSchemasJson: schemas,
			AbiEventsJson:       string(eventsJSON),
			SigningAlgorithms:   signingAlgos,
		},
	}, nil
}

func (r *Railgun) InitDomain(ctx context.Context, req *prototk.InitDomainRequest) (*prototk.InitDomainResponse, error) {
	// Schemas in the order GetStateSchemas() returns them: [0] note, [1] tree leaf.
	r.noteSchema = req.AbiStateSchemas[0]
	r.treeLeafSchema = req.AbiStateSchemas[1]
	return &prototk.InitDomainResponse{}, nil
}

func (r *Railgun) InitDeploy(ctx context.Context, req *prototk.InitDeployRequest) (*prototk.InitDeployResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	if _, err := r.validateDeploy(req.Transaction); err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateInitDeployParams, err)
	}
	return &prototk.InitDeployResponse{
		RequiredVerifiers: []*prototk.ResolveVerifierRequest{
			{
				Lookup:       req.Transaction.From,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	}, nil
}

func (r *Railgun) PrepareDeploy(ctx context.Context, req *prototk.PrepareDeployRequest) (*prototk.PrepareDeployResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	initParams, err := r.validateDeploy(req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidatePrepDeployParams, err)
	}
	circuits, err := r.config.GetCircuits(ctx, initParams.TokenName)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorFindCircuit, initParams.TokenName, err)
	}
	instanceConfig := &types.DomainInstanceConfig{
		TokenName: initParams.TokenName,
		Circuits:  circuits,
	}
	configJSON, err := json.Marshal(instanceConfig)
	if err != nil {
		return nil, err
	}
	encoded, err := types.DomainInstanceConfigABI.EncodeABIDataJSONCtx(ctx, configJSON)
	if err != nil {
		return nil, err
	}
	deployParams := &types.DeployParams{
		TransactionID: req.Transaction.TransactionId,
		Data:          pldtypes.HexBytes(encoded),
		TokenName:     initParams.TokenName,
		Name:          initParams.Name,
		Symbol:        initParams.Symbol,
		InitialOwner:  req.ResolvedVerifiers[0].Verifier,
	}
	paramsJSON, err := json.Marshal(deployParams)
	if err != nil {
		return nil, err
	}
	functionJSON, err := json.Marshal(railgunFactoryDeployABI)
	if err != nil {
		return nil, err
	}
	from := req.Transaction.From
	return &prototk.PrepareDeployResponse{
		Transaction: &prototk.PreparedTransaction{
			FunctionAbiJson: string(functionJSON),
			ParamsJson:      string(paramsJSON),
		},
		Signer: &from,
	}, nil
}

func (r *Railgun) InitContract(ctx context.Context, req *prototk.InitContractRequest) (*prototk.InitContractResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	domainConfig, err := r.decodeDomainConfig(ctx, req.ContractConfig)
	if err != nil {
		return &prototk.InitContractResponse{Valid: false}, nil
	}
	configJSON, err := json.Marshal(domainConfig)
	if err != nil {
		return &prototk.InitContractResponse{Valid: false}, nil
	}
	return &prototk.InitContractResponse{
		Valid: true,
		ContractConfig: &prototk.ContractConfig{
			ContractConfigJson:   string(configJSON),
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
			SubmitterSelection:   prototk.ContractConfig_SUBMITTER_SENDER,
		},
	}, nil
}

// -----------------------------------------------------------------------
// Transaction lifecycle methods
// -----------------------------------------------------------------------

func (r *Railgun) InitTransaction(ctx context.Context, req *prototk.InitTransactionRequest) (*prototk.InitTransactionResponse, error) {
	ctx, tx, handler, err := r.validateTxAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateInitTxSpec, err)
	}
	return handler.Init(ctx, tx, req)
}

func (r *Railgun) AssembleTransaction(ctx context.Context, req *prototk.AssembleTransactionRequest) (*prototk.AssembleTransactionResponse, error) {
	ctx, tx, handler, err := r.validateTxAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateAssembleTxSpec, err)
	}
	return handler.Assemble(ctx, tx, req)
}

func (r *Railgun) EndorseTransaction(ctx context.Context, req *prototk.EndorseTransactionRequest) (*prototk.EndorseTransactionResponse, error) {
	ctx, tx, handler, err := r.validateTxAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateEndorseTxParams, err)
	}
	return handler.Endorse(ctx, tx, req)
}

func (r *Railgun) PrepareTransaction(ctx context.Context, req *prototk.PrepareTransactionRequest) (*prototk.PrepareTransactionResponse, error) {
	ctx, tx, handler, err := r.validateTxAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidatePrepTxSpec, err)
	}
	return handler.Prepare(ctx, tx, req)
}

func (r *Railgun) InitCall(ctx context.Context, req *prototk.InitCallRequest) (*prototk.InitCallResponse, error) {
	ctx, tx, handler, err := r.validateCallAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateInitCallTxSpec, err)
	}
	return handler.InitCall(ctx, tx, req)
}

func (r *Railgun) ExecCall(ctx context.Context, req *prototk.ExecCallRequest) (*prototk.ExecCallResponse, error) {
	ctx, tx, handler, err := r.validateCallAndGetLogCtx(ctx, req.Transaction)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorValidateExecCallTxSpec, err)
	}
	return handler.ExecCall(ctx, tx, req)
}

// -----------------------------------------------------------------------
// Event handling
// -----------------------------------------------------------------------

func (r *Railgun) HandleEventBatch(ctx context.Context, req *prototk.HandleEventBatchRequest) (*prototk.HandleEventBatchResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	ctx = log.WithLogField(ctx, "contract", req.ContractInfo.ContractAddress)

	// Pass 1: correlate on-chain tx hashes to Paladin tx ids (embedded in the
	// shield/transact ciphertext). Pass 2: process events, attaching the tx id.
	txIDByHash := txCorrelation(ctx, req.Events, r.events.shield, r.events.transact)

	var res prototk.HandleEventBatchResponse
	var errors []string
	for _, ev := range req.Events {
		txID := txIDByHash[ev.Location.TransactionHash]
		var evErr error
		switch ev.SoliditySignature {
		case r.events.shield:
			evErr = r.handleShieldEvent(ctx, ev, txID, &res)
		case r.events.transact:
			evErr = r.handleTransactEvent(ctx, ev, txID, &res)
		case r.events.unshield:
			evErr = r.handleUnshieldEvent(ctx, ev, txID, &res)
		case r.events.nullified:
			evErr = r.handleNullifiedEvent(ctx, ev, txID, &res)
		}
		if evErr != nil {
			errors = append(errors, evErr.Error())
		}
	}
	if len(errors) > 0 {
		return &res, i18n.NewError(ctx, msgs.MsgErrorHandleEvents, formatErrors(errors))
	}
	return &res, nil
}

// -----------------------------------------------------------------------
// Signer interface
// -----------------------------------------------------------------------

// GetVerifier returns a party's Railgun address — its masterPublicKey — derived
// from the spending key. Senders resolve recipients to this value to form note
// public keys.
func (r *Railgun) GetVerifier(ctx context.Context, req *prototk.GetVerifierRequest) (*prototk.GetVerifierResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	if req.VerifierType != railgunsignerapi.RAILGUN_MASTER_PUBLIC_KEY {
		return nil, i18n.NewError(ctx, msgs.MsgErrorGetVerifier, "unsupported verifier type "+req.VerifierType)
	}
	mpk, err := railgunsignerapi.MasterPublicKey(req.PrivateKey)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorGetVerifier, err)
	}
	return &prototk.GetVerifierResponse{Verifier: mpk}, nil
}

func (r *Railgun) Sign(ctx context.Context, req *prototk.SignRequest) (*prototk.SignResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	switch req.PayloadType {
	case railgunsignerapi.PAYLOAD_DOMAIN_RAILGUN_NULLIFIER:
		// nullifier = Poseidon(nullifyingKey, leafIndex)
		nullifier, err := railgunsignerapi.ComputeNullifier(ctx, req.PrivateKey, req.Payload)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgNullifierGenerationFailed)
		}
		return &prototk.SignResponse{Payload: nullifier}, nil
	case railgunsignerapi.PAYLOAD_DOMAIN_RAILGUN_SNARK:
		if r.prover == nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorSign, "snark prover not configured (no circuits dir)")
		}
		// Build the joinsplit witness and generate the Groth16 proof, returning
		// the fully-assembled on-chain Transaction.
		txn, err := fungible.GenerateTransactionProof(ctx, r.prover, req.PrivateKey, req.Payload)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorSign, err)
		}
		return &prototk.SignResponse{Payload: txn}, nil
	default:
		return nil, i18n.NewError(ctx, msgs.MsgUnknownSignPayload, req.PayloadType)
	}
}

// -----------------------------------------------------------------------
// State validation
// -----------------------------------------------------------------------

func (r *Railgun) ValidateStateHashes(ctx context.Context, req *prototk.ValidateStateHashesRequest) (*prototk.ValidateStateHashesResponse, error) {
	ctx = log.WithComponent(ctx, "railgun")
	var res prototk.ValidateStateHashesResponse
	for _, state := range req.States {
		var id string
		var err error
		switch state.SchemaId {
		case r.noteSchema.Id:
			id, err = r.validateNoteState(ctx, state)
		default:
			id = state.Id
		}
		if err != nil {
			return nil, err
		}
		res.StateIds = append(res.StateIds, id)
	}
	return &res, nil
}

func (r *Railgun) validateNoteState(ctx context.Context, state *prototk.EndorsableState) (string, error) {
	var note types.RailgunNote
	if err := json.Unmarshal([]byte(state.StateDataJson), &note); err != nil {
		return "", i18n.NewError(ctx, msgs.MsgErrorUnmarshalStateData, err)
	}
	hash, err := note.Hash(ctx)
	if err != nil {
		return "", i18n.NewError(ctx, msgs.MsgErrorHashOutputState, err)
	}
	return r.validateStateHash(ctx, hash, state)
}

func (r *Railgun) validateStateHash(ctx context.Context, hash *pldtypes.HexUint256, state *prototk.EndorsableState) (string, error) {
	hashHex := hash.HexString0xPrefix()
	if state.Id == "" {
		return hashHex, nil
	}
	existing, _ := pldtypes.ParseHexUint256(ctx, state.Id)
	if existing == nil || hash.Int().Cmp(existing.Int()) != 0 {
		return "", i18n.NewError(ctx, msgs.MsgErrorStateHashMismatch, hash.String(), state.Id)
	}
	return state.Id, nil
}

// -----------------------------------------------------------------------
// Handler routing
// -----------------------------------------------------------------------

// GetHandler returns the DomainHandler for the given method name.
func (r *Railgun) GetHandler(method string) types.DomainHandler {
	ss := r.stateSchemas()
	switch method {
	case types.METHOD_SHIELD:
		return fungible.NewShieldHandler(r.name, r.Callbacks, ss)
	case types.METHOD_TRANSFER:
		return fungible.NewTransferHandler(r.name, r.Callbacks, ss, r.chainID)
	case types.METHOD_UNSHIELD:
		return fungible.NewUnshieldHandler(r.name, r.Callbacks, ss, r.chainID)
	default:
		return nil
	}
}

// GetCallHandler returns the DomainCallHandler for read-only calls.
func (r *Railgun) GetCallHandler(method string) types.DomainCallHandler {
	switch method {
	case types.METHOD_BALANCE_OF:
		return fungible.NewBalanceOfHandler(r.name, r.Callbacks, r.stateSchemas())
	default:
		return nil
	}
}

// -----------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------

func (r *Railgun) validateDeploy(tx *prototk.DeployTransactionSpecification) (*types.InitializerParams, error) {
	var params types.InitializerParams
	err := json.Unmarshal([]byte(tx.ConstructorParamsJson), &params)
	return &params, err
}

func (r *Railgun) decodeDomainConfig(ctx context.Context, domainConfig []byte) (*types.DomainInstanceConfig, error) {
	configValues, err := types.DomainInstanceConfigABI.DecodeABIDataCtx(ctx, domainConfig, 0)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgErrorAbiDecodeDomainConfig, err)
	}
	configJSON, err := pldtypes.StandardABISerializer().SerializeJSON(configValues)
	if err != nil {
		return nil, err
	}
	var config types.DomainInstanceConfig
	return &config, json.Unmarshal(configJSON, &config)
}

func validateTransactionCommon[T any](
	ctx context.Context,
	tx *prototk.TransactionSpecification,
	getHandler func(method string) T,
	abis map[string]*abi.Entry,
) (*types.ParsedTransaction, T, error) {
	var functionABI abi.Entry
	if err := json.Unmarshal([]byte(tx.FunctionAbiJson), &functionABI); err != nil {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgErrorUnmarshalFuncAbi, err)
	}

	var domainConfig *types.DomainInstanceConfig
	if err := json.Unmarshal([]byte(tx.ContractInfo.ContractConfigJson), &domainConfig); err != nil {
		var zero T
		return nil, zero, err
	}

	abiEntry := abis[functionABI.Name]
	handler := getHandler(functionABI.Name)
	handlerValue := reflect.ValueOf(handler)
	if abiEntry == nil || handlerValue.IsNil() {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgUnknownFunction, functionABI.Name)
	}

	validator, ok := any(handler).(interface {
		ValidateParams(ctx context.Context, domainConfig *types.DomainInstanceConfig, paramsJson string) (any, error)
	})
	if !ok {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgErrorHandlerImplementationNotFound)
	}

	params, err := validator.ValidateParams(ctx, domainConfig, tx.FunctionParamsJson)
	if err != nil {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgErrorValidateFuncParams, err)
	}

	sig := abiEntry.SolString()
	if tx.FunctionSignature != sig {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgUnexpectedFuncSignature, functionABI.Name, sig, tx.FunctionSignature)
	}

	contractAddress, err := ethtypes.NewAddress(tx.ContractInfo.ContractAddress)
	if err != nil {
		var zero T
		return nil, zero, i18n.NewError(ctx, msgs.MsgErrorDecodeContractAddress, err)
	}

	return &types.ParsedTransaction{
		Transaction:     tx,
		FunctionABI:     &functionABI,
		ContractAddress: contractAddress,
		DomainConfig:    domainConfig,
		Params:          params,
	}, handler, nil
}

func (r *Railgun) validateTx(ctx context.Context, tx *prototk.TransactionSpecification) (*types.ParsedTransaction, types.DomainHandler, error) {
	return validateTransactionCommon(ctx, tx, r.GetHandler, types.RailgunABI.Functions())
}

func (r *Railgun) validateCall(ctx context.Context, tx *prototk.TransactionSpecification) (*types.ParsedTransaction, types.DomainCallHandler, error) {
	return validateTransactionCommon(ctx, tx, r.GetCallHandler, types.RailgunABI.Functions())
}

func (r *Railgun) validateTxAndGetLogCtx(ctx context.Context, tx *prototk.TransactionSpecification) (context.Context, *types.ParsedTransaction, types.DomainHandler, error) {
	ctx = log.WithComponent(ctx, "railgun")
	parsed, handler, err := r.validateTx(ctx, tx)
	if err != nil {
		return ctx, nil, nil, err
	}
	ctx = log.WithLogField(ctx, "tx", parsed.Transaction.TransactionId)
	ctx = log.WithLogField(ctx, "contract", parsed.Transaction.ContractInfo.ContractAddress)
	return ctx, parsed, handler, nil
}

func (r *Railgun) validateCallAndGetLogCtx(ctx context.Context, tx *prototk.TransactionSpecification) (context.Context, *types.ParsedTransaction, types.DomainCallHandler, error) {
	ctx = log.WithComponent(ctx, "railgun")
	parsed, handler, err := r.validateCall(ctx, tx)
	if err != nil {
		return ctx, nil, nil, err
	}
	ctx = log.WithLogField(ctx, "tx", parsed.Transaction.TransactionId)
	ctx = log.WithLogField(ctx, "contract", parsed.Transaction.ContractInfo.ContractAddress)
	return ctx, parsed, handler, nil
}

// -----------------------------------------------------------------------
// Event signature registration
// -----------------------------------------------------------------------

func (r *Railgun) registerEventSignatures(eventAbis abi.ABI) {
	for _, event := range eventAbis.Events() {
		switch event.Name {
		case "Shield":
			r.events.shield = event.SolString()
		case "Transact":
			r.events.transact = event.SolString()
		case "Unshield":
			r.events.unshield = event.SolString()
		case "Nullified":
			r.events.nullified = event.SolString()
		}
	}
}

