// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IPaladinContractRegistry_V0} from "./IPaladinContractRegistry.sol";

/// @title RailgunFactory — Paladin registration wrapper for a RailgunSmartWallet.
/// @notice Paladin's Railgun domain plugin drives deployment by calling `deploy(...)`
/// on the contract registered as the domain's factory. This factory registers a
/// pre-deployed RailgunSmartWallet instance (the real Railgun privacy-pool contract,
/// see contracts/logic/RailgunSmartWallet.sol in the Railgun repo) with the off-chain
/// domain by emitting `PaladinRegisterSmartContract_V0`.
///
/// The `data` argument is forwarded verbatim; the Railgun domain encodes it as the
/// ABI-encoded `DomainInstanceConfig` (token name + circuit set) — see
/// `pkg/types/config.go` in the paladin-railgun repo.
contract RailgunFactory is IPaladinContractRegistry_V0 {
    /// The deployed RailgunSmartWallet that instances register against.
    address public immutable implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function deploy(
        bytes32 transactionId,
        string memory tokenName,
        string memory name,
        string memory symbol,
        address initialOwner,
        bytes memory data
    ) external {
        // tokenName/name/symbol/initialOwner are part of the standard Paladin
        // factory ABI; the RailgunSmartWallet itself is already deployed and
        // initialized, so we simply announce it to the domain.
        emit PaladinRegisterSmartContract_V0(transactionId, implementation, data);
    }
}
