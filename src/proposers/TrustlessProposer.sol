// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "../interfaces/IProposer.sol";

/// @title TrustlessProposer
/// @notice A secure proposer implementation that requires cryptographic signatures
/// @dev Uses custom storage layout to prevent conflicts with future account code versions
/// @custom:storage-location keccak256(abi.encode(uint256(keccak256("Spire.TrustlessProposer.1.0.0")) - 1)) & ~bytes32(uint256(0xff))
contract TrustlessProposer is IProposer, EIP712 layout at 25_732_701_950_170_629_563_862_734_149_613_701_595_693_524_766_703_709_478_375_563_609_458_162_252_544 {
    error NonceTooLow();
    error DeadlinePassed();
    error SignatureInvalid();
    error GasLimitExceeded();

    bytes32 public constant CALL_TYPEHASH =
        keccak256("Call(uint256 deadline,uint256 nonce,address target,uint256 value,bytes calldata,uint256 gasLimit)");

    /// @notice The address of the proposer multicall contract
    address public immutable PROPOSER_MULTICALL;

    /// @notice A separate nonce for nested calls from external callers
    ///
    /// @dev Nonce is used as a uint256 instead of a mapping for gas reasons
    uint256 public nestedNonce;

    /// @notice Constructor
    ///
    /// @param _proposerMulticall The address of the proposer multicall contract
    constructor(address _proposerMulticall) EIP712("TrustlessProposer", "1") {
        PROPOSER_MULTICALL = _proposerMulticall;
    }

    function call(address _target, bytes calldata _data, uint256 _value) external returns (bool) {
        // The estimated gas used is not perfect but provides a meaningful bound to know if we went over the gas limit
        uint256 _startGas = gasleft();

        if (msg.sender != PROPOSER_MULTICALL && address(this) != msg.sender) revert Unauthorized();

        // Decode the data parameter which contains: (signature, deadline, nonce, actual_calldata, gasLimit)
        (bytes memory _sig, uint256 _deadline, uint256 _nonce, bytes memory _calldata, uint256 _gasLimit) =
            abi.decode(_data, (bytes, uint256, uint256, bytes, uint256));

        if (block.timestamp > _deadline) revert DeadlinePassed();
        if (_nonce != nestedNonce) revert NonceTooLow();

        // Create the EIP-712 message hash
        bytes32 _messageHash = getMessageHash(_deadline, _nonce, _target, _value, _calldata, _gasLimit);

        // Recover the signer from the signature
        address _signer = getSignerFromSignature(_messageHash, _sig);
        if (_signer != address(this)) revert SignatureInvalid();

        // Execute the actual call
        (bool _success,) = _target.call{value: _value}(_calldata);
        if (!_success) {
            revert LowLevelCallFailed();
        }

        nestedNonce++;

        // If gas used is greater than gasLimit, revert
        if (_startGas - gasleft() > _gasLimit) {
            revert GasLimitExceeded();
        }

        return true;
    }

    /// @notice Hashes the typed data for the call
    ///
    /// @param _deadline The deadline for the call
    /// @param _nonce The nonce for the call
    /// @param _target The target for the call
    /// @param _value The value for the call
    /// @param _calldata The calldata for the call
    /// @param _gasLimit The gas limit for the call
    function getMessageHash(
        uint256 _deadline,
        uint256 _nonce,
        address _target,
        uint256 _value,
        bytes memory _calldata,
        uint256 _gasLimit
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(keccak256(abi.encode(CALL_TYPEHASH, _deadline, _nonce, _target, _value, _calldata, _gasLimit)));
    }

    /// @notice Gets the signer from the signature
    ///
    /// @param _messageHash The message hash to recover the signer from
    /// @param _sig The signature to recover the signer from
    ///
    /// @return The signer address
    function getSignerFromSignature(bytes32 _messageHash, bytes memory _sig) public pure returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        assembly {
            r := mload(add(_sig, 0x20))
            s := mload(add(_sig, 0x40))
            v := byte(0, mload(add(_sig, 0x60)))
        }

        return ecrecover(_messageHash, v, r, s);
    }

    receive() external payable {}
    fallback() external payable {}
}
