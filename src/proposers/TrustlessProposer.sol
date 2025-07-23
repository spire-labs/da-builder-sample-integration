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

    bytes32 public constant CALL_TYPEHASH =
        keccak256("Call(uint256 deadline,uint256 nonce,address target,uint256 value,bytes calldata)");

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
        if (msg.sender != PROPOSER_MULTICALL && address(this) != msg.sender) revert Unauthorized();

        // Decode the data parameter which contains: (signature, deadline, nonce, actual_calldata)
        (bytes memory _sig, uint256 _deadline, uint256 _nonce, bytes memory _calldata) =
            abi.decode(_data, (bytes, uint256, uint256, bytes));

        if (block.timestamp > _deadline) revert DeadlinePassed();
        if (_nonce != nestedNonce) revert NonceTooLow();

        // Create the EIP-712 message hash
        bytes32 _structHash =
            keccak256(abi.encode(CALL_TYPEHASH, _deadline, _nonce, _target, _value, _calldata));
        bytes32 _messageHash = _hashTypedDataV4(_structHash);

        // Extract signature components
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(_sig, 0x20))
            s := mload(add(_sig, 0x40))
            v := byte(0, mload(add(_sig, 0x60)))
        }

        // Recover the signer from the signature
        address _signer = ecrecover(_messageHash, v, r, s);
        if (_signer != address(this)) revert SignatureInvalid();

        // Execute the actual call
        (bool _success,) = _target.call{value: _value}(_calldata);
        if (!_success) {
            revert LowLevelCallFailed();
        }

        nestedNonce++;
        return true;
    }

    function getMessageHash(uint256 _deadline, uint256 _nonce, address _target, uint256 _value, bytes memory _calldata)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(CALL_TYPEHASH, _deadline, _nonce, _target, _value, keccak256(_calldata)))
        );
    }

    receive() external payable {}
    fallback() external payable {}
}
