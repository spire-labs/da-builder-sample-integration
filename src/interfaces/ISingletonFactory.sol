// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Interface for the ERC-2470 Singleton Factory at 0xce0042B868300000d44A59004Da54A005ffdcf9f
/// @dev This factory allows deterministic deployment of contracts using CREATE2
interface ISingletonFactory {
    /// @notice Deploys `_initCode` using `_salt` for defining the deterministic address
    /// @param _initCode Initialization code (contract bytecode + constructor args)
    /// @param _salt Arbitrary value to modify resulting address
    /// @return createdContract Created contract address
    function deploy(bytes memory _initCode, bytes32 _salt) external returns (address payable createdContract);
}
