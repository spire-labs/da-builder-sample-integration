// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Minimal interface for the standard Foundry CREATE2 factory at 0x4e59b44847b379578588920cA78FbF26c0B4956C
interface ICreate2Factory {
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address);
    function getDeployed(bytes32 salt) external view returns (address);
} 