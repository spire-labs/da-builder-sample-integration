// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "../interfaces/IProposer.sol";

/// @title UnsafeProposer
///
/// @dev An example implementation of a proposer contract that is compatible with the aggregation service
///      Intended to be set as an EOA account code (EIP-7702)
///      This contract is meant to be an example implementation, and is stateless for the sake of simple storage management
contract UnsafeProposer is IProposer {
    /// @notice The address of the proposer multicall contract
    address public immutable PROPOSER_MULTICALL;

    /// @notice Constructor
    ///
    /// @param _proposerMulticall The address of the proposer multicall contract
    constructor(address _proposerMulticall) {
        PROPOSER_MULTICALL = _proposerMulticall;
    }

    /// @notice Fallback function to receive ether
    receive() external payable {}

    /// @dev     To support EIP 721 and EIP 1155, we need to respond to those methods with their own method signature
    ///
    /// @return  bytes4  onERC721Received function selector
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /// @dev     To support EIP 721 and EIP 1155, we need to respond to those methods with their own method signature
    ///
    /// @return  bytes4  onERC1155Received function selector
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /// @dev     To support EIP 721 and EIP 1155, we need to respond to those methods with their own method signature
    ///
    /// @return  bytes4  onERC1155BatchReceived function selector
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /// @notice  nothing to do here
    ///
    /// @dev     this contract can accept ETH with calldata, hence payable
    fallback() external payable {}

    /// @notice  EIP-1155 implementation
    /// we pretty much only need to signal that we support the interface for 165, but for 1155 we also need the fallback function
    ///
    /// @param   _interfaceID  the interface we're signaling support for
    ///
    /// @return  bool  True if the interface is supported, false otherwise.
    function supportsInterface(bytes4 _interfaceID) external pure returns (bool) {
        bool _supported = _interfaceID == 0x01ffc9a7 // ERC-165 support (i.e. `bytes4(keccak256('supportsInterface(bytes4)'))`).
            || _interfaceID == 0x150b7a02 // ERC721TokenReceiver
            || _interfaceID == 0x4e2312e0; // ERC-1155 `ERC1155TokenReceiver` support (i.e. `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")) ^ bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`).
        return _supported;
    }

    /// @notice Makes an arbitrary low level call
    ///
    /// @param _target The address to call
    /// @param _data The calldata to send
    /// @param _value The value to send with the call
    ///
    /// @return True by default if the call succeeds
    ///
    /// @dev The interface expectation is the boolean return value matches the status of the call, if it returns false for any reason
    ///      the builder will ignore the transaction
    /// @dev Has a whitelist check to enforce an authorized caller
    /// @dev Used to allow for contracts to make arbitrary calls for an EOA
    function call(address _target, bytes calldata _data, uint256 _value) external returns (bool) {
        if (msg.sender != PROPOSER_MULTICALL && address(this) != msg.sender) revert Unauthorized();

        (bool _success,) = _target.call{value: _value}(_data);
        if (!_success) {
            revert LowLevelCallFailed();
        }

        return true;
    }
}
