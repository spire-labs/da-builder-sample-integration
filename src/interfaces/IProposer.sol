// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IProposer {
    error LowLevelCallFailed();
    error Unauthorized();

    function onCall(address _target, bytes calldata _data, uint256 _value) external returns (bool);
}
