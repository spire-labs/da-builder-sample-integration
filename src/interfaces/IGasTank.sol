// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IGasTank {
    /// @notice Throws when an account can't be closed
    error AccountCantBeClosed();

    /// @notice Throws when a low level call fails
    error FailedLowLevelCall();

    /// @notice Throws when an account is being closed and they try to deposit
    error AccountClosing();

    /// @notice Throws when the caller is not the owner
    error NotBuilder();

    /// @notice Event emitted when an account is initiated to be closed
    event AccountCloseInitiated(address _operator);

    /// @notice Event emitted when an account is closed
    event AccountClosed(address _operator);

    /// @notice Event emitted when an account makes a deposit
    event AccountDeposited(address _operator, uint256 _newBalance);

    /// @notice Struct for charging an account
    /// @param charge The amount to charge
    /// @param operator The address of the account to charge
    struct Account {
        uint256 charge;
        address operator;
    }

    function initialize(address _owner, address _builder) external;
    function setBuilder(address _builder) external;
    function deposit() external payable;
    function charge(Account calldata _account) external;
    function batchCharge(Account[] calldata _accounts) external;
    function initiateAccountClose() external;
    function closeAccount(address _operator) external;
    function withdrawalStartedAt(address _operator) external view returns (uint256);
    function balances(address _operator) external view returns (uint256);
    function builder() external view returns (address);
}
