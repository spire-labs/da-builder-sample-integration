// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title MockInbox
/// @notice A mock inbox contract for testing DA Builder integration
/// @dev This simulates an L2 inbox where transactions are submitted
contract MockInbox {
    /// @notice Event emitted when a message is sent to L2
    event MessageSent(address indexed sender, address indexed target, bytes data, uint256 value, uint256 messageId);

    /// @notice Message counter
    uint256 public messageCounter;

    /// @notice Mapping from message ID to message details
    mapping(uint256 => Message) public messages;

    /// @notice Struct for message data
    struct Message {
        address sender;
        address target;
        bytes data;
        uint256 value;
        bool processed;
        uint256 timestamp;
    }

    /// @notice Send a message to L2
    /// @param target The target contract on L2
    /// @param data The calldata to send
    function sendMessage(address target, bytes calldata data) external payable {
        uint256 messageId = messageCounter++;

        messages[messageId] = Message({
            sender: msg.sender,
            target: target,
            data: data,
            value: msg.value,
            processed: false,
            timestamp: block.timestamp
        });

        emit MessageSent(msg.sender, target, data, msg.value, messageId);
    }

    /// @notice Get message details
    /// @param messageId The message ID
    /// @return sender The sender of the message
    /// @return target The target contract
    /// @return data The calldata
    /// @return value The ETH value
    /// @return processed Whether the message was processed
    /// @return timestamp The timestamp when the message was sent
    function getMessage(uint256 messageId)
        external
        view
        returns (address sender, address target, bytes memory data, uint256 value, bool processed, uint256 timestamp)
    {
        Message storage message = messages[messageId];
        return (message.sender, message.target, message.data, message.value, message.processed, message.timestamp);
    }

    /// @notice Mark a message as processed (simulates L2 processing)
    /// @param messageId The message ID to mark as processed
    function markAsProcessed(uint256 messageId) external {
        require(messageId < messageCounter, "Message does not exist");
        messages[messageId].processed = true;
    }

    /// @notice Get the total number of messages sent
    /// @return The total number of messages
    function getMessageCount() external view returns (uint256) {
        return messageCounter;
    }
}
