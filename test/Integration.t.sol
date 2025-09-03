// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/proposers/TrustlessProposer.sol";
import "../src/proposers/UnsafeProposer.sol";
import "../src/proposers/OPStackProposer.sol";
import "../src/mocks/MockInbox.sol";
import "../src/interfaces/IGasTank.sol";

/**
 * @title DA Builder Integration Tests
 * @dev Tests for the complete DA Builder integration flow
 */
contract IntegrationTest is Test {
    // Test addresses - using a known private key for testing
    uint256 constant USER_PRIVATE_KEY = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;
    address public user;
    address public builder;
    address constant PROPOSER_MULTICALL = address(0x5132dCe9aD675b2ac5E37D69D2bC7399764b5469);
    address constant GAS_TANK = address(0x18Fa15ea0A34a7c4BCA01bf7263b2a9Ac0D32e92);
    address constant L2_INBOX = address(0x3456789012345678901234567890123456789012);

    // Test contracts
    TrustlessProposer public proposerImpl;
    UnsafeProposer public unsafeProposer;
    OPStackProposer public opStackProposer;
    MockInbox public inbox;

    function setUp() public {
        user = vm.addr(USER_PRIVATE_KEY);
        builder = address(0x9999999999999999999999999999999999999999);

        console.log("[TEST] USER_PRIVATE_KEY address:", user);

        // Deploy contracts
        proposerImpl = new TrustlessProposer(PROPOSER_MULTICALL);
        unsafeProposer = new UnsafeProposer(PROPOSER_MULTICALL);
        opStackProposer = new OPStackProposer(PROPOSER_MULTICALL);
        inbox = new MockInbox();

        // Fund user
        vm.deal(user, 100 ether);

        // Set the EOA's code to the TestTrustlessProposer's code (simulate EIP-7702)
        vm.etch(user, address(proposerImpl).code);
    }

    function testTrustlessProposer() public {
        console.log("Testing TrustlessProposer");
        console.log("============================");

        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));

        // Debug: Check addresses
        console.log("User (EOA) address:", user);
        console.log("ProposerImpl address:", address(proposerImpl));
        console.log("User code length:", user.code.length);

        // Create properly signed data for TrustlessProposer
        bytes memory signedData = createTrustlessProposerData(user, target, data, 0, 200_000);

        vm.prank(PROPOSER_MULTICALL);
        bool success = IProposer(user).onCall(target, signedData, 0);
        assertTrue(success, "TrustlessProposer call should succeed");

        // Verify the call was processed
        uint256 messageCount = inbox.getMessageCount();
        assertGt(messageCount, 0, "Message should be sent to inbox");
        console.log("TrustlessProposer call successful!");
        console.log("Messages sent:", messageCount);
        console.log("TrustlessProposer test passed!");
    }

    function testTrustlessProposerRejectsGasLimitExceeded() public {
        console.log("Testing TrustlessProposer gas limit enforcement");

        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));

        // Create signed data with a very low gas limit that will be exceeded
        bytes memory signedData = createTrustlessProposerData(user, target, data, 0, 1_000); // Very low gas limit

        vm.prank(PROPOSER_MULTICALL);

        // Expect the call to revert with GasLimitExceeded error
        vm.expectRevert(abi.encodeWithSelector(TrustlessProposer.GasLimitExceeded.selector));
        IProposer(user).onCall(target, signedData, 0);

        console.log("TrustlessProposer gas limit enforcement test passed!");
    }

    function testTrustlessProposerRejectsInvalidSignature() public {
        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));
        // Create data with invalid signature
        bytes memory invalidData = abi.encode(bytes(""), block.timestamp, 0, data);
        vm.prank(PROPOSER_MULTICALL);
        vm.expectRevert(abi.encodeWithSelector(TrustlessProposer.SignatureInvalid.selector));
        IProposer(user).onCall(target, invalidData, 0);
    }

    function testTrustlessProposerRejectsExpiredDeadline() public {
        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));
        // Create data with expired deadline
        uint256 expiredDeadline = block.timestamp - 1;
        bytes memory expiredData = abi.encode(bytes(""), expiredDeadline, 0, data);
        vm.prank(PROPOSER_MULTICALL);
        vm.expectRevert(abi.encodeWithSelector(TrustlessProposer.DeadlinePassed.selector));
        IProposer(user).onCall(target, expiredData, 0);
    }

    function testTrustlessProposerRejectsWrongNonce() public {
        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));
        // Create data with wrong nonce
        bytes memory wrongNonceData = abi.encode(bytes(""), block.timestamp, 999, data);
        vm.prank(PROPOSER_MULTICALL);
        vm.expectRevert(abi.encodeWithSelector(TrustlessProposer.NonceTooLow.selector));
        IProposer(user).onCall(target, wrongNonceData, 0);
    }

    /**
     * @dev Test UnsafeProposer functionality
     */
    function testUnsafeProposer() public {
        console.log("Testing UnsafeProposer");
        console.log("==========================");

        // Test basic call functionality
        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));

        vm.prank(PROPOSER_MULTICALL);
        (bool success,) =
            address(unsafeProposer).call(abi.encodeWithSignature("onCall(address,bytes,uint256)", target, data, 0));
        assertTrue(success, "UnsafeProposer call should succeed");

        // Verify the call was processed
        uint256 messageCount = inbox.getMessageCount();
        assertGt(messageCount, 0, "Message should be sent to inbox");

        console.log("UnsafeProposer call successful!");
        console.log("Messages sent:", messageCount);

        console.log("UnsafeProposer test passed!");
    }

    /**
     * @dev Test OPStackProposer functionality
     */
    function testOPStackProposer() public {
        console.log("Testing OPStackProposer");
        console.log("===========================");

        // Test basic call functionality
        address target = address(inbox);
        // OPStackProposer expects bytes32[] versioned hashes, not regular calldata
        bytes32[] memory versionedHashes = new bytes32[](1);
        versionedHashes[0] = keccak256("test blob data");
        bytes memory data = abi.encode(versionedHashes);

        vm.prank(PROPOSER_MULTICALL);
        (bool success,) =
            address(opStackProposer).call(abi.encodeWithSignature("onCall(address,bytes,uint256)", target, data, 0));
        assertTrue(success, "OPStackProposer call should succeed");

        console.log("OPStackProposer call successful!");
        console.log("OPStackProposer test passed!");
    }

    /**
     * @dev Test MockInbox functionality
     */
    function testMockInbox() public {
        console.log("Testing MockInbox");
        console.log("====================");

        vm.startPrank(user);

        // Test sending a message
        address target = address(0x42);
        bytes memory data = abi.encodeWithSignature("increment()");
        uint256 value = 0.1 ether;

        inbox.sendMessage{value: value}(target, data);

        // Verify message was recorded
        uint256 messageCount = inbox.getMessageCount();
        assertEq(messageCount, 1, "Should have 1 message");

        // Verify message details
        (address sender, address msgTarget, bytes memory msgData, uint256 msgValue, bool processed, uint256 timestamp) =
            inbox.getMessage(0);

        assertEq(sender, user, "Sender should be user");
        assertEq(msgTarget, target, "Target should match");
        assertEq(msgData, data, "Data should match");
        assertEq(msgValue, value, "Value should match");
        assertFalse(processed, "Message should not be processed initially");
        assertGt(timestamp, 0, "Timestamp should be set");

        console.log("Message sent successfully!");
        console.log("Sender:", sender);
        console.log("Target:", msgTarget);
        console.log("Value:", msgValue);
        console.log("Timestamp:", timestamp);

        vm.stopPrank();

        console.log("MockInbox test passed!");
    }

    /**
     * @dev Test that proposers can only be called by the builder
     */
    function testProposerAccessControl() public {
        console.log("Testing Proposer Access Control");
        console.log("==================================");

        // Test that non-builder cannot call proposers directly
        address target = address(inbox);
        bytes memory data =
            abi.encodeWithSignature("sendMessage(address,bytes)", address(0x42), abi.encodeWithSignature("increment()"));

        // This should fail because the caller is not PROPOSER_MULTICALL or the contract itself
        address unauthorized = address(0xdeadbeef);
        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(IProposer.Unauthorized.selector));
        proposerImpl.onCall(target, data, 0);

        console.log("Access control test completed");

        console.log("Proposer access control test passed!");
    }

    /**
     * @dev Create properly signed data for TrustlessProposer
     * This follows the pattern from the DA Builder documentation
     */
    function createTrustlessProposerData(
        address eoa,
        address target,
        bytes memory callData,
        uint256 value,
        uint256 gasLimit
    ) internal view returns (bytes memory) {
        uint256 nonce = TrustlessProposer(payable(eoa)).nestedNonce();
        uint256 deadline = block.timestamp + 3600;

        // Manually compute the correct domain separator for the EOA address
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("TrustlessProposer"),
                keccak256("1"),
                block.chainid,
                eoa // Use EOA address as verifyingContract
            )
        );

        // Create the struct hash
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Call(uint256 deadline,uint256 nonce,address target,uint256 value,bytes calldata,uint256 gasLimit)"
                ),
                deadline,
                nonce,
                target,
                value,
                keccak256(callData)
                ,
                gasLimit
            )
        );

        // Create the message hash
        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_PRIVATE_KEY, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        return abi.encode(signature, deadline, nonce, callData, gasLimit);
    }
}
