// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

import "../src/FastBridge.sol";
import "../src/interfaces/IFastBridge.sol";
import "../src/libs/Errors.sol";
import "../src/libs/UniversalToken.sol";

import "./MockERC20.sol";

contract FastBridgeTest is Test {
    FastBridge public fastBridge;

    address owner = address(1);
    address relayer = address(2);
    address guard = address(3);
    address user = address(4);
    address dstUser = address(5);
    MockERC20 arbUSDC;
    MockERC20 ethUSDC;

    function setUp() public {
        vm.chainId(42161);
        fastBridge = new FastBridge(owner);
        arbUSDC = new MockERC20("arbUSDC", 6);
        ethUSDC = new MockERC20("ethUSDC", 6);
        _mintTokensToActors();
    }

    function _mintTokensToActors() internal {
        arbUSDC.mint(relayer, 100 * 10 ** 6);
        arbUSDC.mint(guard, 100 * 10 ** 6);
        arbUSDC.mint(user, 100 * 10 ** 6);
        arbUSDC.mint(dstUser, 100 * 10 ** 6);
        ethUSDC.mint(relayer, 100 * 10 ** 6);
        ethUSDC.mint(guard, 100 * 10 ** 6);
        ethUSDC.mint(user, 100 * 10 ** 6);
        ethUSDC.mint(dstUser, 100 * 10 ** 6);
    }

    function _getBridgeRequestAndId(
        uint256 chainId,
        uint256 currentNonce
    ) internal returns (bytes memory request, bytes32 transactionId) {
        // Define input variables for the bridge transaction
        address to = user;
        address oldRelayer = relayer;
        uint32 originChainId = uint32(chainId);
        uint32 dstChainId = 1;
        address originToken = address(arbUSDC);
        address destToken = address(ethUSDC);
        uint256 originAmount = 11 * 10 ** 6;
        uint256 destAmount = 10.97e6;
        uint256 deadline = block.timestamp + 3600;

        // Calculate the expected transaction ID
        request = abi.encode(
            IFastBridge.BridgeTransaction({
                originChainId: originChainId,
                destChainId: dstChainId,
                originSender: user,
                destRecipient: to,
                originToken: originToken,
                destToken: destToken,
                originAmount: originAmount,
                destAmount: destAmount,
                deadline: deadline,
                nonce: currentNonce
            })
        );
        transactionId = keccak256(request);
    }

    function _getBridgeRequestAndIdWithETH(
        uint256 chainId,
        uint256 currentNonce
    ) internal returns (bytes memory request, bytes32 transactionId) {
        // Define input variables for the bridge transaction
        address to = user;
        address oldRelayer = relayer;
        uint32 originChainId = uint32(chainId);
        uint32 dstChainId = 1;
        address originToken = UniversalTokenLib.ETH_ADDRESS;
        address destToken = UniversalTokenLib.ETH_ADDRESS;
        uint256 originAmount = 11 * 10 ** 18;
        uint256 destAmount = 10.97e18;
        uint256 deadline = block.timestamp + 3600;

        // Calculate the expected transaction ID
        request = abi.encode(
            IFastBridge.BridgeTransaction({
                originChainId: originChainId,
                destChainId: dstChainId,
                originSender: user,
                destRecipient: to,
                originToken: originToken,
                destToken: destToken,
                originAmount: originAmount,
                destAmount: destAmount,
                deadline: deadline,
                nonce: currentNonce
            })
        );
        transactionId = keccak256(request);
    }

    function setUpRoles() public {
        vm.startPrank(owner);
        fastBridge.addRelayer(relayer);
        fastBridge.addGuard(guard);
        assertTrue(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
        assertTrue(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
        vm.stopPrank();
    }

    /// @notice Test to check if the owner is correctly set
    function test_owner() public {
        assertEq(fastBridge.owner(), owner);
    }

    /// @notice Test to check if a relayer can be successfully added
    function test_successfulAddRelayer() public {
        vm.startPrank(owner);
        assertFalse(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
        fastBridge.addRelayer(relayer);
        assertTrue(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
    }

    /// @notice Test to check if only an admin can add a relayer
    function test_onlyAdminCanAddRelayer() public {
        vm.startPrank(relayer);
        assertFalse(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
        vm.expectRevert();
        fastBridge.addRelayer(relayer);
    }

    /// @notice Test to check if a relayer can be successfully removed
    function test_successfulRemoveRelayer() public {
        test_successfulAddRelayer();
        assertTrue(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
        vm.startPrank(owner);
        fastBridge.removeRelayer(relayer);
        assertFalse(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
    }

    /// @notice Test to check if only an admin can remove a relayer
    function test_onlyAdminCanRemoveRelayer() public {
        test_successfulAddRelayer();
        vm.startPrank(relayer);
        assertTrue(fastBridge.hasRole(fastBridge.RELAYER_ROLE(), relayer));
        vm.expectRevert();
        fastBridge.removeRelayer(relayer);
    }

    /// @notice Test to check if a guard can be successfully added
    function test_successfulAddGuard() public {
        vm.startPrank(owner);
        assertFalse(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
        fastBridge.addGuard(guard);
        assertTrue(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
    }

    /// @notice Test to check if only an admin can add a guard
    function test_onlyAdminCanAddGuard() public {
        vm.startPrank(guard);
        assertFalse(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
        vm.expectRevert();
        fastBridge.addGuard(guard);
    }

    /// @notice Test to check if a guard can be successfully removed
    function test_successfulRemoveGuard() public {
        test_successfulAddGuard();
        assertTrue(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
        vm.startPrank(owner);
        fastBridge.removeGuard(guard);
        assertFalse(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
    }

    /// @notice Test to check if only an admin can remove a guard
    function test_onlyAdminCanRemoveGuard() public {
        test_successfulAddGuard();
        vm.startPrank(guard);
        assertTrue(fastBridge.hasRole(fastBridge.GUARD_ROLE(), guard));
        vm.expectRevert();
        fastBridge.removeGuard(guard);
    }

    event BridgeRequested(bytes32 transactionId, address sender, bytes request);

    // This test checks the successful execution of a bridge transaction
    function test_successfulBridge() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // get expected bridge request and tx id
        uint256 currentNonce = fastBridge.nonce();
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, currentNonce);

        vm.expectEmit();
        emit BridgeRequested(transactionId, user, request);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(arbUSDC),
            destToken: address(ethUSDC),
            originAmount: 11 * 10 ** 6,
            destAmount: 10.97e6,
            deadline: block.timestamp + 3600
        });
        fastBridge.bridge(params);
        // Check the state of the tokens after the bridge transaction
        // The fastBridge should have 11 * 10 ** 6 of arbUSDC
        assertEq(arbUSDC.balanceOf(address(fastBridge)), 11 * 10 ** 6);
        // The user should have 89 * 10 ** 6 of arbUSDC
        assertEq(arbUSDC.balanceOf(user), 89 * 10 ** 6);

        // Get the information of the bridge transaction
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.REQUESTED));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulBridgeWithETH() public {
        // setup eth
        deal(user, 100 * 10 ** 18);
        uint256 userBalanceBefore = user.balance;
        uint256 bridgeBalanceBefore = address(fastBridge).balance;

        // Start a prank with the user
        vm.startPrank(user);

        // get current nonce
        uint256 currentNonce = fastBridge.nonce();

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: UniversalTokenLib.ETH_ADDRESS,
            destToken: UniversalTokenLib.ETH_ADDRESS,
            originAmount: 11 * 10 ** 18,
            destAmount: 10.97e18,
            deadline: block.timestamp + 3600
        });
        fastBridge.bridge{value: params.originAmount}(params);

        // Check the state of the tokens after the bridge transaction
        uint256 userBalanceAfter = user.balance;
        uint256 bridgeBalanceAfter = address(fastBridge).balance;

        assertEq(userBalanceBefore - userBalanceAfter, 11 * 10 ** 18);
        assertEq(bridgeBalanceAfter - bridgeBalanceBefore, 11 * 10 ** 18);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeSameChainId() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: uint32(block.chainid),
            to: user,
            originToken: address(arbUSDC),
            destToken: address(ethUSDC),
            originAmount: 11 * 10 ** 6,
            destAmount: 10.97e6,
            deadline: block.timestamp + 3600
        });
        vm.expectRevert(abi.encodeWithSelector(ChainIncorrect.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeOriginAmountZero() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(arbUSDC),
            destToken: address(ethUSDC),
            originAmount: 0,
            destAmount: 10.97e6,
            deadline: block.timestamp + 3600
        });
        vm.expectRevert(abi.encodeWithSelector(AmountIncorrect.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeDestAmountZero() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(arbUSDC),
            destToken: address(ethUSDC),
            originAmount: 11 * 10 ** 6,
            destAmount: 0,
            deadline: block.timestamp + 3600
        });
        vm.expectRevert(abi.encodeWithSelector(AmountIncorrect.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeOriginTokenZero() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(0),
            destToken: address(ethUSDC),
            originAmount: 11 * 10 ** 6,
            destAmount: 10.97e6,
            deadline: block.timestamp + 3600
        });
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeDestTokenZero() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(arbUSDC),
            destToken: address(0),
            originAmount: 11 * 10 ** 6,
            destAmount: 10.97e6,
            deadline: block.timestamp + 3600
        });
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedBridgeDeadlineTooShort() public {
        // Start a prank with the user
        vm.startPrank(user);
        // Approve the fastBridge to spend 100 * 10 ** 6 of arbUSDC from the user
        arbUSDC.approve(address(fastBridge), 100 * 10 ** 6);

        // Execute the bridge transaction
        IFastBridge.BridgeParams memory params = IFastBridge.BridgeParams({
            dstChainId: 1,
            to: user,
            originToken: address(arbUSDC),
            destToken: address(ethUSDC),
            originAmount: 11 * 10 ** 6,
            destAmount: 10.97e6,
            deadline: block.timestamp + 1800 - 1
        });
        vm.expectRevert(abi.encodeWithSelector(DeadlineTooShort.selector));
        fastBridge.bridge(params);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    event BridgeRelayed(bytes32 transactionId, address oldRelayer, address to, address token, uint256 amount);

    // This test checks the successful relaying of a destination bridge
    function test_successfulRelayDestination() public {
        // Set up the roles for the test
        setUpRoles();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(42161, 0);

        // Get the initial information of the bridge transaction; make sure not relayed
        assertEq(fastBridge.bridgeRelays(transactionId), false);

        // Start a prank with the relayer
        vm.startPrank(relayer);
        // Approve the fastBridge to spend the maximum amount of ethUSDC from the relayer
        ethUSDC.approve(address(fastBridge), type(uint256).max);
        // Check the initial balances of the relayer and the user
        assertEq(ethUSDC.balanceOf(relayer), 100 * 10 ** 6);
        assertEq(ethUSDC.balanceOf(user), 100 * 10 ** 6);
        // Expect the BridgeRelayed event to be emitted
        vm.expectEmit();
        emit BridgeRelayed(transactionId, relayer, user, address(ethUSDC), 10.97e6);
        // Relay the destination bridge
        vm.chainId(1); // set to dest chain
        fastBridge.relay(request);
        // Check the balances of the relayer and the user after relaying the destination bridge
        assertEq(ethUSDC.balanceOf(relayer), 89.03e6);
        assertEq(ethUSDC.balanceOf(user), 110.97e6);

        // Get the returned information of the bridge transaction relays status
        assertEq(fastBridge.bridgeRelays(transactionId), true);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulRelayDestinationWithETH() public {
        // Set up the roles for the test
        setUpRoles();

        // deal some dest ETH to relayer
        deal(relayer, 100e18);

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndIdWithETH(42161, 0);

        // Get the initial information of the bridge transaction; make sure not relayed
        assertEq(fastBridge.bridgeRelays(transactionId), false);

        // Start a prank with the relayer
        vm.startPrank(relayer);
        // Get the initial balances of the relayer and the user
        uint256 userBalanceBefore = user.balance;
        uint256 relayerBalanceBefore = relayer.balance;

        // Relay the destination bridge
        vm.chainId(1); // set to dest chain
        uint256 value = 10.97e18;
        fastBridge.relay{value: value}(request);

        // Check the balances of the relayer and the user after relaying the destination bridge
        uint256 userBalanceAfter = user.balance;
        uint256 relayerBalanceAfter = relayer.balance;

        assertEq(userBalanceAfter - userBalanceBefore, value);
        assertEq(relayerBalanceBefore - relayerBalanceAfter, value);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedRelayNotDestChain() public {
        // Set up the roles for the test
        setUpRoles();

        vm.prank(owner);
        fastBridge.addRelayer(address(this));

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(42161, 0);

        // Start a prank with the relayer
        vm.startPrank(relayer);

        // Approve the fastBridge to spend the maximum amount of ethUSDC from the relayer
        ethUSDC.approve(address(fastBridge), type(uint256).max);

        // Relay the destination bridge
        vm.expectRevert(abi.encodeWithSelector(ChainIncorrect.selector));
        vm.chainId(2); // wrong dest chain id
        fastBridge.relay(request);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    // This test checks if the destination bridge has already been relayed
    function test_alreadyRelayedDestination() public {
        // First, we successfully relay the destination
        test_successfulRelayDestination();

        // Then, we set up the roles for the test
        setUpRoles();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(42161, 0);
        assertEq(fastBridge.bridgeRelays(transactionId), true);

        // We start a prank with the relayer
        vm.startPrank(relayer);
        // We expect a revert because the destination bridge has already been relayed
        vm.expectRevert(abi.encodeWithSelector(TransactionRelayed.selector));
        vm.chainId(1); // set to dest chain
        // We try to relay the destination bridge again
        fastBridge.relay(request);
        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedRelayNotRelayer() public {
        // Set up the roles for the test
        setUpRoles();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(42161, 0);

        // Start a prank with the relayer
        vm.startPrank(guard);
        // Approve the fastBridge to spend the maximum amount of ethUSDC from the relayer
        ethUSDC.approve(address(fastBridge), type(uint256).max);

        // Relay the destination bridge
        vm.expectRevert("Caller is not a relayer");
        vm.chainId(1); // set to dest chain
        fastBridge.relay(request);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    event BridgeProofProvided(bytes32 transactionId, address oldRelayer, bytes32 transactionHash);

    // This test checks the successful provision of relay proof
    function test_successfulRelayProof() public {
        // First, we successfully initiate the original bridge tx
        test_successfulBridge();

        // Then, we set up the roles for the test
        setUpRoles();

        // We start a prank with the relayer
        vm.startPrank(relayer);

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        // We define a fake transaction hash to be the proof from dest chain
        bytes32 fakeTxnHash = bytes32("0x01");
        // We expect an event to be emitted
        vm.expectEmit();
        // We emit the BridgeProofProvided event to test again
        emit BridgeProofProvided(transactionId, relayer, fakeTxnHash);

        // We provide the relay proof
        fastBridge.prove(request, fakeTxnHash);

        // We check if the bridge transaction proof timestamp is set to the timestamp at which the proof was provided
        (uint96 _timestamp, address _oldRelayer) = fastBridge.bridgeProofs(transactionId);
        assertEq(_timestamp, uint96(block.timestamp));
        assertEq(_oldRelayer, relayer);

        // We check if the bridge status is RELAYER_PROVED
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.RELAYER_PROVED));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulProveWithProofTimestampOverflow() public {
        // sets block timestamp to just before overflow of uint96
        vm.warp(uint256(type(uint96).max) + 1 minutes);

        // First, we successfully initiate the original bridge tx
        test_successfulBridge();

        // Then, we set up the roles for the test
        setUpRoles();

        // We start a prank with the relayer
        vm.startPrank(relayer);

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        // We define a fake transaction hash to be the proof from dest chain
        bytes32 fakeTxnHash = bytes32("0x01");

        // We provide the relay proof
        fastBridge.prove(request, fakeTxnHash);

        // We check if the bridge transaction proof timestamp is set to the timestamp at which the proof was provided
        (uint96 _timestamp, address _oldRelayer) = fastBridge.bridgeProofs(transactionId);
        assertEq(_timestamp, uint96(block.timestamp));
        assertEq(_oldRelayer, relayer);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedProveTimeExceeded() public {
        // First, we successfully initiate the original bridge tx
        test_successfulBridge();

        // Then, we set up the roles for the test
        setUpRoles();

        // We start a prank with the relayer
        vm.startPrank(relayer);

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        // We define a fake transaction hash to be the proof from dest chain
        bytes32 fakeTxnHash = bytes32("0x01");

        vm.warp(block.timestamp + 61 minutes);

        // We provide the relay proof
        vm.expectRevert(abi.encodeWithSelector(DeadlineExceeded.selector));
        fastBridge.prove(request, fakeTxnHash);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedProveNotRequested() public {
        // Then, we set up the roles for the test
        setUpRoles();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        // We start a prank with the relayer
        vm.startPrank(relayer);

        // We provide the relay proof
        vm.expectRevert(abi.encodeWithSelector(StatusIncorrect.selector));
        fastBridge.prove(request, bytes32("0x01"));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedProveNotRelayer() public {
        // First, we successfully initiate the original bridge tx
        test_successfulBridge();

        // Then, we set up the roles for the test
        setUpRoles();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        // We provide the relay proof
        vm.expectRevert("Caller is not a relayer");
        fastBridge.prove(request, bytes32("0x01"));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    event BridgeDepositClaimed(bytes32 transactionId, address oldRelayer, address to, address token, uint256 amount);

    function test_successfulClaimOriginTokens() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(relayer);
        fastBridge.prove(request, bytes32("0x04"));

        vm.warp(block.timestamp + 31 minutes);

        vm.expectEmit();
        emit BridgeDepositClaimed(transactionId, relayer, relayer, address(arbUSDC), 11 * 10 ** 6);

        uint256 preClaimBalanceRelayer = arbUSDC.balanceOf(relayer);
        uint256 preClaimBalanceBridge = arbUSDC.balanceOf(address(fastBridge));

        fastBridge.claim(request, relayer);

        // check balance changes
        uint256 postClaimBalanceRelayer = arbUSDC.balanceOf(relayer);
        uint256 postClaimBalanceBridge = arbUSDC.balanceOf(address(fastBridge));

        assertEq(postClaimBalanceRelayer - preClaimBalanceRelayer, 11 * 10 ** 6);
        assertEq(preClaimBalanceBridge - postClaimBalanceBridge, 11 * 10 ** 6);

        // check status changed
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.RELAYER_CLAIMED));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulClaimWithETH() public {
        setUpRoles();
        test_successfulBridgeWithETH();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndIdWithETH(block.chainid, 0);

        vm.startPrank(relayer);
        fastBridge.prove(request, bytes32("0x04"));

        vm.warp(block.timestamp + 31 minutes);

        uint256 preClaimBalanceRelayer = relayer.balance;
        uint256 preClaimBalanceBridge = address(fastBridge).balance;

        fastBridge.claim(request, relayer);

        // check balance changes
        uint256 postClaimBalanceRelayer = relayer.balance;
        uint256 postClaimBalanceBridge = address(fastBridge).balance;

        assertEq(postClaimBalanceRelayer - preClaimBalanceRelayer, 11 * 10 ** 18);
        assertEq(preClaimBalanceBridge - postClaimBalanceBridge, 11 * 10 ** 18);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulClaimWithProofTimestampOverflow() public {
        // sets block timestamp to just before overflow of uint96
        vm.warp(type(uint96).max - 1 minutes);

        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(relayer);
        fastBridge.prove(request, bytes32("0x04"));

        vm.warp(block.timestamp + 31 minutes);

        fastBridge.claim(request, relayer);

        // check status changed
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.RELAYER_CLAIMED));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedClaimNoProof() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(relayer);

        vm.warp(block.timestamp + 31 minutes);

        vm.expectRevert(abi.encodeWithSelector(StatusIncorrect.selector));
        fastBridge.claim(request, relayer);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedClaimNotoldRelayer() public {
        setUpRoles();
        test_successfulBridge();

        vm.prank(owner);
        fastBridge.addRelayer(address(this));

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.warp(block.timestamp + 31 minutes);

        vm.prank(relayer);
        fastBridge.prove(request, bytes32("0x04"));

        vm.expectRevert(abi.encodeWithSelector(SenderIncorrect.selector));
        fastBridge.claim(request, relayer);
    }

    function test_failedClaimNotEnoughTime() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(relayer);
        fastBridge.prove(request, bytes32("0x04"));

        vm.expectRevert(abi.encodeWithSelector(DisputePeriodNotPassed.selector));
        fastBridge.claim(request, relayer);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedClaimNotRelayer() public {
        setUpRoles();
        test_successfulRelayProof();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.warp(block.timestamp + 31 minutes);

        vm.expectRevert("Caller is not a relayer");
        fastBridge.claim(request, relayer);
    }

    event BridgeProofDisputed(bytes32 transactionId, address oldRelayer);

    function test_successfulDisputeProof() public {
        setUpRoles();
        test_successfulRelayProof();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(guard);

        vm.expectEmit();
        emit BridgeProofDisputed(transactionId, guard);

        fastBridge.dispute(transactionId);

        // check status and proofs updated
        (uint96 _timestamp, address _oldRelayer) = fastBridge.bridgeProofs(transactionId);
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.REQUESTED));
        assertEq(_timestamp, 0);
        assertEq(_oldRelayer, address(0));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulDisputeProofWithProofTimestampOverflow() public {
        // sets block timestamp to just before overflow of uint96
        vm.warp(type(uint96).max - 1 minutes);

        setUpRoles();
        test_successfulRelayProof();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.warp(block.timestamp + 25 minutes);

        vm.startPrank(guard);

        fastBridge.dispute(transactionId);

        // check status and proofs updated
        (uint96 _timestamp, address _oldRelayer) = fastBridge.bridgeProofs(transactionId);
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.REQUESTED));
        assertEq(_timestamp, 0);
        assertEq(_oldRelayer, address(0));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedDisputeNoProof() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(guard);

        vm.expectRevert(abi.encodeWithSelector(StatusIncorrect.selector));
        fastBridge.dispute(transactionId);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedDisputeEnoughTime() public {
        setUpRoles();
        test_successfulRelayProof();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(guard);

        vm.warp(block.timestamp + 31 minutes);

        vm.expectRevert(abi.encodeWithSelector(DisputePeriodPassed.selector));
        fastBridge.dispute(transactionId);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedDisputeNotGuard() public {
        setUpRoles();
        test_successfulRelayProof();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.expectRevert("Caller is not a guard");
        fastBridge.dispute(transactionId);
    }

    event BridgeDepositRefunded(bytes32 transactionId, address to, address token, uint256 amount);

    function test_successfulRefund() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(user);

        vm.warp(block.timestamp + 61 minutes);

        vm.expectEmit();
        emit BridgeDepositRefunded(transactionId, user, address(arbUSDC), 11 * 10 ** 6);

        uint256 preRefundBalanceUser = arbUSDC.balanceOf(user);
        uint256 preRefundBalanceBridge = arbUSDC.balanceOf(address(fastBridge));

        fastBridge.refund(request, user);

        // check balance changes
        uint256 postRefundBalanceUser = arbUSDC.balanceOf(user);
        uint256 postRefundBalanceBridge = arbUSDC.balanceOf(address(fastBridge));

        assertEq(postRefundBalanceUser - preRefundBalanceUser, 11 * 10 ** 6);
        assertEq(preRefundBalanceBridge - postRefundBalanceBridge, 11 * 10 ** 6);

        // check bridge status updated
        assertEq(uint256(fastBridge.bridgeStatuses(transactionId)), uint256(FastBridge.BridgeStatus.REFUNDED));

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_successfulRefundWithETH() public {
        setUpRoles();
        test_successfulBridgeWithETH();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndIdWithETH(block.chainid, 0);

        vm.startPrank(user);

        vm.warp(block.timestamp + 61 minutes);

        uint256 preRefundBalanceUser = user.balance;
        uint256 preRefundBalanceBridge = address(fastBridge).balance;

        fastBridge.refund(request, user);

        // check balance changes
        uint256 postRefundBalanceUser = user.balance;
        uint256 postRefundBalanceBridge = address(fastBridge).balance;

        assertEq(postRefundBalanceUser - preRefundBalanceUser, 11 * 10 ** 18);
        assertEq(preRefundBalanceBridge - postRefundBalanceBridge, 11 * 10 ** 18);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedRefundNotEnoughTime() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.startPrank(user);

        vm.warp(block.timestamp + 59 minutes);

        vm.expectRevert(abi.encodeWithSelector(DeadlineNotExceeded.selector));
        fastBridge.refund(request, user);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedRefundNotUser() public {
        setUpRoles();
        test_successfulBridge();

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.warp(block.timestamp + 61 minutes);

        vm.expectRevert(abi.encodeWithSelector(SenderIncorrect.selector));
        fastBridge.refund(request, user);

        // We stop a prank to contain within test
        vm.stopPrank();
    }

    function test_failedRefundNoBridge() public {
        setUpRoles();

        vm.startPrank(user);

        // get bridge request and tx id
        (bytes memory request, bytes32 transactionId) = _getBridgeRequestAndId(block.chainid, 0);

        vm.warp(block.timestamp + 61 minutes);

        vm.expectRevert(abi.encodeWithSelector(StatusIncorrect.selector));
        fastBridge.refund(request, user);

        // We stop a prank to contain within test
        vm.stopPrank();
    }
}