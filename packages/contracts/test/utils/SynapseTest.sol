// SPDX-License-Identifier: MIT

pragma solidity 0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../../contracts/UpdaterManager.sol";
import { HomeUpdate } from "../../contracts/libs/HomeUpdate.sol";

contract SynapseTest is Test {
    using HomeUpdate for bytes;

    uint256 updaterPK = 1;
    uint256 fakeUpdaterPK = 2;
    address updater = vm.addr(updaterPK);
    address fakeUpdater = vm.addr(fakeUpdaterPK);
    address signer = vm.addr(3);
    address fakeSigner = vm.addr(4);

    uint32 localDomain = 1500;
    uint32 remoteDomain = 1000;

    function setUp() public virtual {
        vm.label(updater, "updater");
        vm.label(fakeUpdater, "fake updater");
        vm.label(signer, "signer");
        vm.label(fakeSigner, "fake signer");
    }

    function getMessage(
        bytes32 oldRoot,
        bytes32 newRoot,
        uint32 domain
    ) public pure returns (bytes memory) {
        bytes memory message = abi.encodePacked(
            keccak256(abi.encodePacked(domain, "SYN")),
            oldRoot,
            newRoot
        );
        return message;
    }

    function signHomeUpdate(
        uint256 privKey,
        uint32 nonce,
        bytes32 root
    ) public returns (bytes memory update, bytes memory signature) {
        update = HomeUpdate.formatHomeUpdate(localDomain, nonce, root);
        bytes32 digest = keccak256(update);
        digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function signHomeUpdate(
        uint256 privKey,
        bytes32 oldRoot,
        bytes32 newRoot
    ) public returns (bytes memory) {
        bytes32 digest = keccak256(getMessage(oldRoot, newRoot, localDomain));
        digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function signRemoteUpdate(
        uint256 privKey,
        bytes32 oldRoot,
        bytes32 newRoot
    ) public returns (bytes memory) {
        bytes32 digest = keccak256(getMessage(oldRoot, newRoot, remoteDomain));
        digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

    function stringToBytes32(string memory source) public pure returns (bytes32 result) {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }
        assembly {
            result := mload(add(source, 32))
        }
    }

    function addressToBytes32(address addr) public pure returns (bytes32 result) {
        return bytes32(uint256(uint160(addr)));
    }
}

contract SynapseTestWithUpdaterManager is SynapseTest {
    UpdaterManager updaterManager;

    function setUp() public virtual override {
        super.setUp();
        updaterManager = new UpdaterManager(updater);
    }
}
