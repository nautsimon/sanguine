// SPDX-License-Identifier: MIT

pragma solidity 0.8.17;

import { Client } from "../../../contracts/client/Client.sol";
import { ClientHarnessEvents } from "../events/ClientHarnessEvents.sol";

contract ClientHarness is ClientHarnessEvents, Client {
    uint32 internal optimisticPeriod;

    // solhint-disable-next-line no-empty-blocks
    constructor(
        address _origin,
        address _destination,
        uint32 _optimisticPeriod
    ) Client(_origin, _destination) {
        optimisticPeriod = _optimisticPeriod;
    }

    /// @notice Prevents this contract from being included in the coverage report
    function testClientHarness() external {}

    function sendMessage(
        uint32 _destination,
        bytes memory _tips,
        bytes memory _message
    ) public payable {
        _send(_destination, _tips, _message);
    }

    function optimisticSeconds() public view override returns (uint32) {
        return optimisticPeriod;
    }

    function trustedSender(uint32 _destination) public pure override returns (bytes32 sender) {
        sender = bytes32(uint256(_destination));
        // bytes32(0) for _destination == 0
    }

    function _handle(
        uint32 _origin,
        uint32 _nonce,
        bytes memory _message
    ) internal override {
        emit LogClientMessage(_origin, _nonce, _message);
    }
}
