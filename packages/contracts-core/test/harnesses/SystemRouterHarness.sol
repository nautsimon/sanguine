// SPDX-License-Identifier: MIT

pragma solidity 0.8.13;

import { SystemRouter } from "../../contracts/system/SystemRouter.sol";

contract SystemRouterHarness is SystemRouter {
    constructor(
        uint32 _localDomain,
        address _origin,
        address _destination
    ) SystemRouter(_localDomain, _origin, _destination) {}
}
