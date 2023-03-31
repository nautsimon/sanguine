// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { ATTESTATION_LENGTH } from "../../../contracts/libs/Constants.sol";

import { SynapseLibraryTest, TypedMemView } from "../../utils/SynapseLibraryTest.t.sol";
import {
    AttestationHarness,
    ExecutionAttestation,
    SummitAttestation,
    TypedMemView
} from "../../harnesses/libs/AttestationHarness.t.sol";

import { RawAttestation } from "../../utils/libs/SynapseStructs.t.sol";

// solhint-disable func-name-mixedcase
contract AttestationLibraryTest is SynapseLibraryTest {
    using TypedMemView for bytes;

    AttestationHarness internal libHarness;

    function setUp() public override {
        libHarness = new AttestationHarness();
    }

    function test_formatAttestation(RawAttestation memory ra) public {
        bytes memory payload = libHarness.formatAttestation(
            ra.snapRoot,
            ra.agentRoot,
            ra.nonce,
            ra.blockNumber,
            ra.timestamp
        );
        // Test formatting of state
        assertEq(
            payload,
            abi.encodePacked(ra.snapRoot, ra.agentRoot, ra.nonce, ra.blockNumber, ra.timestamp),
            "!formatAttestation"
        );
        checkCastToAttestation({ payload: payload, isAttestation: true });
        // Test getters
        assertEq(libHarness.snapRoot(payload), ra.snapRoot, "!snapRoot");
        assertEq(libHarness.agentRoot(payload), ra.agentRoot, "!agentRoot");
        assertEq(libHarness.nonce(payload), ra.nonce, "!nonce");
        assertEq(libHarness.blockNumber(payload), ra.blockNumber, "!blockNumber");
        assertEq(libHarness.timestamp(payload), ra.timestamp, "!timestamp");
        // Test hashing
        bytes32 attestationSalt = keccak256("ATTESTATION_SALT");
        bytes32 hashedAttestation = keccak256(
            abi.encodePacked(attestationSalt, keccak256(payload))
        );
        assertEq(libHarness.hash(payload), hashedAttestation, "!hash");
    }

    function test_isAttestation(uint8 length) public {
        bytes memory payload = new bytes(length);
        checkCastToAttestation({ payload: payload, isAttestation: length == ATTESTATION_LENGTH });
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                       DESTINATION ATTESTATION                        ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function test_toExecutionAttestation(
        RawAttestation memory ra,
        address notary,
        uint40 submittedAt
    ) public {
        vm.warp(submittedAt);
        bytes memory payload = ra.formatAttestation();
        ExecutionAttestation memory execAtt = libHarness.toExecutionAttestation(payload, notary);
        assertEq(execAtt.notary, notary, "!notary");
        assertEq(execAtt.nonce, ra.nonce, "!nonce");
        assertEq(execAtt.submittedAt, submittedAt, "!submittedAt");
    }

    function test_isEmpty(ExecutionAttestation memory execAtt) public {
        if (execAtt.notary == address(0)) {
            assertTrue(libHarness.isEmpty(execAtt), "!isEmpty: when Empty");
        } else {
            assertFalse(libHarness.isEmpty(execAtt), "!isEmpty: when non-Empty");
        }
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                          SUMMIT ATTESTATION                          ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function test_formatSummitAttestation(RawAttestation memory ra) public {
        SummitAttestation memory att = SummitAttestation(
            ra.snapRoot,
            ra.agentRoot,
            ra.blockNumber,
            ra.timestamp
        );
        bytes memory payload = libHarness.formatSummitAttestation(att, ra.nonce);
        assertEq(
            payload,
            libHarness.formatAttestation(
                ra.snapRoot,
                ra.agentRoot,
                ra.nonce,
                ra.blockNumber,
                ra.timestamp
            ),
            "!formatSummitAttestation"
        );
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                               HELPEra                                ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function checkCastToAttestation(bytes memory payload, bool isAttestation) public {
        if (isAttestation) {
            assertTrue(libHarness.isAttestation(payload), "!isAttestation: when valid");
            assertEq(
                libHarness.castToAttestation(payload),
                payload,
                "!castToAttestation: when valid"
            );
        } else {
            assertFalse(libHarness.isAttestation(payload), "!isAttestation: when valid");
            vm.expectRevert("Not an attestation");
            libHarness.castToAttestation(payload);
        }
    }
}
