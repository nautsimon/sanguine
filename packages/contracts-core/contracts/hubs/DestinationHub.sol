// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import { Attestation } from "../libs/Attestation.sol";
import { AttestationHub } from "./AttestationHub.sol";
import { DestinationHubEvents } from "../events/DestinationHubEvents.sol";
import { Report } from "../libs/Report.sol";
import { ReportHub } from "./ReportHub.sol";
import { DomainContext } from "../context/DomainContext.sol";
import { GlobalNotaryRegistry } from "../registry/GlobalNotaryRegistry.sol";
import { GuardRegistry } from "../registry/GuardRegistry.sol";

import { TypedMemView } from "../libs/TypedMemView.sol";

/**
 * @notice Keeps track of remote Origins by storing each Origin
 * merkle state in a separate Mirror.
 */
abstract contract DestinationHub is
    DestinationHubEvents,
    DomainContext,
    AttestationHub,
    ReportHub,
    GlobalNotaryRegistry,
    GuardRegistry
{
    using Attestation for bytes29;
    using Report for bytes29;
    using TypedMemView for bytes29;

    /**
     * @notice Information stored for every submitted merkle root.
     * Optimized to fit into one word of storage.
     * @param notary		Notary who submitted the root
     * @param submittedAt	Timestamp when root was submitted
     */
    struct Root {
        address notary;
        uint96 submittedAt;
    }

    /**
     * @notice Information stored for every remote Origin.
     * TODO: finalize structure
     * @param latestNonce	Nonce of last submitted attestation
     * @param latestNotary	Notary who signed last submitted attestation
     */
    struct Mirror {
        uint32 latestNonce;
        address latestNotary;
        // 64 bits remaining
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                               STORAGE                                ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    // domain => [root => info]
    mapping(uint32 => mapping(bytes32 => Root)) public mirrorRoots;

    // domain => mirror
    mapping(uint32 => Mirror) public mirrors;

    // gap for upgrade safety
    uint256[48] private __GAP; // solhint-disable-line var-name-mixedcase

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                                VIEWS                                 ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function submittedAt(uint32 _originDomain, bytes32 _root) external view returns (uint96) {
        return mirrorRoots[_originDomain][_root].submittedAt;
    }

    /**
     * @notice Check that the root has been submitted
     * and that the root's optimistic timeout period has expired,
     * meaning message proven against the root can be executed.
     * @dev This will revert if any of the checks fail.
     * @param _originDomain         Domain of Origin
     * @param _optimisticSeconds    Optimistic period for a message
     * @param _root                 The Merkle root from Origin to check
     * @return TRUE if following requirements are fulfilled:
     * - Root was submitted
     * - Notary who signed the root wasn't blacklisted
     * - Optimistic period has passed
     */
    function acceptableRoot(
        uint32 _originDomain,
        uint32 _optimisticSeconds,
        bytes32 _root
    ) public view returns (bool) {
        Root memory rootInfo = mirrorRoots[_originDomain][_root];
        // Check if root has been submitted
        require(rootInfo.submittedAt != 0, "Invalid root");
        // Check if Notary is an active Notary
        require(_isNotary(_originDomain, rootInfo.notary), "Inactive notary");
        // Check if optimistic period has passed
        require(block.timestamp >= rootInfo.submittedAt + _optimisticSeconds, "!optimisticSeconds");
        return true;
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                          INTERNAL FUNCTIONS                          ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    /**
     * @notice Called by external agent. Submits the signed attestation,
     * updates Mirror state for the attested origin, and emits an `AttestationAccepted` event.
     *
     * @dev Notary role and signature have been checked (see ReportHub.sol),
     * meaning `_notary` is an active Notary at this point.
     *
     * @param _notary           Notary address
     * @param _attestationView  Memory view over attestation
     * @return TRUE if Attestation was accepted (implying a new root was added to Mirror).
     */
    function _handleAttestation(
        address _notary,
        bytes29 _attestationView,
        bytes memory
    ) internal override returns (bool) {
        uint32 originDomain = _attestationView.attestedDomain();
        require(originDomain != _localDomain(), "Attestation is from local chain");
        bytes32 root = _attestationView.attestedRoot();
        require(root != bytes32(0), "Empty root");
        uint32 nonce = _attestationView.attestedNonce();
        _updateMirror(_notary, originDomain, nonce, root);
        emit AttestationAccepted(
            originDomain,
            nonce,
            root,
            _attestationView.notarySignature().clone()
        );
        return true;
    }

    /**
     * @notice Applies submitted Report to blacklist reported Notary,
     * and all roots signed by this Notary. An honest Notary is incentivized to sign
     * a valid Attestation to collect tips from the pending messages,
     * which prevents downtime caused by root blacklisting.
     *
     * @dev Notary and Guard roles and signatures have been checked (see ReportHub.sol),
     * meaning `_guard` and `_notary` are an active Guard and Notary respectively at this point.
     *
     * @param _guard            Guard address
     * @param _notary           Notary address
     * @param _attestationView  Memory view over reported Attestation
     * @param _reportView       Memory view over Report
     * @param _report           Payload with Report data and signature
     * @return TRUE if Notary was blacklisted as a result
     */
    function _handleReport(
        address _guard,
        address _notary,
        bytes29 _attestationView,
        bytes29 _reportView,
        bytes memory _report
    ) internal override returns (bool) {
        require(_reportView.reportedFraud(), "Not a fraud report");
        _blacklistNotary(_attestationView.attestedDomain(), _notary, _guard, _report);
        return true;
    }

    function _updateMirror(
        address _notary,
        uint32 _originDomain,
        uint32 _nonce,
        bytes32 _root
    ) internal {
        Mirror storage mirror = mirrors[_originDomain];
        // New Attestation is accepted either if the nonce increased,
        // or the latest attestation was signed by an inactive notary.
        require(
            _nonce > mirror.latestNonce || !_isNotary(_originDomain, _notary),
            "Outdated attestation"
        );
        (mirror.latestNonce, mirror.latestNotary) = (_nonce, _notary);
        mirrorRoots[_originDomain][_root] = Root({
            notary: _notary,
            submittedAt: uint96(block.timestamp)
        });
    }

    /**
     * @notice Child contracts should implement the blacklisting logic.
     * @dev _notary is always an active Notary, _guard is always an active Guard.
     * @param _domain   Origin domain where fraud was allegedly committed by Notary
     * @param _notary   Notary address who allegedly committed fraud attestation
     * @param _guard    Guard address that reported the Notary
     * @param _report   Payload with Report data and signature
     */
    function _blacklistNotary(
        uint32 _domain,
        address _notary,
        address _guard,
        bytes memory _report
    ) internal virtual;
}
