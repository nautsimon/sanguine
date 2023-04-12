// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

// ══════════════════════════════ LIBRARY IMPORTS ══════════════════════════════
import {AgentFlag, AgentStatus} from "./libs/Structures.sol";
// ═════════════════════════════ INTERNAL IMPORTS ══════════════════════════════
import {AgentManager} from "./manager/AgentManager.sol";
import {DomainContext} from "./context/DomainContext.sol";
import {SummitEvents} from "./events/SummitEvents.sol";
import {IAgentManager} from "./interfaces/IAgentManager.sol";
import {InterfaceSummit} from "./interfaces/InterfaceSummit.sol";
import {DisputeHub, ExecutionHub, MessageStatus, Receipt, Tips} from "./hubs/ExecutionHub.sol";
import {SnapshotHub, SummitAttestation, SummitState} from "./hubs/SnapshotHub.sol";
import {Attestation, AttestationLib, AttestationReport, Snapshot} from "./hubs/StatementHub.sol";
import {DomainContext, Versioned} from "./system/SystemContract.sol";
import {SystemRegistry} from "./system/SystemRegistry.sol";
// ═════════════════════════════ EXTERNAL IMPORTS ══════════════════════════════
import {DoubleEndedQueue} from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";

contract Summit is ExecutionHub, SnapshotHub, SummitEvents, InterfaceSummit {
    using AttestationLib for bytes;
    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;

    // TODO: write docs, pack values
    struct ReceiptInfo {
        uint32 origin;
        uint32 destination;
        uint32 snapRootIndex;
        uint32 attNotaryIndex;
        address firstExecutor;
        address finalExecutor;
    }

    struct ReceiptStatus {
        MessageStatus status;
        bool pending;
        bool tipsAwarded;
        uint32 receiptNotaryIndex;
        uint40 submittedAt;
    }

    struct ReceiptTips {
        uint64 summitTip;
        uint64 attestationTip;
        uint64 executionTip;
        uint64 deliveryTip;
    }

    struct ActorTips {
        uint128 earned;
        uint128 claimed;
    }

    // ══════════════════════════════════════════════════ STORAGE ══════════════════════════════════════════════════════

    // (message hash => receipt data)
    mapping(bytes32 => ReceiptInfo) private _receiptInfo;

    // (message hash => receipt status)
    mapping(bytes32 => ReceiptStatus) private _receiptStatus;

    // (message hash => receipt tips)
    mapping(bytes32 => ReceiptTips) private _receiptTips;

    // Quarantine queue for message hashes
    DoubleEndedQueue.Bytes32Deque private _receiptQueue;

    /// @inheritdoc InterfaceSummit
    mapping(address => ActorTips) public actorTips;

    // ═════════════════════════════════════════ CONSTRUCTOR & INITIALIZER ═════════════════════════════════════════════

    constructor(uint32 domain, IAgentManager agentManager_)
        DomainContext(domain)
        SystemRegistry(agentManager_)
        Versioned("0.0.3")
    {
        require(_onSynapseChain(), "Only deployed on SynChain");
    }

    function initialize() external initializer {
        // Initialize Ownable: msg.sender is set as "owner"
        __Ownable_init();
        _initializeAttestations();
    }

    // ═════════════════════════════════════════════ ACCEPT STATEMENTS ═════════════════════════════════════════════════

    /// @inheritdoc InterfaceSummit
    function submitReceipt(bytes memory rcptPayload, bytes memory rcptSignature) external returns (bool wasAccepted) {
        // Call the hook and check if we can accept the statement
        if (!_beforeStatement()) return false;
        // This will revert if payload is not an receipt
        Receipt rcpt = _wrapReceipt(rcptPayload);
        // This will revert if the attestation signer is not a known Notary
        (AgentStatus memory status, address notary) = _verifyReceipt(rcpt, rcptSignature);
        // Notary needs to be Active and not in Dispute
        _verifyActive(status);
        require(!_inDispute(notary), "Notary is in dispute");
        // Receipt needs to be signed by a destination chain Notary
        require(rcpt.destination() == status.domain, "Wrong Notary domain");
        wasAccepted = _saveReceipt(rcpt, status.index);
        if (wasAccepted) {
            emit ReceiptAccepted(status.domain, notary, rcptPayload, rcptSignature);
        }
    }

    /// @inheritdoc InterfaceSummit
    function submitSnapshot(bytes memory snapPayload, bytes memory snapSignature)
        external
        returns (bytes memory attPayload)
    {
        // Call the hook and check if we can accept the statement
        if (!_beforeStatement()) return "";
        // This will revert if payload is not a snapshot
        Snapshot snapshot = _wrapSnapshot(snapPayload);
        // This will revert if the signer is not a known Agent
        (AgentStatus memory status, address agent) = _verifySnapshot(snapshot, snapSignature);
        // Check that Agent is active
        _verifyActive(status);
        if (status.domain == 0) {
            /// @dev We don't check if Guard is in dispute for accepting the snapshots.
            /// Guard could only be in Dispute, if they submitted a Report on a Notary.
            /// This should not strip away their ability to post snapshots, as they require
            /// a Notary signature in order to be used / gain tips anyway.

            // This will revert if Guard has previously submitted
            // a fresher state than one in the snapshot.
            _acceptGuardSnapshot(snapshot, agent);
        } else {
            // Check that Notary who submitted the snapshot is not in dispute
            require(!_inDispute(agent), "Notary is in dispute");
            // Fetch current Agent Root from BondingManager
            bytes32 agentRoot = agentManager.agentRoot();
            // This will revert if any of the states from the Notary snapshot
            // haven't been submitted by any of the Guards before.
            attPayload = _acceptNotarySnapshot(snapshot, agentRoot, agent);
            // Save attestation derived from Notary snapshot
            _saveAttestation(attPayload.castToAttestation(), agent);
        }
        emit SnapshotAccepted(status.domain, agent, snapPayload, snapSignature);
    }

    // ═════════════════════════════════════════════ VERIFY STATEMENTS ═════════════════════════════════════════════════

    /// @inheritdoc InterfaceSummit
    function verifyAttestation(bytes memory attPayload, bytes memory attSignature) external returns (bool isValid) {
        // This will revert if payload is not an attestation
        Attestation att = _wrapAttestation(attPayload);
        // This will revert if the attestation signer is not a known Notary
        (AgentStatus memory status, address notary) = _verifyAttestation(att, attSignature);
        // Notary needs to be Active/Unstaking
        _verifyActiveUnstaking(status);
        isValid = _isValidAttestation(att);
        if (!isValid) {
            emit InvalidAttestation(attPayload, attSignature);
            // Slash Notary and notify local AgentManager
            _slashAgent(status.domain, notary);
        }
    }

    /// @inheritdoc InterfaceSummit
    function verifyAttestationReport(bytes memory arPayload, bytes memory arSignature)
        external
        returns (bool isValid)
    {
        // This will revert if payload is not an attestation report
        AttestationReport report = _wrapAttestationReport(arPayload);
        // This will revert if the report signer is not a known Guard
        (AgentStatus memory status, address guard) = _verifyAttestationReport(report, arSignature);
        // Guard needs to be Active/Unstaking
        _verifyActiveUnstaking(status);
        // Report is valid, if the reported attestation is invalid
        isValid = !_isValidAttestation(report.attestation());
        if (!isValid) {
            emit InvalidAttestationReport(arPayload, arSignature);
            // Slash Guard and notify local AgentManager
            _slashAgent(0, guard);
        }
    }

    function distributeTips() public returns (bool queuePopped) {
        // Check message that is first in the "quarantine queue"
        if (_receiptQueue.empty()) return false;
        bytes32 messageHash = _receiptQueue.front();
        ReceiptStatus memory rcptStatus = _receiptStatus[messageHash];
        // Check if optimistic period for the receipt is over
        if (block.timestamp < uint256(rcptStatus.submittedAt) + BONDING_OPTIMISTIC_PERIOD) return false;
        // Fetch Notary who signed the receipt. If they are Slashed or in Dispute, exit early.
        (address rcptNotary, AgentStatus memory rcptNotaryStatus) = _getAgent(rcptStatus.receiptNotaryIndex);
        if (_checkNotaryDisputed(messageHash, rcptNotary, rcptNotaryStatus)) return true;
        ReceiptInfo memory rcptInfo = _receiptInfo[messageHash];
        // Fetch Notary who signed the statement with snapshot root. If they are Slashed or in Dispute, exit early.
        (address attNotary, AgentStatus memory attNotaryStatus) = _getAgent(rcptInfo.attNotaryIndex);
        if (_checkNotaryDisputed(messageHash, attNotary, attNotaryStatus)) return true;
        // At this point Receipt is optimistically verified to be correct, as well as the receipt's attestation
        // Meaning we can go ahead and distribute the tip values among the tipped actors.
        _awardTips(rcptNotary, attNotary, messageHash, rcptInfo, rcptStatus);
        // Save new receipt status
        rcptStatus.pending = false;
        rcptStatus.tipsAwarded = true;
        _receiptStatus[messageHash] = rcptStatus;
        // Remove the receipt from the queue
        _receiptQueue.popFront();
        return true;
    }

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    /// @inheritdoc InterfaceSummit
    // solhint-disable-next-line ordering
    function receiptQueueLength() external view returns (uint256) {
        return _receiptQueue.length();
    }

    /// @inheritdoc InterfaceSummit
    function getLatestState(uint32 origin) external view returns (bytes memory statePayload) {
        // TODO: implement once Agent Merkle Tree is done
    }

    // ═══════════════════════════════════════════ INTERNAL LOGIC: QUEUE ═══════════════════════════════════════════════

    /// @dev Checks if the given Notary has been disputed.
    /// - Notary was slashed => receipt is invalided and deleted
    /// - Notary is in Dispute => receipt handling is postponed
    function _checkNotaryDisputed(bytes32 messageHash, address notary, AgentStatus memory status)
        internal
        returns (bool queuePopped)
    {
        if (status.flag == AgentFlag.Fraudulent || status.flag == AgentFlag.Slashed) {
            // Notary has been slashed, so we can't trust their statement.
            // Honest Notaries are incentivized to resubmit the Receipt or Attestation if it was in fact valid.
            _deleteFromQueue(messageHash);
            return true;
        }
        if (_inDispute(notary)) {
            // Notary is not slashed, but is in Dispute. To keep the tips flow going we add the receipt to the back of
            // the queue, hoping that by the next interaction the dispute will have been resolved.
            _moveToBack();
            return true;
        }
    }

    /// @dev Deletes all stored receipt data and removes it from the queue.
    function _deleteFromQueue(bytes32 messageHash) internal {
        delete _receiptInfo[messageHash];
        delete _receiptStatus[messageHash];
        delete _receiptTips[messageHash];
        _receiptQueue.popFront();
    }

    /// @dev Moves the front element of the queue to its back.
    function _moveToBack() internal {
        bytes32 popped = _receiptQueue.popFront();
        _receiptQueue.pushBack(popped);
    }

    /// @dev Saves the message from the receipt into the "quarantine queue". Once message leaves the queue,
    /// tips associated with the message are distributed across off-chain actors.
    function _saveReceipt(Receipt receipt, uint32 rcptNotaryIndex) internal returns (bool) {
        bytes32 snapRoot = receipt.snapshotRoot();
        SnapRootData memory rootData = _rootData[snapRoot];
        require(rootData.submittedAt != 0, "Unknown snapshot root");
        // Attestation Notary needs to be known and not slashed
        address attNotary = receipt.attNotary();
        AgentStatus memory attNotaryStatus = _agentStatus(attNotary);
        _verifyKnown(attNotaryStatus);
        _verifyNotSlashed(attNotaryStatus);
        // Check if tip values are non-zero
        Tips tips = receipt.tips();
        if (tips.value() == 0) return false;
        // Check if there already exists receipt for the message
        bytes32 messageHash = receipt.messageHash();
        ReceiptStatus memory savedRcpt = _receiptStatus[messageHash];
        // Don't save if receipt is already in the queue
        if (savedRcpt.pending) return false;
        // Get the status from the provided receipt
        MessageStatus msgStatus = receipt.finalExecutor() == address(0) ? MessageStatus.Failed : MessageStatus.Success;
        // Don't save if we already have the receipt with at least this status
        if (savedRcpt.status >= msgStatus) return false;
        // Save information from the receipt
        _receiptInfo[messageHash] = ReceiptInfo({
            origin: receipt.origin(),
            destination: receipt.destination(),
            snapRootIndex: rootData.index,
            attNotaryIndex: attNotaryStatus.index,
            firstExecutor: receipt.firstExecutor(),
            finalExecutor: receipt.finalExecutor()
        });
        // Save receipt status: transfer tipsAwarded field (whether we paid tips for Failed Receipt before)
        _receiptStatus[messageHash] = ReceiptStatus({
            status: msgStatus,
            pending: true,
            tipsAwarded: savedRcpt.tipsAwarded,
            receiptNotaryIndex: rcptNotaryIndex,
            submittedAt: uint40(block.timestamp)
        });
        // Save receipt tips
        _receiptTips[messageHash] = ReceiptTips({
            summitTip: tips.summitTip(),
            attestationTip: tips.attestationTip(),
            executionTip: tips.executionTip(),
            deliveryTip: tips.deliveryTip()
        });
        // Add message hash to the quarantine queue
        _receiptQueue.pushBack(messageHash);
        return true;
    }

    // ══════════════════════════════════════ INTERNAL LOGIC: TIPS ACCOUNTING ══════════════════════════════════════════

    /// @dev Awards tips to the agent/actors that participated in message lifecycle
    function _awardTips(
        address rcptNotary,
        address attNotary,
        bytes32 messageHash,
        ReceiptInfo memory rcptInfo,
        ReceiptStatus memory rcptStatus
    ) internal {
        ReceiptTips memory tips = _receiptTips[messageHash];
        // Check if we awarded tips for this message earlier
        bool awardFirst = !rcptStatus.tipsAwarded;
        // Check if this is the final tips distribution
        bool awardFinal = rcptStatus.status == MessageStatus.Success;
        if (awardFirst) {
            // There has been a valid attempt to execute the message
            _awardSnapshotTip(_roots[rcptInfo.snapRootIndex], tips.summitTip);
            _awardAgentTip(attNotary, tips.attestationTip);
            _awardActorTip(rcptInfo.firstExecutor, tips.executionTip);
        }
        _awardReceiptTip(rcptNotary, awardFirst, awardFinal, tips.summitTip);
        if (awardFinal) {
            // Message has been executed successfully
            _awardActorTip(rcptInfo.finalExecutor, tips.deliveryTip);
        }
    }

    /// @dev Award tip to the bonded agent
    function _awardAgentTip(address agent, uint64 tip) internal {
        // If agent has been slashed, their earned tips go to treasury
        _awardActorTip(_isSlashed(agent) ? address(0) : agent, tip);
    }

    /// @dev Award tip to any actor whether bonded or unbonded
    function _awardActorTip(address actor, uint64 tip) internal {
        actorTips[actor].earned += tip;
        emit TipAwarded(actor, tip);
    }

    /// @dev Award tip for posting Receipt to Summit contract.
    function _awardReceiptTip(address rcptNotary, bool awardFirst, bool awardFinal, uint64 summitTip) internal {
        uint64 receiptTip = _receiptTip(summitTip);
        // Tip for posting Receipt with status >= MessageStatus.Failed
        uint64 receiptTipFirst = receiptTip / 2;
        // Tip for posting Receipt with status == MessageStatus.Success
        uint64 receiptTipFinal = receiptTip - receiptTipFirst;
        _awardAgentTip(rcptNotary, (awardFirst ? receiptTipFirst : 0) + (awardFinal ? receiptTipFinal : 0));
    }

    /// @dev Award tip for posting Snapshot to Summit contract.
    function _awardSnapshotTip(bytes32 snapRoot, uint64 summitTip) internal {
        uint64 snapshotTip = _snapshotTip(summitTip);
        // TODO: get the addresses
        snapRoot;
        address snapGuard;
        address snapNotary;
        _awardAgentTip(snapGuard, snapshotTip);
        _awardAgentTip(snapNotary, snapshotTip);
    }

    // ══════════════════════════════════════════════ INTERNAL VIEWS ═══════════════════════════════════════════════════

    /// @inheritdoc DisputeHub
    function _beforeStatement() internal pure override returns (bool acceptNext) {
        // Summit is always open for new Guard/Notary statements
        return true;
    }

    /// @dev Returns "snapshot part" of the summit tip.
    function _snapshotTip(uint64 summitTip) internal pure returns (uint64) {
        return summitTip / 3;
    }

    /// @dev Returns "receipt part" of the summit tip.
    function _receiptTip(uint64 summitTip) internal pure returns (uint64) {
        return summitTip - 2 * _snapshotTip(summitTip);
    }
}
