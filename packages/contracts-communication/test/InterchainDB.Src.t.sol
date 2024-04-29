// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {
    InterchainDB,
    InterchainBatch,
    InterchainEntry,
    InterchainEntryLib,
    IInterchainDB,
    InterchainDBEvents,
    BatchingV1Lib
} from "../contracts/InterchainDB.sol";

import {InterchainBatchLibHarness} from "./harnesses/InterchainBatchLibHarness.sol";
import {VersionedPayloadLibHarness} from "./harnesses/VersionedPayloadLibHarness.sol";
import {InterchainModuleMock, IInterchainModule} from "./mocks/InterchainModuleMock.sol";

import {Test} from "forge-std/Test.sol";

// solhint-disable custom-errors
// solhint-disable func-name-mixedcase
// solhint-disable ordering
/// @notice Unit tests for InterchainDB interactions on the source chain
/// Note: we inherit from interface with the events to avoid their copy-pasting.
contract InterchainDBSourceTest is Test, InterchainDBEvents {
    uint64 public constant SRC_CHAIN_ID = 1337;
    uint64 public constant DST_CHAIN_ID = 7331;

    uint16 public constant DB_VERSION = 1;

    uint64 public constant INITIAL_WRITER_F = 1;
    uint64 public constant INITIAL_WRITER_S = 2;
    uint64 public constant INITIAL_DB_NONCE = INITIAL_WRITER_F + INITIAL_WRITER_S;

    uint256 public constant MODULE_A_FEE = 100;
    uint256 public constant MODULE_B_FEE = 200;

    InterchainBatchLibHarness public batchLibHarness;
    VersionedPayloadLibHarness public payloadLibHarness;

    InterchainDB public icDB;
    InterchainModuleMock public moduleA;
    InterchainModuleMock public moduleB;

    InterchainEntry[] public initialEntries;

    address[] public oneModule;
    address[] public twoModules;

    address public requestCaller = makeAddr("Request Caller");
    address public writerF = makeAddr("First Writer");
    address public writerS = makeAddr("Second Writer");
    address public notWriter = makeAddr("Not a Writer");

    function setUp() public {
        vm.chainId(SRC_CHAIN_ID);
        icDB = new InterchainDB();
        moduleA = new InterchainModuleMock();
        moduleB = new InterchainModuleMock();
        batchLibHarness = new InterchainBatchLibHarness();
        payloadLibHarness = new VersionedPayloadLibHarness();
        oneModule.push(address(moduleA));
        twoModules.push(address(moduleA));
        twoModules.push(address(moduleB));
        initialWrites();
        mockModuleFee(moduleA, MODULE_A_FEE);
        mockModuleFee(moduleB, MODULE_B_FEE);
    }

    function initialWrites() internal {
        for (uint64 i = 0; i < INITIAL_WRITER_F; ++i) {
            InterchainEntry memory entry = getMockEntry(i, writerF);
            writeEntry(writerF, entry.dataHash);
            initialEntries.push(entry);
        }
        for (uint64 i = 0; i < INITIAL_WRITER_S; ++i) {
            InterchainEntry memory entry = getMockEntry(INITIAL_WRITER_F + i, writerS);
            writeEntry(writerS, entry.dataHash);
            initialEntries.push(entry);
        }
    }

    function getInitialEntry(uint64 dbNonce) internal view returns (InterchainEntry memory) {
        require(dbNonce < initialEntries.length, "dbNonce out of range");
        return initialEntries[dbNonce];
    }

    function getMockDataHash(address writer, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(writer, nonce));
    }

    function getMockEntry(uint64 dbNonce, address writer) internal pure returns (InterchainEntry memory entry) {
        return InterchainEntry({
            srcChainId: SRC_CHAIN_ID,
            dbNonce: dbNonce,
            // TODO: entryIndex
            entryIndex: 0,
            srcWriter: addressToBytes32(writer),
            dataHash: getMockDataHash(writer, dbNonce)
        });
    }

    function getModuleCalldata(InterchainEntry memory entry) internal view returns (bytes memory) {
        bytes32 batchRoot = keccak256(abi.encode(entry.srcWriter, entry.dataHash));
        bytes memory versionedBatch = payloadLibHarness.encodeVersionedPayload(
            DB_VERSION,
            batchLibHarness.encodeBatch(
                InterchainBatch({srcChainId: entry.srcChainId, dbNonce: entry.dbNonce, batchRoot: batchRoot})
            )
        );
        return abi.encodeCall(IInterchainModule.requestBatchVerification, (DST_CHAIN_ID, versionedBatch));
    }

    function addressToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    /// @dev Mocks a return value of module.getModuleFee(DST_CHAIN_ID, *)
    function mockModuleFee(InterchainModuleMock module, uint256 feeValue) internal {
        // Encode partial calldata so that we can mock the return value for any dbNonce
        bytes memory callData = abi.encodeWithSelector(module.getModuleFee.selector, DST_CHAIN_ID);
        bytes memory returnData = abi.encode(feeValue);
        vm.mockCall(address(module), callData, returnData);
    }

    function writeEntry(address writer, bytes32 dataHash) internal returns (uint64 dbNonce) {
        vm.prank(writer);
        (dbNonce,) = icDB.writeEntry(dataHash);
    }

    function requestVerification(address caller, uint256 msgValue, uint64 dbNonce, address[] memory modules) internal {
        deal(caller, msgValue);
        vm.prank(caller);
        icDB.requestBatchVerification{value: msgValue}(DST_CHAIN_ID, dbNonce, modules);
    }

    function writeEntryWithVerification(
        uint256 msgValue,
        address writer,
        bytes32 dataHash,
        address[] memory modules
    )
        internal
        returns (uint64 dbNonce)
    {
        deal(writer, msgValue);
        vm.prank(writer);
        (dbNonce,) = icDB.writeEntryWithVerification{value: msgValue}(DST_CHAIN_ID, dataHash, modules);
    }

    // ═══════════════════════════════════════════════ TEST HELPERS ════════════════════════════════════════════════════

    function assertCorrectValue(bytes32 entryValue, InterchainEntry memory expected) internal {
        bytes32 expectedValue = keccak256(abi.encode(expected.srcWriter, expected.dataHash));
        assertEq(entryValue, expectedValue, "!entryValue");
    }

    function expectEventInterchainEntryWritten(InterchainEntry memory entry) internal {
        vm.expectEmit(address(icDB));
        emit InterchainEntryWritten({
            dbNonce: entry.dbNonce,
            entryIndex: entry.entryIndex,
            srcWriter: entry.srcWriter,
            dataHash: entry.dataHash
        });
        // In the V1 of InterchainDB, the batch is finalized immediately after writing an entry
        vm.expectEmit(address(icDB));
        emit InterchainBatchFinalized({dbNonce: entry.dbNonce, batchRoot: entry.entryValue()});
    }

    function expectEventVerificationRequested(InterchainEntry memory entry, address[] memory srcModules) internal {
        bytes32 batchRoot = InterchainEntryLib.entryValue(entry);
        vm.expectEmit(address(icDB));
        emit InterchainBatchVerificationRequested(DST_CHAIN_ID, entry.dbNonce, batchRoot, srcModules);
    }

    function expectRevertBatchDoesNotExist(uint64 dbNonce) internal {
        vm.expectRevert(abi.encodeWithSelector(IInterchainDB.InterchainDB__BatchDoesNotExist.selector, dbNonce));
    }

    function expectRevertBatchNotFinalized(uint64 dbNonce) internal {
        vm.expectRevert(abi.encodeWithSelector(IInterchainDB.InterchainDB__BatchNotFinalized.selector, dbNonce));
    }

    function expectRevertEntryIndexOutOfRange(uint64 dbNonce, uint64 entryIndex, uint64 batchSize) internal {
        vm.expectRevert(
            abi.encodeWithSelector(
                IInterchainDB.InterchainDB__EntryIndexOutOfRange.selector, dbNonce, entryIndex, batchSize
            )
        );
    }

    function expectRevertIncorrectEntryIndex(uint64 entryIndex) internal {
        vm.expectRevert(abi.encodeWithSelector(BatchingV1Lib.BatchingV1__IncorrectEntryIndex.selector, entryIndex));
    }

    function expectRevertIncorrectFeeAmount(uint256 actualFee, uint256 expectedFee) internal {
        vm.expectRevert(
            abi.encodeWithSelector(IInterchainDB.InterchainDB__IncorrectFeeAmount.selector, actualFee, expectedFee)
        );
    }

    function expectRevertIncorrectProof() internal {
        vm.expectRevert(BatchingV1Lib.BatchingV1__IncorrectProof.selector);
    }

    function expectRevertInvalidEntryRange(uint64 dbNonce, uint64 start, uint64 end) internal {
        vm.expectRevert(
            abi.encodeWithSelector(IInterchainDB.InterchainDB__InvalidEntryRange.selector, dbNonce, start, end)
        );
    }

    function expectRevertNoModulesSpecified() internal {
        vm.expectRevert(IInterchainDB.InterchainDB__NoModulesSpecified.selector);
    }

    function expectRevertSameChainId(uint64 chainId) internal {
        vm.expectRevert(abi.encodeWithSelector(IInterchainDB.InterchainDB__SameChainId.selector, chainId));
    }

    // ═══════════════════════════════════════════════ TESTS: SET UP ═══════════════════════════════════════════════════

    function test_setup_getDBNonce() public {
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE);
    }

    function test_setup_getEntryValue() public {
        for (uint64 i = 0; i < INITIAL_DB_NONCE; ++i) {
            assertCorrectValue(icDB.getEntryValue(i, 0), getInitialEntry(i));
        }
    }

    // ══════════════════════════════════════════ TESTS: WRITING AN ENTRY ══════════════════════════════════════════════

    function test_writeEntry_writerF_emitsEvent() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        expectEventInterchainEntryWritten(entry);
        writeEntry(writerF, entry.dataHash);
    }

    function test_writeEntry_writerF_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        writeEntry(writerF, dataHash);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntry_writerF_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        uint64 nonce = writeEntry(writerF, dataHash);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntry_writerF_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        writeEntry(writerF, entry.dataHash);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntry_writerS_emitsEvent() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        expectEventInterchainEntryWritten(entry);
        writeEntry(writerS, entry.dataHash);
    }

    function test_writeEntry_writerS_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        writeEntry(writerS, dataHash);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntry_writerS_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        uint64 nonce = writeEntry(writerS, dataHash);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntry_writerS_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        writeEntry(writerS, entry.dataHash);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    // ═══════════════════════════════════════ TESTS: REQUESTING VALIDATION ════════════════════════════════════════════

    function test_requestVerification_writerF_oneModule_emitsEvent() public {
        uint64 dbNonce = 0;
        expectEventVerificationRequested(getInitialEntry(dbNonce), oneModule);
        requestVerification(requestCaller, MODULE_A_FEE, dbNonce, oneModule);
    }

    function test_requestVerification_writerF_oneModule_callsModule() public {
        uint64 dbNonce = 0;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        requestVerification(requestCaller, MODULE_A_FEE, dbNonce, oneModule);
    }

    function test_requestVerification_writerF_oneModule_higherFee() public {
        uint64 dbNonce = 0;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        expectEventVerificationRequested(getInitialEntry(dbNonce), oneModule);
        requestVerification(requestCaller, MODULE_A_FEE * 2, dbNonce, oneModule);
    }

    function test_requestVerification_writerF_twoModules_emitsEvent() public {
        uint64 dbNonce = 0;
        expectEventVerificationRequested(getInitialEntry(dbNonce), twoModules);
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, dbNonce, twoModules);
    }

    function test_requestVerification_writerF_twoModules_callsModules() public {
        uint64 dbNonce = 0;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, dbNonce, twoModules);
    }

    function test_requestVerification_writerF_twoModules_higherFee() public {
        // Overpaid fees should be directed to the first module
        uint64 dbNonce = 0;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        expectEventVerificationRequested(getInitialEntry(dbNonce), twoModules);
        requestVerification(requestCaller, MODULE_A_FEE * 2 + MODULE_B_FEE, dbNonce, twoModules);
    }

    function test_requestVerification_writerS_oneModule_emitsEvent() public {
        uint64 dbNonce = 2;
        expectEventVerificationRequested(getInitialEntry(dbNonce), oneModule);
        requestVerification(requestCaller, MODULE_A_FEE, dbNonce, oneModule);
    }

    function test_requestVerification_writerS_oneModule_callsModule() public {
        uint64 dbNonce = 2;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        requestVerification(requestCaller, MODULE_A_FEE, dbNonce, oneModule);
    }

    function test_requestVerification_writerS_oneModule_higherFee() public {
        uint64 dbNonce = 2;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        expectEventVerificationRequested(getInitialEntry(dbNonce), oneModule);
        requestVerification(requestCaller, MODULE_A_FEE * 2, dbNonce, oneModule);
    }

    function test_requestVerification_writerS_twoModules_emitsEvent() public {
        uint64 dbNonce = 2;
        expectEventVerificationRequested(getInitialEntry(dbNonce), twoModules);
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, dbNonce, twoModules);
    }

    function test_requestVerification_writerS_twoModules_callsModules() public {
        uint64 dbNonce = 2;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, dbNonce, twoModules);
    }

    function test_requestVerification_writerS_twoModules_higherFee() public {
        // Overpaid fees should be directed to the first module
        uint64 dbNonce = 2;
        InterchainEntry memory entry = getInitialEntry(dbNonce);
        // expectCall(address callee, uint256 msgValue, bytes calldata data)
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        expectEventVerificationRequested(getInitialEntry(dbNonce), twoModules);
        requestVerification(requestCaller, MODULE_A_FEE * 2 + MODULE_B_FEE, dbNonce, twoModules);
    }

    // ══════════════════════════════════ TESTS: REQUESTING VALIDATION (REVERTS) ═══════════════════════════════════════

    function test_requestVerification_revert_batchNotFinalized_oneModule_nextNonce() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE);
        requestVerification(requestCaller, MODULE_A_FEE, INITIAL_DB_NONCE, oneModule);
    }

    function test_requestVerification_revert_batchNotFinalized_oneModule_hugeNonce() public {
        expectRevertBatchNotFinalized(2 ** 32);
        requestVerification(requestCaller, MODULE_A_FEE, 2 ** 32, oneModule);
        expectRevertBatchNotFinalized(type(uint64).max);
        requestVerification(requestCaller, MODULE_A_FEE, type(uint64).max, oneModule);
    }

    function test_requestVerification_revert_batchNotFinalized_twoModules_nextNonce() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE);
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, INITIAL_DB_NONCE, twoModules);
    }

    function test_requestVerification_revert_batchNotFinalized_twoModules_hugeNonce() public {
        expectRevertBatchNotFinalized(2 ** 32);
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, 2 ** 32, twoModules);
        expectRevertBatchNotFinalized(type(uint64).max);
        requestVerification(requestCaller, MODULE_A_FEE + MODULE_B_FEE, type(uint64).max, twoModules);
    }

    function test_requestVerification_revert_incorrectFeeAmount_oneModule_underpaid() public {
        uint256 incorrectFee = MODULE_A_FEE - 1;
        expectRevertIncorrectFeeAmount(incorrectFee, MODULE_A_FEE);
        requestVerification(requestCaller, incorrectFee, 0, oneModule);
    }

    function test_requestVerification_revert_incorrectFeeAmount_twoModules_underpaid() public {
        uint256 incorrectFee = MODULE_A_FEE + MODULE_B_FEE - 1;
        expectRevertIncorrectFeeAmount(incorrectFee, MODULE_A_FEE + MODULE_B_FEE);
        requestVerification(requestCaller, incorrectFee, 0, twoModules);
    }

    function test_requestVerification_revert_noModulesSpecified() public {
        expectRevertNoModulesSpecified();
        requestVerification(requestCaller, MODULE_A_FEE, 0, new address[](0));
    }

    function test_requestVerification_revert_sameChainId() public {
        expectRevertSameChainId(SRC_CHAIN_ID);
        vm.prank(requestCaller);
        icDB.requestBatchVerification(SRC_CHAIN_ID, 0, oneModule);
    }

    // ═════════════════════════════════════ TESTS: WRITE + REQUEST VALIDATION ═════════════════════════════════════════

    function test_writeEntryWithVerification_writerF_oneModule_callsModule() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        writeEntryWithVerification(MODULE_A_FEE, writerF, entry.dataHash, oneModule);
    }

    function test_writeEntryWithVerification_writerF_oneModule_emitsEvents() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        expectEventInterchainEntryWritten(entry);
        expectEventVerificationRequested(entry, oneModule);
        writeEntryWithVerification(MODULE_A_FEE, writerF, entry.dataHash, oneModule);
    }

    function test_writeEntryWithVerification_writerF_oneModule_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        writeEntryWithVerification(MODULE_A_FEE, writerF, dataHash, oneModule);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntryWithVerification_writerF_oneModule_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        uint64 nonce = writeEntryWithVerification(MODULE_A_FEE, writerF, dataHash, oneModule);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntryWithVerification_writerF_oneModule_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        writeEntryWithVerification(MODULE_A_FEE, writerF, entry.dataHash, oneModule);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerF_oneModule_higherFee() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        expectEventInterchainEntryWritten(entry);
        writeEntryWithVerification(MODULE_A_FEE * 2, writerF, dataHash, oneModule);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerF_twoModules_callsModules() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerF, entry.dataHash, twoModules);
    }

    function test_writeEntryWithVerification_writerF_twoModules_emitsEvents() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        expectEventInterchainEntryWritten(entry);
        expectEventVerificationRequested(entry, twoModules);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerF, entry.dataHash, twoModules);
    }

    function test_writeEntryWithVerification_writerF_twoModules_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerF, dataHash, twoModules);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntryWithVerification_writerF_twoModules_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        uint64 nonce = writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerF, dataHash, twoModules);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntryWithVerification_writerF_twoModules_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerF, entry.dataHash, twoModules);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerF_twoModules_higherFee() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerF);
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        expectEventInterchainEntryWritten(entry);
        writeEntryWithVerification(MODULE_A_FEE * 2 + MODULE_B_FEE, writerF, dataHash, twoModules);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerS_oneModule_callsModule() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        writeEntryWithVerification(MODULE_A_FEE, writerS, entry.dataHash, oneModule);
    }

    function test_writeEntryWithVerification_writerS_oneModule_emitsEvents() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        expectEventInterchainEntryWritten(entry);
        expectEventVerificationRequested(entry, oneModule);
        writeEntryWithVerification(MODULE_A_FEE, writerS, entry.dataHash, oneModule);
    }

    function test_writeEntryWithVerification_writerS_oneModule_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        writeEntryWithVerification(MODULE_A_FEE, writerS, dataHash, oneModule);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntryWithVerification_writerS_oneModule_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        uint64 nonce = writeEntryWithVerification(MODULE_A_FEE, writerS, dataHash, oneModule);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntryWithVerification_writerS_oneModule_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        writeEntryWithVerification(MODULE_A_FEE, writerS, entry.dataHash, oneModule);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerS_oneModule_higherFee() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        expectEventInterchainEntryWritten(entry);
        writeEntryWithVerification(MODULE_A_FEE * 2, writerS, dataHash, oneModule);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerS_twoModules_callsModules() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        vm.expectCall(address(moduleA), MODULE_A_FEE, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerS, entry.dataHash, twoModules);
    }

    function test_writeEntryWithVerification_writerS_twoModules_emitsEvents() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        expectEventInterchainEntryWritten(entry);
        expectEventVerificationRequested(entry, twoModules);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerS, entry.dataHash, twoModules);
    }

    function test_writeEntryWithVerification_writerS_twoModules_increasesDBNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerS, dataHash, twoModules);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
    }

    function test_writeEntryWithVerification_writerS_twoModules_returnsCorrectNonce() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        uint64 nonce = writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerS, dataHash, twoModules);
        assertEq(nonce, INITIAL_DB_NONCE);
    }

    function test_writeEntryWithVerification_writerS_twoModules_savesEntry() public {
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        writeEntryWithVerification(MODULE_A_FEE + MODULE_B_FEE, writerS, entry.dataHash, twoModules);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    function test_writeEntryWithVerification_writerS_twoModules_higherFee() public {
        bytes32 dataHash = getMockDataHash(writerS, INITIAL_DB_NONCE);
        InterchainEntry memory entry = getMockEntry(INITIAL_DB_NONCE, writerS);
        vm.expectCall(address(moduleA), MODULE_A_FEE * 2, getModuleCalldata(entry));
        vm.expectCall(address(moduleB), MODULE_B_FEE, getModuleCalldata(entry));
        expectEventInterchainEntryWritten(entry);
        writeEntryWithVerification(MODULE_A_FEE * 2 + MODULE_B_FEE, writerS, dataHash, twoModules);
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE + 1);
        assertCorrectValue(icDB.getEntryValue(INITIAL_DB_NONCE, 0), entry);
    }

    // ════════════════════════════════ TESTS: WRITE + REQUEST VALIDATION (REVERTS) ════════════════════════════════════

    function test_writeEntryWithVerification_revert_incorrectFeeAmount_oneModule_underpaid() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        uint256 incorrectFee = MODULE_A_FEE - 1;
        expectRevertIncorrectFeeAmount(incorrectFee, MODULE_A_FEE);
        writeEntryWithVerification(incorrectFee, writerF, dataHash, oneModule);
    }

    function test_writeEntryWithVerification_revert_incorrectFeeAmount_twoModules_underpaid() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        uint256 incorrectFee = MODULE_A_FEE + MODULE_B_FEE - 1;
        expectRevertIncorrectFeeAmount(incorrectFee, MODULE_A_FEE + MODULE_B_FEE);
        writeEntryWithVerification(incorrectFee, writerF, dataHash, twoModules);
    }

    function test_writeEntryWithVerification_revert_noModulesSpecified() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        expectRevertNoModulesSpecified();
        writeEntryWithVerification(0, writerF, dataHash, new address[](0));
    }

    function test_writeEntryWithVerification_revert_sameChainId() public {
        bytes32 dataHash = getMockDataHash(writerF, INITIAL_DB_NONCE);
        expectRevertSameChainId(SRC_CHAIN_ID);
        vm.prank(writerF);
        icDB.writeEntryWithVerification(SRC_CHAIN_ID, dataHash, oneModule);
    }

    // ═════════════════════════════════════════ TESTS: GET INTERCHAIN FEE ═════════════════════════════════════════════

    function test_getInterchainFee_noModules() public {
        expectRevertNoModulesSpecified();
        icDB.getInterchainFee(DST_CHAIN_ID, new address[](0));
    }

    function test_getInterchainFee_oneModule() public {
        // [moduleA]
        assertEq(icDB.getInterchainFee(DST_CHAIN_ID, oneModule), MODULE_A_FEE);
    }

    function test_getInterchainFee_twoModules() public {
        // [moduleA, moduleB]
        assertEq(icDB.getInterchainFee(DST_CHAIN_ID, twoModules), MODULE_A_FEE + MODULE_B_FEE);
    }

    // ════════════════════════════════════════ TESTS: RETRIEVING DB VALUES ════════════════════════════════════════════

    function checkBatchRoot(bytes32 batchRoot, InterchainEntry memory expectedEntry) internal {
        bytes32 expectedRoot = InterchainEntryLib.entryValue(expectedEntry);
        assertEq(batchRoot, expectedRoot, "!batchRoot");
    }

    function checkBatch(InterchainBatch memory batch, InterchainEntry memory expectedEntry) internal {
        assertEq(batch.srcChainId, expectedEntry.srcChainId, "!srcChainId");
        assertEq(batch.dbNonce, expectedEntry.dbNonce, "!dbNonce");
        checkBatchRoot(batch.batchRoot, expectedEntry);
    }

    function test_getBatchLeafs() public {
        for (uint64 nonce = 0; nonce < INITIAL_DB_NONCE; ++nonce) {
            bytes32[] memory leafs = icDB.getBatchLeafs(nonce);
            assertEq(leafs.length, 1, "!leafs.length");
            checkBatchRoot(leafs[0], getInitialEntry(nonce));
        }
    }

    function test_getBatchLeafs_revert_notFinalized() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE);
        icDB.getBatchLeafs(INITIAL_DB_NONCE);
    }

    function test_getBatchLeafs_revert_nonExistent() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE + 1);
        icDB.getBatchLeafs(INITIAL_DB_NONCE + 1);
    }

    function test_getBatchLeafsPaginated() public {
        for (uint64 nonce = 0; nonce < INITIAL_DB_NONCE; ++nonce) {
            bytes32[] memory leafs = icDB.getBatchLeafsPaginated(nonce, 0, 1);
            assertEq(leafs.length, 1, "!leafs.length");
            checkBatchRoot(leafs[0], getInitialEntry(nonce));
        }
    }

    function test_getBatchLeafsPaginated_revert_notFinalized() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE);
        icDB.getBatchLeafsPaginated(INITIAL_DB_NONCE, 0, 1);
    }

    function test_getBatchLeafsPaginated_revert_nonExistent() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE + 1);
        icDB.getBatchLeafsPaginated(INITIAL_DB_NONCE + 1, 0, 1);
    }

    function test_getBatchLeafsPaginated_revert_invalidRange() public {
        expectRevertInvalidEntryRange(0, 0, 0);
        icDB.getBatchLeafsPaginated(0, 0, 0);
        expectRevertInvalidEntryRange(1, 0, 2);
        icDB.getBatchLeafsPaginated(1, 0, 2);
        expectRevertInvalidEntryRange(2, 1, 1);
        icDB.getBatchLeafsPaginated(2, 1, 1);
        expectRevertInvalidEntryRange(3, 1, 0);
        icDB.getBatchLeafsPaginated(3, 1, 0);
    }

    function test_getBatchSize_finalized() public {
        for (uint64 nonce = 0; nonce < INITIAL_DB_NONCE; ++nonce) {
            assertEq(icDB.getBatchSize(nonce), 1, "!batchSize");
        }
    }

    function test_getBatchSize_pending() public {
        assertEq(icDB.getBatchSize(INITIAL_DB_NONCE), 0);
    }

    function test_getBatchSize_revert_nonExistent() public {
        expectRevertBatchDoesNotExist(INITIAL_DB_NONCE + 1);
        icDB.getBatchSize(INITIAL_DB_NONCE + 1);
    }

    function test_getBatch() public {
        for (uint64 nonce = 0; nonce < INITIAL_DB_NONCE; ++nonce) {
            InterchainBatch memory batch = icDB.getBatch(nonce);
            checkBatch(batch, getInitialEntry(nonce));
        }
    }

    function test_getBatch_revert_notFinalized() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE);
        icDB.getBatch(INITIAL_DB_NONCE);
    }

    function test_getBatch_revert_nonExistent() public {
        expectRevertBatchNotFinalized(INITIAL_DB_NONCE + 1);
        icDB.getBatch(INITIAL_DB_NONCE + 1);
    }

    function test_getEntryValue() public {
        for (uint64 nonce = 0; nonce < INITIAL_DB_NONCE; ++nonce) {
            InterchainEntry memory expectedEntry = getInitialEntry(nonce);
            assertCorrectValue(icDB.getEntryValue(nonce, 0), expectedEntry);
        }
    }

    function test_getEntryValue_revert_finalizedOutOfRange() public {
        expectRevertEntryIndexOutOfRange(INITIAL_DB_NONCE - 1, 1, 1);
        icDB.getEntryValue(INITIAL_DB_NONCE - 1, 1);
    }

    function test_getEntryValue_revert_notFinalizedOutOfRange() public {
        expectRevertEntryIndexOutOfRange(INITIAL_DB_NONCE, 0, 0);
        icDB.getEntryValue(INITIAL_DB_NONCE, 0);
    }

    function test_getDBNonce() public {
        assertEq(icDB.getDBNonce(), INITIAL_DB_NONCE);
    }

    // ═══════════════════════════════════════════ TESTS: GET BATCH ROOT ═══════════════════════════════════════════════

    function test_getBatchRoot(InterchainEntry memory entry) public {
        entry.entryIndex = 0;
        bytes32 batchRoot = icDB.getBatchRoot(entry, new bytes32[](0));
        assertEq(batchRoot, InterchainEntryLib.entryValue(entry));
    }

    function test_getBatchRoot_revert_nonZeroEntryIndex() public {
        InterchainEntry memory entry = getInitialEntry(0);
        entry.entryIndex = 1;
        expectRevertIncorrectEntryIndex(1);
        icDB.getBatchRoot(entry, new bytes32[](0));
    }

    function test_getBatchRoot_revert_nonEmptyProof() public {
        InterchainEntry memory entry = getInitialEntry(0);
        expectRevertIncorrectProof();
        icDB.getBatchRoot(entry, new bytes32[](1));
    }
}
