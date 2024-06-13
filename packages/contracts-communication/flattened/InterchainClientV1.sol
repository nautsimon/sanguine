// SPDX-License-Identifier: MIT
pragma solidity =0.8.20 ^0.8.0 ^0.8.13 ^0.8.20;

// contracts/events/InterchainClientV1Events.sol

abstract contract InterchainClientV1Events {
    /// @notice Emitted when the default Guard module is set.
    /// @param guard    The address of the Guard module that will be used by default.
    event DefaultGuardSet(address guard);

    /// @notice Emitted when the default Module is set.
    /// @param module   The address of the Module that will be used by default.
    event DefaultModuleSet(address module);

    /// @notice Emitted when the InterchainClientV1 deployment on a remote chain is linked.
    /// @param chainId   The chain ID of the remote chain.
    /// @param client    The address of the InterchainClientV1 deployment on the remote chain.
    event LinkedClientSet(uint64 chainId, bytes32 client);

    /// @notice Emitted when a new interchain transaction is sent through the InterchainClientV1.
    /// The Receiver on the destination chain will receive the specified message once the transaction is executed.
    /// @param transactionId    The unique identifier of the interchain transaction.
    /// @param dbNonce          The nonce of entry containing the transaction.
    /// @param dstChainId       The chain ID of the destination chain.
    /// @param srcSender        The sender of the transaction on the source chain.
    /// @param dstReceiver      The receiver of the transaction on the destination chain.
    /// @param verificationFee  The fee paid to verify the entry on the destination chain.
    /// @param executionFee     The fee paid to execute the transaction on the destination chain.
    /// @param options          The execution options for the transaction.
    /// @param message          The payload of the message being sent.
    event InterchainTransactionSent(
        bytes32 indexed transactionId,
        uint64 dbNonce,
        uint64 dstChainId,
        bytes32 indexed srcSender,
        bytes32 indexed dstReceiver,
        uint256 verificationFee,
        uint256 executionFee,
        bytes options,
        bytes message
    );

    /// @notice Emitted when an interchain transaction is received by the InterchainClientV1.
    /// The Receiver on the destination chain has just received the message sent from the source chain.
    /// @param transactionId    The unique identifier of the interchain transaction.
    /// @param dbNonce          The nonce of entry containing the transaction.
    /// @param srcChainId       The chain ID of the source chain.
    /// @param srcSender        The sender of the transaction on the source chain.
    /// @param dstReceiver      The receiver of the transaction on the destination chain.
    event InterchainTransactionReceived(
        bytes32 indexed transactionId,
        uint64 dbNonce,
        uint64 srcChainId,
        bytes32 indexed srcSender,
        bytes32 indexed dstReceiver
    );

    /// @notice Emitted when the proof of execution is written to InterchainDB. This allows the source chain
    /// to verify that the transaction was executed by a specific executor, if necessary.
    /// @param transactionId    The unique identifier of the interchain transaction.
    /// @param dbNonce          The nonce of entry containing the transaction.
    /// @param executor         The address of the executor that completed the transaction.
    event ExecutionProofWritten(bytes32 indexed transactionId, uint64 dbNonce, address indexed executor);
}

// contracts/interfaces/IExecutionService.sol

interface IExecutionService {
    function requestTxExecution(
        uint64 dstChainId,
        uint256 txPayloadSize,
        bytes32 transactionId,
        bytes memory options
    )
        external
        payable;

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    function executorEOA() external view returns (address);

    function getExecutionFee(
        uint64 dstChainId,
        uint256 txPayloadSize,
        bytes memory options
    )
        external
        view
        returns (uint256);
}

// contracts/interfaces/IInterchainApp.sol

/// @notice Minimal interface for the Interchain App to work with the Interchain Client.
interface IInterchainApp {
    function appReceive(uint64 srcChainId, bytes32 sender, uint64 dbNonce, bytes calldata message) external payable;

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    function getReceivingConfig() external view returns (bytes memory appConfig, address[] memory modules);
}

// contracts/libs/Math.sol

library MathLib {
    /// @notice Rounds up to the nearest multiple of 32.
    /// Note: Returns zero on overflows instead of reverting. This is fine for practical
    /// use cases, as this is used for determining the size of the payload in memory.
    function roundUpToWord(uint256 x) internal pure returns (uint256) {
        unchecked {
            return (x + 31) & ~uint256(31);
        }
    }
}

// contracts/libs/TypeCasts.sol

library TypeCasts {
    function addressToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    function bytes32ToAddress(bytes32 b) internal pure returns (address) {
        return address(uint160(uint256(b)));
    }
}

// contracts/libs/VersionedPayload.sol

// solhint-disable no-inline-assembly
// solhint-disable ordering
library VersionedPayloadLib {
    /// @notice Amount of bytes reserved for the version (uint16) in the versioned payload
    uint256 internal constant VERSION_LENGTH = 2;

    error VersionedPayload__PayloadTooShort(bytes versionedPayload);
    error VersionedPayload__PrecompileFailed();

    /// @notice Encodes the versioned payload into a single bytes array.
    /// @param version  The payload's version.
    /// @param payload  The payload to encode.
    function encodeVersionedPayload(uint16 version, bytes memory payload) internal pure returns (bytes memory) {
        return abi.encodePacked(version, payload);
    }

    /// @notice Extracts the version from the versioned payload (calldata reference).
    /// @param versionedPayload     The versioned payload (calldata reference).
    function getVersion(bytes calldata versionedPayload) internal pure returns (uint16 version) {
        if (versionedPayload.length < VERSION_LENGTH) {
            revert VersionedPayload__PayloadTooShort(versionedPayload);
        }
        assembly {
            // We are only interested in the highest 16 bits of the loaded full 32 bytes word.
            version := shr(240, calldataload(versionedPayload.offset))
        }
    }

    /// @notice Extracts the payload from the versioned payload (calldata reference).
    /// @dev The extracted payload is also returned as a calldata reference.
    /// @param versionedPayload     The versioned payload.
    function getPayload(bytes calldata versionedPayload) internal pure returns (bytes calldata) {
        if (versionedPayload.length < VERSION_LENGTH) {
            revert VersionedPayload__PayloadTooShort(versionedPayload);
        }
        return versionedPayload[VERSION_LENGTH:];
    }

    /// @notice Extracts the version from the versioned payload (memory reference).
    /// @param versionedPayload     The versioned payload (memory reference).
    function getVersionFromMemory(bytes memory versionedPayload) internal pure returns (uint16 version) {
        if (versionedPayload.length < VERSION_LENGTH) {
            revert VersionedPayload__PayloadTooShort(versionedPayload);
        }
        assembly {
            // We are only interested in the highest 16 bits of the loaded full 32 bytes word.
            // We add 0x20 to skip the length of the bytes array.
            version := shr(240, mload(add(versionedPayload, 0x20)))
        }
    }

    /// @notice Extracts the payload from the versioned payload (memory reference).
    /// @dev The extracted payload is copied into a new memory location. Use `getPayload` when possible
    /// to avoid extra memory allocation.
    /// @param versionedPayload     The versioned payload (memory reference).
    function getPayloadFromMemory(bytes memory versionedPayload) internal view returns (bytes memory payload) {
        if (versionedPayload.length < VERSION_LENGTH) {
            revert VersionedPayload__PayloadTooShort(versionedPayload);
        }
        // Figure how many bytes to copy and allocate the memory for the extracted payload.
        uint256 toCopy;
        unchecked {
            toCopy = versionedPayload.length - VERSION_LENGTH;
        }
        payload = new bytes(toCopy);
        // Use identity precompile (0x04) to copy the payload. Unlike MCOPY, this is available on all EVM chains.
        bool res;
        assembly {
            // We add 0x20 to skip the length of the bytes array.
            // We add 0x02 to skip the 2 bytes reserved for the version.
            // Copy the payload to the previously allocated memory.
            res := staticcall(gas(), 0x04, add(versionedPayload, 0x22), toCopy, add(payload, 0x20), toCopy)
        }
        if (!res) {
            revert VersionedPayload__PrecompileFailed();
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/Context.sol

// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// node_modules/@openzeppelin/contracts/utils/math/SafeCast.sol

// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

/**
 * @dev Wrappers over Solidity's uintXX/intXX casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }
}

// contracts/libs/AppConfig.sol

// TODO: all of these could fit into a single 32 bytes slot
struct AppConfigV1 {
    uint256 requiredResponses;
    uint256 optimisticPeriod;
    uint256 guardFlag;
    address guard;
}

using AppConfigLib for AppConfigV1 global;

/// @dev Signals that the app opted out of using any Guard module.
uint8 constant APP_CONFIG_GUARD_DISABLED = 0;
/// @dev Signals that the app uses the default Guard module provided by InterchainClient contract.
uint8 constant APP_CONFIG_GUARD_DEFAULT = 1;
/// @dev Signals that the app uses a custom Guard module.
uint8 constant APP_CONFIG_GUARD_CUSTOM = 2;

library AppConfigLib {
    using VersionedPayloadLib for bytes;

    uint16 internal constant APP_CONFIG_V1 = 1;

    error AppConfigLib__VersionInvalid(uint16 version);

    /// @notice Decodes app config (V1 or higher) from a bytes format back into an AppConfigV1 struct.
    /// @param data         The app config data in bytes format.
    function decodeAppConfigV1(bytes memory data) internal view returns (AppConfigV1 memory) {
        uint16 version = data.getVersionFromMemory();
        if (version < APP_CONFIG_V1) {
            revert AppConfigLib__VersionInvalid(version);
        }
        // Structs of the same version will always be decoded correctly.
        // Following versions will be decoded correctly if they have the same fields as the previous version,
        // and new fields at the end: abi.decode ignores the extra bytes in the decoded payload.
        return abi.decode(data.getPayloadFromMemory(), (AppConfigV1));
    }

    /// @notice Encodes V1 app config into a bytes format.
    /// @param appConfig    The AppConfigV1 to encode.
    function encodeAppConfigV1(AppConfigV1 memory appConfig) internal pure returns (bytes memory) {
        return VersionedPayloadLib.encodeVersionedPayload(APP_CONFIG_V1, abi.encode(appConfig));
    }
}

// contracts/libs/InterchainEntry.sol

/// @notice Struct representing an entry in the Interchain DataBase.
/// Entry has a globally unique identifier (key) and a value.
/// Assuming `srcWriter` has written data `digest` on the source chain:
/// - key: (srcChainId, dbNonce)
/// - entryValue = keccak256(srcWriter, digest)
/// @param srcChainId   The chain id of the source chain
/// @param dbNonce      The database nonce of the entry
/// @param entryValue   The entry value
struct InterchainEntry {
    uint64 srcChainId;
    uint64 dbNonce;
    bytes32 entryValue;
}

type EntryKey is uint128;

/// @dev Signals that the module has not verified any entry with the given key.
uint256 constant ENTRY_UNVERIFIED = 0;
/// @dev Signals that the module has verified a conflicting entry with the given key.
uint256 constant ENTRY_CONFLICT = type(uint256).max;

library InterchainEntryLib {
    /// @notice Constructs an InterchainEntry struct to be written on the local chain
    /// @param dbNonce      The database nonce of the entry on the source chain
    /// @param entryValue   The value of the entry
    /// @return entry       The constructed InterchainEntry struct
    function constructLocalEntry(
        uint64 dbNonce,
        bytes32 entryValue
    )
        internal
        view
        returns (InterchainEntry memory entry)
    {
        uint64 srcChainId = SafeCast.toUint64(block.chainid);
        return InterchainEntry({srcChainId: srcChainId, dbNonce: dbNonce, entryValue: entryValue});
    }

    /// @notice Returns the value of the entry: writer + digest hashed together
    function getEntryValue(bytes32 srcWriter, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encode(srcWriter, digest));
    }

    /// @notice Returns the value of the entry: writer + digest hashed together.
    /// Note: this is exposed for convenience to avoid typecasts prior to abi-encoding.
    function getEntryValue(address srcWriter, bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encode(srcWriter, digest));
    }

    /// @notice Encodes the InterchainEntry struct into a non-versioned entry payload.
    function encodeEntry(InterchainEntry memory entry) internal pure returns (bytes memory) {
        return abi.encode(encodeEntryKey(entry.srcChainId, entry.dbNonce), entry.entryValue);
    }

    /// @notice Decodes the InterchainEntry struct from a non-versioned entry payload in calldata.
    function decodeEntry(bytes calldata data) internal pure returns (InterchainEntry memory entry) {
        EntryKey key;
        (key, entry.entryValue) = abi.decode(data, (EntryKey, bytes32));
        (entry.srcChainId, entry.dbNonce) = decodeEntryKey(key);
    }

    /// @notice Decodes the InterchainEntry struct from a non-versioned entry payload in memory.
    function decodeEntryFromMemory(bytes memory data) internal pure returns (InterchainEntry memory entry) {
        EntryKey key;
        (key, entry.entryValue) = abi.decode(data, (EntryKey, bytes32));
        (entry.srcChainId, entry.dbNonce) = decodeEntryKey(key);
    }

    /// @notice Encodes the uint128 key of the entry from uint64 srcChainId and uint64 dbNonce.
    function encodeEntryKey(uint64 srcChainId, uint64 dbNonce) internal pure returns (EntryKey) {
        return EntryKey.wrap((uint128(srcChainId) << 64) | dbNonce);
    }

    /// @notice Decodes the uint128 key of the entry into uint64 srcChainId and uint64 dbNonce.
    function decodeEntryKey(EntryKey key) internal pure returns (uint64 srcChainId, uint64 dbNonce) {
        srcChainId = uint64(EntryKey.unwrap(key) >> 64);
        dbNonce = uint64(EntryKey.unwrap(key));
    }
}

// contracts/libs/Options.sol

/// @notice Struct to hold V1 of options data.
/// @dev Next versions have to use the fields from the previous version and add new fields at the end.
/// @param gasLimit The gas limit for the transaction.
/// @param gasAirdrop The amount of gas to airdrop.
struct OptionsV1 {
    uint256 gasLimit;
    uint256 gasAirdrop;
}

using OptionsLib for OptionsV1 global;

/// @title OptionsLib
/// @notice A library for encoding and decoding Interchain options related to interchain messages.
library OptionsLib {
    using VersionedPayloadLib for bytes;

    uint16 internal constant OPTIONS_V1 = 1;

    error OptionsLib__VersionInvalid(uint16 version);

    /// @notice Decodes options (V1 or higher) from a bytes format back into an OptionsV1 struct.
    /// @param data         The options data in bytes format.
    function decodeOptionsV1(bytes memory data) internal view returns (OptionsV1 memory) {
        uint16 version = data.getVersionFromMemory();
        if (version < OPTIONS_V1) {
            revert OptionsLib__VersionInvalid(version);
        }
        // Structs of the same version will always be decoded correctly.
        // Following versions will be decoded correctly if they have the same fields as the previous version,
        // and new fields at the end: abi.decode ignores the extra bytes in the decoded payload.
        return abi.decode(data.getPayloadFromMemory(), (OptionsV1));
    }

    /// @notice Encodes V1 options into a bytes format.
    /// @param options      The OptionsV1 to encode.
    function encodeOptionsV1(OptionsV1 memory options) internal pure returns (bytes memory) {
        return VersionedPayloadLib.encodeVersionedPayload(OPTIONS_V1, abi.encode(options));
    }
}

// node_modules/@openzeppelin/contracts/access/Ownable.sol

// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// contracts/interfaces/IInterchainDB.sol

interface IInterchainDB {
    error InterchainDB__ChainIdNotRemote(uint64 chainId);
    error InterchainDB__EntryConflict(address module, InterchainEntry newEntry);
    error InterchainDB__EntryVersionMismatch(uint16 version, uint16 required);
    error InterchainDB__FeeAmountBelowMin(uint256 feeAmount, uint256 minRequired);
    error InterchainDB__ModulesNotProvided();

    function writeEntry(bytes32 digest) external returns (uint64 dbNonce);

    function requestEntryVerification(
        uint64 dstChainId,
        uint64 dbNonce,
        address[] memory srcModules
    )
        external
        payable;

    function writeEntryRequestVerification(
        uint64 dstChainId,
        bytes32 digest,
        address[] memory srcModules
    )
        external
        payable
        returns (uint64 dbNonce);

    function verifyRemoteEntry(bytes memory encodedEntry) external;

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    function getInterchainFee(uint64 dstChainId, address[] memory srcModules) external view returns (uint256);

    function getEncodedEntry(uint64 dbNonce) external view returns (bytes memory);
    function getEntry(uint64 dbNonce) external view returns (InterchainEntry memory);
    function getEntryValue(uint64 dbNonce) external view returns (bytes32);

    function getDBNonce() external view returns (uint64);

    function checkEntryVerification(
        address dstModule,
        InterchainEntry memory entry
    )
        external
        view
        returns (uint256 moduleVerifiedAt);

    // solhint-disable-next-line func-name-mixedcase
    function DB_VERSION() external pure returns (uint16);
}

// contracts/libs/InterchainTransaction.sol

type ICTxHeader is uint256;

struct InterchainTransaction {
    uint64 srcChainId;
    uint64 dstChainId;
    uint64 dbNonce;
    bytes32 srcSender;
    bytes32 dstReceiver;
    bytes options;
    bytes message;
}

struct InterchainTxDescriptor {
    bytes32 transactionId;
    uint64 dbNonce;
}

using InterchainTransactionLib for InterchainTransaction global;

library InterchainTransactionLib {
    using MathLib for uint256;
    using VersionedPayloadLib for bytes;

    function constructLocalTransaction(
        address srcSender,
        uint64 dstChainId,
        bytes32 dstReceiver,
        uint64 dbNonce,
        bytes memory options,
        bytes memory message
    )
        internal
        view
        returns (InterchainTransaction memory transaction)
    {
        return InterchainTransaction({
            srcChainId: SafeCast.toUint64(block.chainid),
            srcSender: TypeCasts.addressToBytes32(srcSender),
            dstChainId: dstChainId,
            dstReceiver: dstReceiver,
            dbNonce: dbNonce,
            options: options,
            message: message
        });
    }

    function encodeTransaction(InterchainTransaction memory transaction) internal pure returns (bytes memory) {
        return abi.encode(
            encodeTxHeader(transaction.srcChainId, transaction.dstChainId, transaction.dbNonce),
            transaction.srcSender,
            transaction.dstReceiver,
            transaction.options,
            transaction.message
        );
    }

    function decodeTransaction(bytes calldata transaction) internal pure returns (InterchainTransaction memory icTx) {
        ICTxHeader header;
        (header, icTx.srcSender, icTx.dstReceiver, icTx.options, icTx.message) =
            abi.decode(transaction, (ICTxHeader, bytes32, bytes32, bytes, bytes));
        (icTx.srcChainId, icTx.dstChainId, icTx.dbNonce) = decodeTxHeader(header);
    }

    function payloadSize(uint256 optionsLen, uint256 messageLen) internal pure returns (uint256) {
        // 2 bytes are reserved for the transaction version
        // + 5 fields * 32 bytes (3 values for static, 2 offsets for dynamic) + 2 * 32 bytes (lengths for dynamic) = 226
        // (srcChainId, dstChainId, dbNonce) are merged into a single 32 bytes field
        // Both options and message are dynamic fields, which are padded up to 32 bytes
        return 226 + optionsLen.roundUpToWord() + messageLen.roundUpToWord();
    }

    function encodeTxHeader(uint64 srcChainId, uint64 dstChainId, uint64 dbNonce) internal pure returns (ICTxHeader) {
        return ICTxHeader.wrap((uint256(srcChainId) << 128) | (uint256(dstChainId) << 64) | (uint256(dbNonce)));
    }

    function decodeTxHeader(ICTxHeader header)
        internal
        pure
        returns (uint64 srcChainId, uint64 dstChainId, uint64 dbNonce)
    {
        srcChainId = uint64(ICTxHeader.unwrap(header) >> 128);
        dstChainId = uint64(ICTxHeader.unwrap(header) >> 64);
        dbNonce = uint64(ICTxHeader.unwrap(header));
    }
}

// contracts/interfaces/IInterchainClientV1.sol

interface IInterchainClientV1 {
    enum TxReadiness {
        Ready,
        AlreadyExecuted,
        EntryAwaitingResponses,
        EntryConflict,
        ReceiverNotICApp,
        TxWrongDstChainId,
        UndeterminedRevert
    }

    error InterchainClientV1__ChainIdNotLinked(uint64 chainId);
    error InterchainClientV1__ChainIdNotRemote(uint64 chainId);
    error InterchainClientV1__DstChainIdNotLocal(uint64 chainId);
    error InterchainClientV1__EntryConflict(address module);
    error InterchainClientV1__ExecutionServiceZeroAddress();
    error InterchainClientV1__FeeAmountBelowMin(uint256 feeAmount, uint256 minRequired);
    error InterchainClientV1__GasLeftBelowMin(uint256 gasLeft, uint256 minRequired);
    error InterchainClientV1__GuardZeroAddress();
    error InterchainClientV1__LinkedClientNotEVM(bytes32 client);
    error InterchainClientV1__ModuleZeroAddress();
    error InterchainClientV1__MsgValueMismatch(uint256 msgValue, uint256 required);
    error InterchainClientV1__ReceiverNotICApp(address receiver);
    error InterchainClientV1__ReceiverZeroAddress();
    error InterchainClientV1__ResponsesAmountBelowMin(uint256 responsesAmount, uint256 minRequired);
    error InterchainClientV1__TxAlreadyExecuted(bytes32 transactionId);
    error InterchainClientV1__TxNotExecuted(bytes32 transactionId);
    error InterchainClientV1__TxVersionMismatch(uint16 txVersion, uint16 required);

    function setDefaultGuard(address guard) external;
    function setDefaultModule(address module) external;
    function setLinkedClient(uint64 chainId, bytes32 client) external;

    function interchainSend(
        uint64 dstChainId,
        bytes32 receiver,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        bytes calldata message
    )
        external
        payable
        returns (InterchainTxDescriptor memory desc);

    function interchainSendEVM(
        uint64 dstChainId,
        address receiver,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        bytes calldata message
    )
        external
        payable
        returns (InterchainTxDescriptor memory desc);

    function interchainExecute(uint256 gasLimit, bytes calldata transaction) external payable;

    function writeExecutionProof(bytes32 transactionId) external returns (uint64 dbNonce);

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    function isExecutable(bytes calldata transaction) external view returns (bool);
    function getTxReadinessV1(InterchainTransaction memory icTx)
        external
        view
        returns (TxReadiness status, bytes32 firstArg, bytes32 secondArg);

    function getInterchainFee(
        uint64 dstChainId,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        uint256 messageLen
    )
        external
        view
        returns (uint256);

    function getExecutor(bytes calldata transaction) external view returns (address);
    function getExecutorById(bytes32 transactionId) external view returns (address);
    function getLinkedClient(uint64 chainId) external view returns (bytes32);
    function getLinkedClientEVM(uint64 chainId) external view returns (address);
}

// contracts/InterchainClientV1.sol

/**
 * @title InterchainClientV1
 * @dev Implements the operations of the Interchain Execution Layer.
 */
contract InterchainClientV1 is Ownable, InterchainClientV1Events, IInterchainClientV1 {
    using AppConfigLib for bytes;
    using OptionsLib for bytes;
    using TypeCasts for address;
    using TypeCasts for bytes32;
    using VersionedPayloadLib for bytes;

    /// @notice Version of the InterchainClient contract. Sent and received transactions must have the same version.
    uint16 public constant CLIENT_VERSION = 1;

    /// @notice Address of the InterchainDB contract, set at the time of deployment.
    address public immutable INTERCHAIN_DB;

    /// @notice Address of the Guard module used to verify the validity of entries.
    /// Note: entries marked as invalid by the Guard could not be used for message execution,
    /// if the app opts in to use the Guard.
    address public defaultGuard;

    /// @notice Address of the default module to use to verify the validity of entries.
    /// Note: this module will be used for the apps that define an empty module list in their config.
    address public defaultModule;

    /// @dev Address of the InterchainClient contract on the remote chain
    mapping(uint64 chainId => bytes32 remoteClient) internal _linkedClient;
    /// @dev Executor address that completed the transaction. Address(0) if not executed yet.
    mapping(bytes32 transactionId => address executor) internal _txExecutor;

    constructor(address interchainDB, address owner_) Ownable(owner_) {
        INTERCHAIN_DB = interchainDB;
    }

    /// @notice Allows the contract owner to set the address of the Guard module.
    /// Note: entries marked as invalid by the Guard could not be used for message execution,
    /// if the app opts in to use the Guard.
    /// @param guard            The address of the Guard module.
    function setDefaultGuard(address guard) external onlyOwner {
        if (guard == address(0)) {
            revert InterchainClientV1__GuardZeroAddress();
        }
        defaultGuard = guard;
        emit DefaultGuardSet(guard);
    }

    /// @notice Allows the contract owner to set the address of the default module.
    /// Note: this module will be used for the apps that define an empty module list in their config.
    /// @param module           The address of the default module.
    function setDefaultModule(address module) external onlyOwner {
        if (module == address(0)) {
            revert InterchainClientV1__ModuleZeroAddress();
        }
        defaultModule = module;
        emit DefaultModuleSet(module);
    }

    /// @notice Sets the linked client for a specific chain ID.
    /// Note: only Interchain Entries written by the linked client could be used for message execution.
    /// @param chainId          The chain ID for which the client is being set.
    /// @param client           The address of the client being linked.
    function setLinkedClient(uint64 chainId, bytes32 client) external onlyOwner {
        _linkedClient[chainId] = client;
        emit LinkedClientSet(chainId, client);
    }

    /// @notice Sends a message to another chain via the Interchain Communication Protocol.
    /// @dev Charges a fee for the message, which is payable upon calling this function:
    /// - Verification fees: paid to every module that verifies the message.
    /// - Execution fee: paid to the executor that executes the message.
    /// Note: while a specific execution service is specified to request the execution of the message,
    /// any executor is able to execute the message on destination chain.
    /// @param dstChainId           The chain ID of the destination chain.
    /// @param receiver             The address of the receiver on the destination chain.
    /// @param srcExecutionService  The address of the execution service to use for the message.
    /// @param srcModules           The source modules involved in the message sending.
    /// @param options              Execution options for the message sent, encoded as bytes,
    ///                             currently gas limit + native gas drop.
    /// @param message              The message to be sent.
    /// @return desc                The descriptor of the sent transaction:
    /// - transactionId: the ID of the transaction that was sent.
    /// - dbNonce: the database nonce of the entry containing the transaction.
    function interchainSend(
        uint64 dstChainId,
        bytes32 receiver,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        bytes calldata message
    )
        external
        payable
        returns (InterchainTxDescriptor memory desc)
    {
        return _interchainSend(dstChainId, receiver, srcExecutionService, srcModules, options, message);
    }

    /// @notice A thin wrapper around `interchainSend` that allows to specify the receiver address as an EVM address.
    function interchainSendEVM(
        uint64 dstChainId,
        address receiver,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        bytes calldata message
    )
        external
        payable
        returns (InterchainTxDescriptor memory desc)
    {
        bytes32 receiverBytes32 = receiver.addressToBytes32();
        return _interchainSend(dstChainId, receiverBytes32, srcExecutionService, srcModules, options, message);
    }

    /// @notice Executes a transaction that has been sent via the Interchain Communication Protocol.
    /// Note: The transaction must be proven to be included in one of the InterchainDB entries.
    /// Note: Transaction data includes the requested gas limit, but the executors could specify a different gas limit.
    /// If the specified gas limit is lower than requested, the requested gas limit will be used.
    /// Otherwise, the specified gas limit will be used.
    /// This allows to execute the transactions with requested gas limit set too low.
    /// @param gasLimit          The gas limit to use for the execution.
    /// @param transaction       The transaction data.
    function interchainExecute(uint256 gasLimit, bytes calldata transaction) external payable {
        InterchainTransaction memory icTx = _assertCorrectTransaction(transaction);
        bytes32 transactionId = keccak256(transaction);
        _assertExecutable(icTx, transactionId);
        _txExecutor[transactionId] = msg.sender;

        OptionsV1 memory decodedOptions = icTx.options.decodeOptionsV1();
        if (msg.value != decodedOptions.gasAirdrop) {
            revert InterchainClientV1__MsgValueMismatch(msg.value, decodedOptions.gasAirdrop);
        }
        // We should always use at least as much as the requested gas limit.
        // The executor can specify a higher gas limit if they wanted.
        if (decodedOptions.gasLimit > gasLimit) gasLimit = decodedOptions.gasLimit;
        // Check the the Executor has provided big enough gas limit for the whole transaction.
        uint256 gasLeft = gasleft();
        if (gasLeft <= gasLimit) {
            revert InterchainClientV1__GasLeftBelowMin(gasLeft, gasLimit);
        }
        // Pass the full msg.value to the app: we have already checked that it matches the requested gas airdrop.
        IInterchainApp(icTx.dstReceiver.bytes32ToAddress()).appReceive{gas: gasLimit, value: msg.value}({
            srcChainId: icTx.srcChainId,
            sender: icTx.srcSender,
            dbNonce: icTx.dbNonce,
            message: icTx.message
        });
        emit InterchainTransactionReceived({
            transactionId: transactionId,
            dbNonce: icTx.dbNonce,
            srcChainId: icTx.srcChainId,
            srcSender: icTx.srcSender,
            dstReceiver: icTx.dstReceiver
        });
    }

    /// @notice Writes the proof of execution for a transaction into the InterchainDB.
    /// @dev Will revert if the transaction has not been executed.
    /// @param transactionId    The ID of the transaction to write the proof for.
    /// @return dbNonce         The database nonce of the entry containing the written proof for transaction.
    function writeExecutionProof(bytes32 transactionId) external returns (uint64 dbNonce) {
        address executor = _txExecutor[transactionId];
        if (executor == address(0)) {
            revert InterchainClientV1__TxNotExecuted(transactionId);
        }
        bytes memory proof = abi.encode(transactionId, executor);
        dbNonce = IInterchainDB(INTERCHAIN_DB).writeEntry(keccak256(proof));
        emit ExecutionProofWritten({transactionId: transactionId, dbNonce: dbNonce, executor: executor});
    }

    // ═══════════════════════════════════════════════════ VIEWS ═══════════════════════════════════════════════════════

    /// @notice Determines if a transaction meets the criteria to be executed based on:
    /// - If approved modules have verified the entry in the InterchainDB
    /// - If the threshold of approved modules have been met
    /// - If the optimistic window has passed for all modules
    /// - If the Guard module (if opted in) has not submitted an entry that conflicts with the approved modules
    /// @dev Will revert with a specific error message if the transaction is not executable.
    /// @param encodedTx        The encoded transaction to check for executable status.
    function isExecutable(bytes calldata encodedTx) external view returns (bool) {
        InterchainTransaction memory icTx = _assertCorrectTransaction(encodedTx);
        // Check that options could be decoded
        icTx.options.decodeOptionsV1();
        bytes32 transactionId = keccak256(encodedTx);
        _assertExecutable(icTx, transactionId);
        return true;
    }

    /// @notice Returns the readiness status of a transaction to be executed.
    /// @dev Some of the possible statuses have additional arguments that are returned:
    /// - Ready: the transaction is ready to be executed.
    /// - AlreadyExecuted: the transaction has already been executed.
    ///   - `firstArg` is the transaction ID.
    /// - EntryAwaitingResponses: not enough responses have been received for the transaction.
    ///   - `firstArg` is the number of responses received.
    ///   - `secondArg` is the number of responses required.
    /// - EntryConflict: one of the modules have submitted a conflicting entry.
    ///   - `firstArg` is the address of the module.
    ///   - This is either one of the modules that the app trusts, or the Guard module used by the app.
    /// - ReceiverNotICApp: the receiver is not an Interchain app.
    ///  - `firstArg` is the receiver address.
    /// - TxWrongDstChainId: the destination chain ID does not match the local chain ID.
    ///   - `firstArg` is the destination chain ID.
    /// - UndeterminedRevert: the transaction will revert for another reason.
    ///
    /// Note: the arguments are abi-encoded bytes32 values (as their types could be different).
    // solhint-disable-next-line code-complexity
    function getTxReadinessV1(InterchainTransaction memory icTx)
        external
        view
        returns (TxReadiness status, bytes32 firstArg, bytes32 secondArg)
    {
        bytes memory encodedTx = encodeTransaction(icTx);
        try this.isExecutable(encodedTx) returns (bool) {
            return (TxReadiness.Ready, 0, 0);
        } catch (bytes memory errorData) {
            bytes4 selector;
            (selector, firstArg, secondArg) = _decodeRevertData(errorData);
            if (selector == InterchainClientV1__TxAlreadyExecuted.selector) {
                status = TxReadiness.AlreadyExecuted;
            } else if (selector == InterchainClientV1__ResponsesAmountBelowMin.selector) {
                status = TxReadiness.EntryAwaitingResponses;
            } else if (selector == InterchainClientV1__EntryConflict.selector) {
                status = TxReadiness.EntryConflict;
            } else if (selector == InterchainClientV1__ReceiverNotICApp.selector) {
                status = TxReadiness.ReceiverNotICApp;
            } else if (selector == InterchainClientV1__DstChainIdNotLocal.selector) {
                status = TxReadiness.TxWrongDstChainId;
            } else {
                status = TxReadiness.UndeterminedRevert;
                firstArg = 0;
                secondArg = 0;
            }
        }
    }

    /// @notice Returns the address of the executor for a transaction that has been sent to the local chain.
    function getExecutor(bytes calldata encodedTx) external view returns (address) {
        return _txExecutor[keccak256(encodedTx)];
    }

    /// @notice Returns the address of the executor for a transaction that has been sent to the local chain.
    function getExecutorById(bytes32 transactionId) external view returns (address) {
        return _txExecutor[transactionId];
    }

    /// @notice Returns the fee for sending an Interchain message.
    /// @param dstChainId           The chain ID of the destination chain.
    /// @param srcExecutionService  The address of the execution service to use for the message.
    /// @param srcModules           The source modules involved in the message sending.
    /// @param options              Execution options for the message sent, currently gas limit + native gas drop.
    /// @param messageLen           The length of the message being sent.
    function getInterchainFee(
        uint64 dstChainId,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        uint256 messageLen
    )
        external
        view
        returns (uint256 fee)
    {
        _assertLinkedClient(dstChainId);
        if (srcExecutionService == address(0)) {
            revert InterchainClientV1__ExecutionServiceZeroAddress();
        }
        // Check that options could be decoded on destination chain
        options.decodeOptionsV1();
        // Verification fee from InterchainDB
        fee = IInterchainDB(INTERCHAIN_DB).getInterchainFee(dstChainId, srcModules);
        // Add execution fee from ExecutionService
        uint256 payloadSize = InterchainTransactionLib.payloadSize(options.length, messageLen);
        fee += IExecutionService(srcExecutionService).getExecutionFee(dstChainId, payloadSize, options);
    }

    /// @notice Returns the address of the linked client (as bytes32) for a specific chain ID.
    /// @dev Will return 0x0 if no client is linked for the chain ID.
    function getLinkedClient(uint64 chainId) external view returns (bytes32) {
        if (chainId == block.chainid) {
            revert InterchainClientV1__ChainIdNotRemote(chainId);
        }
        return _linkedClient[chainId];
    }

    /// @notice Returns the EVM address of the linked client for a specific chain ID.
    /// @dev Will return 0x0 if no client is linked for the chain ID.
    /// Will revert if the client is not an EVM client.
    function getLinkedClientEVM(uint64 chainId) external view returns (address linkedClientEVM) {
        if (chainId == block.chainid) {
            revert InterchainClientV1__ChainIdNotRemote(chainId);
        }
        bytes32 linkedClient = _linkedClient[chainId];
        linkedClientEVM = linkedClient.bytes32ToAddress();
        // Check that the linked client address fits into the EVM address space
        if (linkedClientEVM.addressToBytes32() != linkedClient) {
            revert InterchainClientV1__LinkedClientNotEVM(linkedClient);
        }
    }

    /// @notice Decodes the encoded options data into a OptionsV1 struct.
    function decodeOptions(bytes memory encodedOptions) external view returns (OptionsV1 memory) {
        return encodedOptions.decodeOptionsV1();
    }

    /// @notice Gets the V1 app config and trusted modules for the receiving app.
    function getAppReceivingConfigV1(address receiver)
        public
        view
        returns (AppConfigV1 memory config, address[] memory modules)
    {
        // First, check that receiver is a contract
        if (receiver.code.length == 0) {
            revert InterchainClientV1__ReceiverNotICApp(receiver);
        }
        // Then, use a low-level static call to get the config and modules
        (bool success, bytes memory returnData) =
            receiver.staticcall(abi.encodeCall(IInterchainApp.getReceivingConfig, ()));
        if (!success || returnData.length == 0) {
            revert InterchainClientV1__ReceiverNotICApp(receiver);
        }
        bytes memory encodedConfig;
        (encodedConfig, modules) = abi.decode(returnData, (bytes, address[]));
        config = encodedConfig.decodeAppConfigV1();
        // Fallback to the default module if the app has no modules
        if (modules.length == 0) {
            modules = new address[](1);
            modules[0] = defaultModule;
        }
        // Fallback to "all responses" if the app requires zero responses
        if (config.requiredResponses == 0) {
            config.requiredResponses = modules.length;
        }
    }

    /// @notice Encodes the transaction data into a bytes format.
    function encodeTransaction(InterchainTransaction memory icTx) public pure returns (bytes memory) {
        return VersionedPayloadLib.encodeVersionedPayload({
            version: CLIENT_VERSION,
            payload: InterchainTransactionLib.encodeTransaction(icTx)
        });
    }

    // ═════════════════════════════════════════════════ INTERNAL ══════════════════════════════════════════════════════

    /// @dev Internal logic for sending a message to another chain.
    function _interchainSend(
        uint64 dstChainId,
        bytes32 receiver,
        address srcExecutionService,
        address[] calldata srcModules,
        bytes calldata options,
        bytes calldata message
    )
        internal
        returns (InterchainTxDescriptor memory desc)
    {
        _assertLinkedClient(dstChainId);
        if (receiver == 0) {
            revert InterchainClientV1__ReceiverZeroAddress();
        }
        if (srcExecutionService == address(0)) {
            revert InterchainClientV1__ExecutionServiceZeroAddress();
        }
        // Check that options could be decoded on destination chain
        options.decodeOptionsV1();
        uint256 verificationFee = IInterchainDB(INTERCHAIN_DB).getInterchainFee(dstChainId, srcModules);
        if (msg.value < verificationFee) {
            revert InterchainClientV1__FeeAmountBelowMin(msg.value, verificationFee);
        }
        desc.dbNonce = IInterchainDB(INTERCHAIN_DB).getDBNonce();
        InterchainTransaction memory icTx = InterchainTransactionLib.constructLocalTransaction({
            srcSender: msg.sender,
            dstReceiver: receiver,
            dstChainId: dstChainId,
            dbNonce: desc.dbNonce,
            options: options,
            message: message
        });
        desc.transactionId = keccak256(encodeTransaction(icTx));
        // Sanity check: nonce returned from DB should match the nonce used to construct the transaction
        {
            uint64 dbNonce = IInterchainDB(INTERCHAIN_DB).writeEntryRequestVerification{value: verificationFee}(
                icTx.dstChainId, desc.transactionId, srcModules
            );
            assert(dbNonce == desc.dbNonce);
        }
        uint256 executionFee;
        unchecked {
            executionFee = msg.value - verificationFee;
        }
        IExecutionService(srcExecutionService).requestTxExecution{value: executionFee}({
            dstChainId: icTx.dstChainId,
            txPayloadSize: InterchainTransactionLib.payloadSize(options.length, message.length),
            transactionId: desc.transactionId,
            options: options
        });
        emit InterchainTransactionSent({
            transactionId: desc.transactionId,
            dbNonce: desc.dbNonce,
            dstChainId: icTx.dstChainId,
            srcSender: icTx.srcSender,
            dstReceiver: icTx.dstReceiver,
            verificationFee: verificationFee,
            executionFee: executionFee,
            options: icTx.options,
            message: icTx.message
        });
    }

    // ══════════════════════════════════════════════ INTERNAL VIEWS ═══════════════════════════════════════════════════

    /// @dev Asserts that the transaction is executable.
    function _assertExecutable(InterchainTransaction memory icTx, bytes32 transactionId) internal view {
        bytes32 linkedClient = _assertLinkedClient(icTx.srcChainId);
        if (_txExecutor[transactionId] != address(0)) {
            revert InterchainClientV1__TxAlreadyExecuted(transactionId);
        }
        // Construct expected entry based on interchain transaction data
        InterchainEntry memory entry = InterchainEntry({
            srcChainId: icTx.srcChainId,
            dbNonce: icTx.dbNonce,
            entryValue: InterchainEntryLib.getEntryValue({srcWriter: linkedClient, digest: transactionId})
        });
        address receiver = icTx.dstReceiver.bytes32ToAddress();
        (AppConfigV1 memory appConfig, address[] memory approvedModules) = getAppReceivingConfigV1(receiver);
        // Note: appConfig.requiredResponses is never zero at this point, see fallbacks in `getAppReceivingConfigV1`
        // Verify against the Guard if the app opts in to use it
        address guard = _getGuard(appConfig);
        _assertNoGuardConflict(guard, entry);
        // Optimistic period is not used if there's no Guard configured
        uint256 optimisticPeriod = guard == address(0) ? 0 : appConfig.optimisticPeriod;
        uint256 finalizedResponses = _getFinalizedResponsesCount(approvedModules, entry, optimisticPeriod);
        if (finalizedResponses < appConfig.requiredResponses) {
            revert InterchainClientV1__ResponsesAmountBelowMin(finalizedResponses, appConfig.requiredResponses);
        }
    }

    /// @dev Asserts that the chain is linked and returns the linked client address.
    function _assertLinkedClient(uint64 chainId) internal view returns (bytes32 linkedClient) {
        if (chainId == block.chainid) {
            revert InterchainClientV1__ChainIdNotRemote(chainId);
        }
        linkedClient = _linkedClient[chainId];
        if (linkedClient == 0) {
            revert InterchainClientV1__ChainIdNotLinked(chainId);
        }
    }

    /// @dev Asserts that the Guard has not submitted a conflicting entry.
    function _assertNoGuardConflict(address guard, InterchainEntry memory entry) internal view {
        if (guard != address(0)) {
            uint256 confirmedAt = IInterchainDB(INTERCHAIN_DB).checkEntryVerification(guard, entry);
            if (confirmedAt == ENTRY_CONFLICT) {
                revert InterchainClientV1__EntryConflict(guard);
            }
        }
    }

    /// @dev Returns the Guard address to use for the given app config.
    function _getGuard(AppConfigV1 memory appConfig) internal view returns (address) {
        if (appConfig.guardFlag == APP_CONFIG_GUARD_DISABLED) {
            return address(0);
        }
        if (appConfig.guardFlag == APP_CONFIG_GUARD_DEFAULT) {
            return defaultGuard;
        }
        return appConfig.guard;
    }

    /// @dev Counts the number of finalized responses for the given entry.
    /// Note: Reverts if a conflicting entry has been verified by any of the approved modules.
    function _getFinalizedResponsesCount(
        address[] memory approvedModules,
        InterchainEntry memory entry,
        uint256 optimisticPeriod
    )
        internal
        view
        returns (uint256 finalizedResponses)
    {
        for (uint256 i = 0; i < approvedModules.length; ++i) {
            address module = approvedModules[i];
            uint256 confirmedAt = IInterchainDB(INTERCHAIN_DB).checkEntryVerification(module, entry);
            // No-op if the module has not verified anything with the same entry key
            if (confirmedAt == ENTRY_UNVERIFIED) {
                continue;
            }
            // Revert if the module has verified a conflicting entry with the same entry key
            if (confirmedAt == ENTRY_CONFLICT) {
                revert InterchainClientV1__EntryConflict(module);
            }
            // The module has verified this exact entry, check if optimistic period has passed
            if (confirmedAt + optimisticPeriod < block.timestamp) {
                unchecked {
                    ++finalizedResponses;
                }
            }
        }
    }

    /// @dev Asserts that the transaction version is correct and that the transaction is for the current chain.
    /// Note: returns the decoded transaction for chaining purposes.
    function _assertCorrectTransaction(bytes calldata versionedTx)
        internal
        view
        returns (InterchainTransaction memory icTx)
    {
        uint16 version = versionedTx.getVersion();
        if (version != CLIENT_VERSION) {
            revert InterchainClientV1__TxVersionMismatch(version, CLIENT_VERSION);
        }
        icTx = InterchainTransactionLib.decodeTransaction(versionedTx.getPayload());
        if (icTx.dstChainId != block.chainid) {
            revert InterchainClientV1__DstChainIdNotLocal(icTx.dstChainId);
        }
    }

    // solhint-disable no-inline-assembly
    /// @dev Decodes the revert data into a selector and two arguments.
    /// Zero values are returned if the revert data is not long enough.
    /// Note: this is only used in `getTxReadinessV1` to decode the revert data,
    /// so usage of assembly is not a security risk.
    function _decodeRevertData(bytes memory revertData)
        internal
        pure
        returns (bytes4 selector, bytes32 firstArg, bytes32 secondArg)
    {
        // The easiest way to load the bytes chunks onto the stack is to use assembly.
        // Each time we try to load a value, we check if the revert data is long enough.
        // We add 0x20 to skip the length field of the revert data.
        if (revertData.length >= 4) {
            // Load the first 32 bytes, then apply the mask that has only the 4 highest bytes set.
            // There is no need to shift, as `bytesN` variables are right-aligned.
            // https://github.com/ProjectOpenSea/seaport/blob/2ff6ea37/contracts/helpers/SeaportRouter.sol#L161-L175
            selector = bytes4(0xFFFFFFFF);
            assembly {
                selector := and(mload(add(revertData, 0x20)), selector)
            }
        }
        if (revertData.length >= 36) {
            // Skip the length field + selector to get the 32 bytes of the first argument.
            assembly {
                firstArg := mload(add(revertData, 0x24))
            }
        }
        if (revertData.length >= 68) {
            // Skip the length field + selector + first argument to get the 32 bytes of the second argument.
            assembly {
                secondArg := mload(add(revertData, 0x44))
            }
        }
    }
}
