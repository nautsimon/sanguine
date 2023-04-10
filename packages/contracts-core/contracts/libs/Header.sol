// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {ByteString} from "./ByteString.sol";
import {HEADER_LENGTH} from "./Constants.sol";
import {TypeCasts} from "./TypeCasts.sol";
import {TypedMemView} from "./TypedMemView.sol";

/// @dev Header is a memory over over a formatted message header payload.
type Header is bytes29;

/// @dev Attach library functions to Header
using HeaderLib for Header global;

/**
 * @notice Library for versioned formatting [the header part]
 * of [the messages used by Origin and Destination].
 */
library HeaderLib {
    using ByteString for bytes;
    using TypedMemView for bytes29;

    /**
     * @dev Header memory layout
     * [000 .. 004): origin             uint32   4 bytes    Domain where message originated
     * [004 .. 008): nonce              uint32   4 bytes    Message nonce on the origin domain
     * [008 .. 012): destination        uint32   4 bytes    Domain where message will be executed
     * [012 .. 016): optimisticPeriod   uint32   4 bytes    Optimistic period that will be enforced
     *
     * The variables below are not supposed to be used outside of the library directly.
     */

    uint256 private constant OFFSET_ORIGIN = 0;
    uint256 private constant OFFSET_NONCE = 4;
    uint256 private constant OFFSET_DESTINATION = 8;
    uint256 private constant OFFSET_OPTIMISTIC_SECONDS = 12;

    // ══════════════════════════════════════════════════ HEADER ═══════════════════════════════════════════════════════

    /**
     * @notice Returns a formatted Header payload with provided fields
     * @param origin_               Domain of origin chain
     * @param nonce_                Message nonce on origin chain
     * @param destination_          Domain of destination chain
     * @param optimisticPeriod_     Optimistic period for message execution
     * @return Formatted header
     */
    function formatHeader(uint32 origin_, uint32 nonce_, uint32 destination_, uint32 optimisticPeriod_)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(origin_, nonce_, destination_, optimisticPeriod_);
    }

    /**
     * @notice Returns a Header view over for the given payload.
     * @dev Will revert if the payload is not a header payload.
     */
    function castToHeader(bytes memory payload) internal pure returns (Header) {
        return castToHeader(payload.castToRawBytes());
    }

    /**
     * @notice Casts a memory view to a Header view.
     * @dev Will revert if the memory view is not over a header payload.
     */
    function castToHeader(bytes29 view_) internal pure returns (Header) {
        require(isHeader(view_), "Not a header payload");
        return Header.wrap(view_);
    }

    /**
     * @notice Checks that a payload is a formatted Header.
     */
    function isHeader(bytes29 view_) internal pure returns (bool) {
        return view_.len() == HEADER_LENGTH;
    }

    /// @notice Convenience shortcut for unwrapping a view.
    function unwrap(Header header) internal pure returns (bytes29) {
        return Header.unwrap(header);
    }

    // ══════════════════════════════════════════════ HEADER SLICING ═══════════════════════════════════════════════════

    /// @notice Returns header's origin field
    function origin(Header header) internal pure returns (uint32) {
        bytes29 view_ = unwrap(header);
        return uint32(view_.indexUint(OFFSET_ORIGIN, 4));
    }

    /// @notice Returns header's nonce field
    function nonce(Header header) internal pure returns (uint32) {
        bytes29 view_ = unwrap(header);
        return uint32(view_.indexUint(OFFSET_NONCE, 4));
    }

    /// @notice Returns header's destination field
    function destination(Header header) internal pure returns (uint32) {
        bytes29 view_ = unwrap(header);
        return uint32(view_.indexUint(OFFSET_DESTINATION, 4));
    }

    /// @notice Returns header's optimistic seconds field
    function optimisticPeriod(Header header) internal pure returns (uint32) {
        bytes29 view_ = unwrap(header);
        return uint32(view_.indexUint(OFFSET_OPTIMISTIC_SECONDS, 4));
    }
}
