// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

interface ISnapshotHub {
    /**
     * @notice Check that a given attestation is valid: matches the historical attestation
     * derived from an accepted Notary snapshot.
     * @dev Will revert if any of these is true:
     *  - Attestation payload is not properly formatted.
     * @param attPayload    Raw payload with attestation data
     * @return isValid      Whether the provided attestation is valid
     */
    function isValidAttestation(bytes memory attPayload) external view returns (bool isValid);

    /**
     * @notice Returns saved attestation with the given nonce.
     * @dev Reverts if attestation with given nonce hasn't been created yet.
     * @param nonce         Nonce for the attestation
     * @return attPayload   Raw payload with formatted Attestation data
     */
    function getAttestation(uint32 nonce) external view returns (bytes memory attPayload);

    /**
     * @notice Returns the state with the highest known nonce submitted by a given Agent.
     * @param origin        Domain of origin chain
     * @param agent         Agent address
     * @return statePayload Raw payload with agent's latest state for origin
     */
    function getLatestAgentState(uint32 origin, address agent) external view returns (bytes memory statePayload);

    /**
     * @notice Returns latest saved attestation for a Notary.
     * @param notary        Notary address
     * @return attPayload   Raw payload with formatted Attestation data
     */
    function getLatestNotaryAttestation(address notary) external view returns (bytes memory attPayload);

    /**
     * @notice Returns Guard snapshot for the list of all accepted Guard snapshots.
     * @dev Reverts if snapshot with given index hasn't been accepted yet.
     * @param index             Snapshot index in the list of all Guard snapshots
     * @return snapshotPayload  Raw payload with Guard snapshot
     */
    function getGuardSnapshot(uint256 index) external view returns (bytes memory snapshotPayload);

    /**
     * @notice Returns Notary snapshot that was used for creating an attestation with a given nonce.
     * @dev Reverts if attestation with given nonce hasn't been created yet.
     * @param nonce             Nonce for the attestation
     * @return snapshotPayload  Raw payload with Notary snapshot used for creating the attestation
     */
    function getNotarySnapshot(uint256 nonce) external view returns (bytes memory snapshotPayload);

    /**
     * @notice Returns Notary snapshot that was used for creating a given attestation.
     * @dev Reverts if any of these is true:
     *  - Attestation payload is not properly formatted.
     *  - Attestation is invalid (doesn't have a matching Notary snapshot).
     * @param attPayload        Raw payload with attestation data
     * @return snapshotPayload  Raw payload with Notary snapshot used for creating the attestation
     */
    function getNotarySnapshot(bytes memory attPayload) external view returns (bytes memory snapshotPayload);

    /**
     * @notice Returns proof of inclusion of (root, origin) fields of a given snapshot's state
     * into the Snapshot Merkle Tree for a given attestation.
     * @dev Reverts if any of these is true:
     *  - Attestation with given nonce hasn't been created yet.
     *  - State index is out of range of snapshot list.
     * @param nonce         Nonce for the attestation
     * @param stateIndex    Index of state in the attestation's snapshot
     * @return snapProof    The snapshot proof
     */
    function getSnapshotProof(uint256 nonce, uint256 stateIndex) external view returns (bytes32[] memory snapProof);
}
