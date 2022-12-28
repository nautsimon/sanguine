// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "../../contracts/bonding/BondingMVP.sol";
import "../../contracts/bonding/BondingPrimary.sol";
import "../../contracts/bonding/BondingSecondary.sol";
import "../../contracts/libs/SystemCall.sol";
import "../../contracts/libs/Report.sol";
import "./SynapseTestStorage.t.sol";
import "./SynapseUtilities.t.sol";

contract SynapseTestSuite is SynapseUtilities, SynapseTestStorage {
    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                                SETUP                                 ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function setUp() public virtual {
        setupAgents();
        for (uint256 d = 0; d < DOMAINS; ++d) {
            setupChain(domains[d], domainNames[d]);
        }
        setupContext();
    }

    function setupAgents() public {
        domains = new uint32[](DOMAINS);
        domainNames = new string[](DOMAINS);
        domains[0] = DOMAIN_SYNAPSE;
        domains[1] = DOMAIN_LOCAL;
        domains[2] = DOMAIN_REMOTE;
        domainNames[0] = "SynChain";
        domainNames[1] = "Local";
        domainNames[2] = "Remote";
        // Create notaries
        for (uint256 domainIndex = 0; domainIndex < DOMAINS; ++domainIndex) {
            for (uint256 notaryIndex = 0; notaryIndex < NOTARIES_PER_CHAIN; ++notaryIndex) {
                uint32 domain = domains[domainIndex];
                uint256 notaryPK = generatePrivateKey(
                    abi.encode("notary", domainIndex, notaryIndex)
                );
                address notary = registerPK(notaryPK);
                vm.label(
                    notary,
                    string.concat("Notary ", domainNames[domainIndex], getActorSuffix(notaryIndex))
                );
                chains[domain].notaries.push(notary);
            }
        }
        // Create guards
        for (uint256 guardIndex = 0; guardIndex < GUARDS; ++guardIndex) {
            uint256 guardPK = generatePrivateKey(abi.encode("guard", guardIndex));
            address guard = registerPK(guardPK);
            vm.label(guard, string.concat("Guard", getActorSuffix(guardIndex)));
            guards.push(guard);
        }
        // Create owner
        owner = registerActor("Owner");
        // Create proxy admin
        proxyAdmin = registerActor("Proxy admin");
        // Create attacker
        attacker = registerActor("The Attackooor");
        // Create user
        user = registerActor("The Bridgooor");
        // Create broadcaster
        broadcaster = registerActor("Broadcaster");
        // Deploy proof generator
        clearMerkleTree();
    }

    // All contracts are deployed by this contract, the ownership is then transferred to `owner`
    // solhint-disable-next-line code-complexity
    function setupChain(uint32 domain, string memory chainName) public {
        // Deploy messaging contracts
        DestinationHarness destination = new DestinationHarness(domain);
        OriginHarness origin = new OriginHarness(domain);
        BondingMVP bondingManager = new BondingMVP(domain);
        SystemRouterHarness systemRouter = new SystemRouterHarness(
            domain,
            address(origin),
            address(destination),
            address(bondingManager)
        );
        // Setup destination
        destination.initialize();
        destination.setSystemRouter(systemRouter);
        // Setup origin
        origin.initialize();
        origin.setSystemRouter(systemRouter);
        // Setup BondingManager
        bondingManager.initialize();
        bondingManager.setSystemRouter(systemRouter);
        // Add global notaries via BondingManager
        for (uint256 i = 0; i < DOMAINS; ++i) {
            uint32 domainToAdd = domains[i];
            // Origin and Destination will filter our agents themselves
            for (uint256 j = 0; j < NOTARIES_PER_CHAIN; ++j) {
                address notary = suiteNotary(domainToAdd, j);
                bondingManager.addAgent(domainToAdd, notary);
            }
        }
        // Add guards  via BondingManager
        for (uint256 i = 0; i < GUARDS; ++i) {
            bondingManager.addAgent({ _domain: 0, _account: guards[i] });
        }
        // Deploy app
        AppHarness app = new AppHarness(APP_OPTIMISTIC_SECONDS);
        // Transfer ownership everywhere
        destination.transferOwnership(owner);
        origin.transferOwnership(owner);
        bondingManager.transferOwnership(owner);
        // Label deployments
        vm.label(address(destination), string.concat("Destination ", chainName));
        vm.label(address(origin), string.concat("Origin ", chainName));
        vm.label(address(bondingManager), string.concat("BondingManager ", chainName));
        vm.label(address(systemRouter), string.concat("SystemRouter ", chainName));
        vm.label(address(app), string.concat("App ", chainName));
        // Save deployments
        chains[domain].destination = destination;
        chains[domain].origin = origin;
        chains[domain].bondingManager = bondingManager;
        chains[domain].systemRouter = systemRouter;
        chains[domain].app = app;
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                             ATTESTATIONS                             ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    /**
     * @notice Attestation signed by the default Guard and chain's default Notary.
     */
    function signAttestation(
        uint32 origin,
        uint32 destination,
        uint32 nonce,
        bytes32 root
    )
        public
        returns (
            bytes memory attestation,
            bytes memory guardSignatures,
            bytes memory notarySignatures
        )
    {
        return signAttestation(origin, destination, nonce, root, 0, 0);
    }

    /**
     * @notice Attestation signed by a given suite Guard and
     * a given suite Notary for the destination chain.
     * @dev Use indexes out of bound to not include any of the signers.
     */
    function signAttestation(
        uint32 origin,
        uint32 destination,
        uint32 nonce,
        bytes32 root,
        uint256 guardIndex,
        uint256 notaryIndex
    )
        public
        returns (
            bytes memory attestation,
            bytes memory guardSignatures,
            bytes memory notarySignatures
        )
    {
        return
            signAttestation(
                origin,
                destination,
                nonce,
                root,
                suiteGuard(guardIndex),
                suiteNotary(destination, notaryIndex)
            );
    }

    /**
     * @notice Attestation signed by a given Guard and Notary.
     * @dev Use address(0) to not include any of the signers
     */
    function signAttestation(
        uint32 origin,
        uint32 destination,
        uint32 nonce,
        bytes32 root,
        address guardSigner,
        address notarySigner
    )
        public
        returns (
            bytes memory attestation,
            bytes memory guardSignatures,
            bytes memory notarySignatures
        )
    {
        // castToArray() will return empty array for address(0)
        return
            signAttestation(
                origin,
                destination,
                nonce,
                root,
                castToArray(guardSigner),
                castToArray(notarySigner)
            );
    }

    function signAttestation(
        uint32 origin,
        uint32 destination,
        uint32 nonce,
        bytes32 root,
        address[] memory guardSigners,
        address[] memory notarySigners
    )
        public
        returns (
            bytes memory attestation,
            bytes memory guardSignatures,
            bytes memory notarySignatures
        )
    {
        bytes memory data = Attestation.formatAttestationData(origin, destination, nonce, root);
        guardSignatures = signMessage(guardSigners, data);
        notarySignatures = signMessage(notarySigners, data);
        attestation = Attestation.formatAttestation(data, guardSignatures, notarySignatures);
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                               REPORTS                                ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    /**
     * @notice Report signed by the default Guard.
     */
    function signReport(Report.Flag flag, bytes memory attestation)
        public
        returns (bytes memory report, bytes memory signature)
    {
        return signReport(flag, attestation, suiteGuard());
    }

    /**
     * @notice Report signed by a given Guard.
     */
    function signReport(
        Report.Flag flag,
        bytes memory attestation,
        uint256 guardIndex
    ) public returns (bytes memory report, bytes memory signature) {
        return signReport(flag, attestation, suiteGuard(guardIndex));
    }

    /**
     * @notice Report signed by a given signer.
     */
    function signReport(
        Report.Flag flag,
        bytes memory attestation,
        address signer
    ) public returns (bytes memory report, bytes memory signature) {
        bytes memory data = Report.formatReportData(flag, attestation);
        signature = signMessage(signer, data);
        report = Report.formatReport(flag, attestation, signature);
    }

    /*╔══════════════════════════════════════════════════════════════════════╗*\
    ▏*║                               SIGNING                                ║*▕
    \*╚══════════════════════════════════════════════════════════════════════╝*/

    function signMessage(uint256 privKey, bytes memory message)
        public
        returns (bytes memory signature)
    {
        bytes32 digest = keccak256(message);
        digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function signMessage(address signer, bytes memory message)
        public
        returns (bytes memory signature)
    {
        uint256 privKey = privKeys[signer];
        require(privKey != 0, "Unknown account");
        return signMessage(privKey, message);
    }

    function signMessage(uint256[] memory keys, bytes memory message)
        public
        returns (bytes memory signatures)
    {
        for (uint256 i = 0; i < keys.length; ++i) {
            // There probably exists a more efficient way to do this without relying on TypedMemView
            signatures = bytes.concat(signatures, signMessage(keys[i], message));
        }
    }

    function signMessage(address[] memory signers, bytes memory message)
        public
        returns (bytes memory signatures)
    {
        for (uint256 i = 0; i < signers.length; ++i) {
            // There probably exists a more efficient way to do this without relying on TypedMemView
            signatures = bytes.concat(signatures, signMessage(signers[i], message));
        }
    }

    function registerPK(uint256 privKey) public returns (address account) {
        account = vm.addr(privKey);
        // Save priv key for later usage
        privKeys[account] = privKey;
    }

    function registerActor(string memory actorName) public returns (address account) {
        account = registerPK(generatePrivateKey(abi.encode(actorName)));
        vm.label(account, actorName);
    }
}
