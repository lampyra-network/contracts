// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {WorkerRegistry} from "../src/WorkerRegistry.sol";
import {MockPYRA} from "./mocks/MockPYRA.sol";
import {PyraAdmin} from "../src/PyraAdmin.sol";

/// @notice WorkerRegistry suite: 37 numbered behaviour cases (kept in file
///         order with stable names), plus the gap cases the numbered set left
///         untested and the proxy-level cases (initializer, UUPS upgrade auth,
///         per-function role gates).
///
///         Actors: superAdmin holds DEFAULT_ADMIN_ROLE (the super admin),
///         opsAdmin holds ADMIN_ROLE for day-to-day moderation, orchestrator
///         holds ORCHESTRATOR_ROLE, alice and bob are worker wallets, and
///         attacker holds no roles at all.
contract WorkerRegistryTest is Test {
    // Roles (mirror PyraAdmin)
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 internal constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 internal constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    // ERC1967 implementation slot
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Tiers / statuses / codecs (mirror the contract constants)
    uint8 internal constant TIER_NONE = 0;
    uint8 internal constant TIER_BRONZE = 1;
    uint8 internal constant TIER_SILVER = 2;
    uint8 internal constant TIER_GOLD = 3;
    uint8 internal constant TIER_PLATINUM = 4;

    uint8 internal constant STATUS_INACTIVE = 0;
    uint8 internal constant STATUS_ACTIVE = 1;
    uint8 internal constant STATUS_SUSPENDED = 2;
    uint8 internal constant STATUS_BANNED = 3;

    uint8 internal constant CODEC_H264 = 0x01;
    uint8 internal constant CODEC_HEVC = 0x02;
    uint8 internal constant CODEC_VP9 = 0x04;
    uint8 internal constant CODEC_AV1 = 0x08;

    // Tier requirements (base units, 9 decimals) — mirror the defaults
    uint256 internal constant BRONZE_REQUIREMENT = 100_000 * 1e9;
    uint256 internal constant SILVER_REQUIREMENT = 500_000 * 1e9;
    uint256 internal constant GOLD_REQUIREMENT = 2_500_000 * 1e9;
    uint256 internal constant PLATINUM_REQUIREMENT = 10_000_000 * 1e9;

    // Default capability fixture shared by every registration in this suite
    uint8 internal constant GPU_TYPE = 1;
    bytes32 internal constant GPU_MODEL_HASH = bytes32(uint256(0xABCD));
    uint16 internal constant GPU_MEMORY_GB = 24;
    uint8 internal constant CPU_CORES = 16;
    uint8 internal constant PROCESSING_TYPE = 1;
    uint8 internal constant SUPPORTED_CODECS = 0x0F;
    uint8 internal constant MAX_CONCURRENT = 4;
    uint16 internal constant REGION = 1;
    uint64 internal constant TIMESTAMP = 1_700_000_000;

    bytes internal constant NODE_A = "node-a";
    bytes internal constant NODE_B = "node-b";

    PyraAdmin internal admin;
    MockPYRA internal token;
    WorkerRegistry internal registry;

    address internal superAdmin;
    address internal opsAdmin;
    address internal orchestrator;
    address internal alice; // worker wallet 1
    address internal bob; // worker wallet 2
    address internal attacker; // stranger: no roles at all

    function setUp() public {
        superAdmin = makeAddr("superAdmin");
        opsAdmin = makeAddr("opsAdmin");
        orchestrator = makeAddr("orchestrator");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");

        admin = new PyraAdmin(0, superAdmin);
        token = new MockPYRA(address(this)); // test contract holds the supply

        WorkerRegistry impl = new WorkerRegistry();
        registry = WorkerRegistry(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(WorkerRegistry.initialize, (address(admin), address(token)))
                )
            )
        );

        vm.startPrank(superAdmin);
        admin.grantRole(ADMIN_ROLE, opsAdmin);
        admin.grantRole(ORCHESTRATOR_ROLE, orchestrator);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    function _defaultCaps() internal pure returns (WorkerRegistry.WorkerCapabilities memory) {
        return WorkerRegistry.WorkerCapabilities({
            gpuModelHash: GPU_MODEL_HASH,
            gpuType: GPU_TYPE,
            gpuMemoryGb: GPU_MEMORY_GB,
            cpuCores: CPU_CORES,
            processingType: PROCESSING_TYPE,
            supportedCodecs: SUPPORTED_CODECS,
            maxConcurrent: MAX_CONCURRENT,
            region: REGION
        });
    }

    function _registerAs(address caller, address wallet, bytes memory nodeId) internal {
        vm.prank(caller);
        registry.register(wallet, nodeId, _defaultCaps(), TIMESTAMP);
    }

    /// @dev The default registration path: admin-registered, default caps.
    function _registerNode(address wallet, bytes memory nodeId) internal {
        _registerAs(opsAdmin, wallet, nodeId);
    }

    /// @dev Sets `wallet`'s PYRA balance to exactly `amount`.
    function _setBalance(address wallet, uint256 amount) internal {
        uint256 cur = token.balanceOf(wallet);
        if (cur < amount) {
            token.transfer(wallet, amount - cur);
        } else if (cur > amount) {
            vm.prank(wallet);
            token.transfer(address(this), cur - amount);
        }
    }

    function _updateTier(address wallet, bytes memory nodeId) internal {
        vm.prank(opsAdmin);
        registry.updateWorkerTier(wallet, nodeId, TIMESTAMP);
    }

    /// @dev Funds the wallet to `balance` and runs a tier refresh.
    function _activateAt(address wallet, bytes memory nodeId, uint256 balance) internal {
        _setBalance(wallet, balance);
        _updateTier(wallet, nodeId);
    }

    function _worker(address wallet, bytes memory nodeId) internal view returns (WorkerRegistry.Worker memory) {
        return registry.getWorker(wallet, nodeId);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Numbered behaviour cases 1–37 (stable names, file order)
    // ─────────────────────────────────────────────────────────────────────

    /// 1. Baseline registration: counters, lookup flags, and stored fields.
    function test_register_worker() public {
        _registerNode(alice, NODE_A);

        assertEq(registry.totalWorkers(), 1);
        assertEq(registry.activeWorkers(), 0);
        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.isNodeRegistered(alice, NODE_A));

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_NONE);
        assertEq(w.status, STATUS_INACTIVE);
        assertEq(w.wallet, alice);
        assertEq(w.nodeId, NODE_A);
        assertEq(w.registeredAt, TIMESTAMP);
        assertEq(w.lastVerified, 0);
        assertEq(w.verifiedBalance, 0);
        assertEq(w.capabilities.gpuType, GPU_TYPE);
        assertEq(w.capabilities.gpuModelHash, GPU_MODEL_HASH);
        assertEq(w.capabilities.supportedCodecs, SUPPORTED_CODECS);
    }

    /// 2. The same (wallet, nodeId) cannot be registered twice
    ///    (WorkerAlreadyRegistered).
    function test_cannot_register_same_wallet_node_twice() public {
        _registerNode(alice, NODE_A);
        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.WorkerAlreadyRegistered.selector, alice, NODE_A));
        registry.register(alice, NODE_A, _defaultCaps(), TIMESTAMP);
    }

    /// 3. One wallet may register several distinct nodes (multi-node-per-wallet).
    function test_register_same_wallet_different_nodes() public {
        _registerNode(alice, NODE_A);
        _registerNode(alice, NODE_B);

        assertEq(registry.totalWorkers(), 2);
        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.isNodeRegistered(alice, NODE_A));
        assertTrue(registry.isNodeRegistered(alice, NODE_B));
        assertEq(registry.walletNodeCount(alice), 2);
    }

    /// 4. A tier refresh auto-activates at exactly the Bronze boundary.
    ///    Also pins the observable event ordering: StatusChanged BEFORE TierUpdated.
    function test_update_tier_auto_activates_at_bronze() public {
        _registerNode(alice, NODE_A);
        _setBalance(alice, BRONZE_REQUIREMENT);

        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_INACTIVE, STATUS_ACTIVE);
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerTierUpdated(alice, NODE_A, TIER_NONE, TIER_BRONZE, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.updateWorkerTier(alice, NODE_A, TIMESTAMP);

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_BRONZE);
        assertEq(w.status, STATUS_ACTIVE);
        assertEq(w.verifiedBalance, BRONZE_REQUIREMENT);
        assertEq(w.lastVerified, TIMESTAMP);
        assertEq(registry.activeWorkers(), 1);
    }

    /// 5. A tier refresh auto-deactivates once the tier falls to NONE.
    function test_update_tier_auto_deactivates_at_none() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        assertEq(_worker(alice, NODE_A).status, STATUS_ACTIVE);
        assertEq(registry.activeWorkers(), 1);

        _setBalance(alice, 0);
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_ACTIVE, STATUS_INACTIVE);
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerTierUpdated(alice, NODE_A, TIER_BRONZE, TIER_NONE, 0);
        _updateTier(alice, NODE_A);

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_NONE);
        assertEq(w.status, STATUS_INACTIVE);
        assertEq(registry.activeWorkers(), 0);
    }

    /// 6. Suspending an already-SUSPENDED worker reverts
    ///    (InvalidStatusTransition).
    function test_suspend_already_suspended_worker_fails() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(WorkerRegistry.InvalidStatusTransition.selector, STATUS_SUSPENDED, STATUS_SUSPENDED)
        );
        registry.suspendWorker(alice, NODE_A);
    }

    /// 7. Suspending a BANNED worker reverts (InvalidStatusTransition): a ban
    ///    is terminal, not a state you can step down from.
    function test_suspend_banned_worker_fails() public {
        _registerNode(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(WorkerRegistry.InvalidStatusTransition.selector, STATUS_BANNED, STATUS_SUSPENDED)
        );
        registry.suspendWorker(alice, NODE_A);
    }

    /// 8. Ban sets the node status to BANNED and records the wallet-level
    ///    banned flag.
    function test_ban_worker_sets_status_and_populates_banned_table() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        assertEq(registry.activeWorkers(), 1);

        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_ACTIVE, STATUS_BANNED);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);

        assertEq(_worker(alice, NODE_A).status, STATUS_BANNED);
        assertTrue(registry.isBanned(alice));
        assertEq(registry.activeWorkers(), 0);
    }

    /// 9. Banning one node blocks new registrations for the whole wallet
    ///    (WorkerBanned) — the ban is per-wallet, not per-node.
    function test_ban_one_node_blocks_new_registrations_for_wallet() public {
        _registerNode(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.WorkerBanned.selector, alice));
        registry.register(alice, NODE_B, _defaultCaps(), TIMESTAMP);
    }

    /// 10. A banned wallet can never re-register — the banned flag survives
    ///     deregistration (WorkerBanned).
    function test_banned_worker_cannot_reregister() public {
        _registerNode(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.deregister(alice, NODE_A);

        assertEq(registry.totalWorkers(), 0);
        assertFalse(registry.isRegistered(alice));
        assertTrue(registry.isBanned(alice)); // never cleared

        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.WorkerBanned.selector, alice));
        registry.register(alice, NODE_A, _defaultCaps(), TIMESTAMP);
    }

    /// 11. Reactivate requires SUSPENDED status — pins the quirky error reuse:
    ///     non-SUSPENDED reverts WorkerNotRegistered, NOT
    ///     InvalidStatusTransition.
    function test_reactivate_requires_suspended_status() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT); // status ACTIVE

        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.WorkerNotRegistered.selector, alice, NODE_A));
        registry.reactivateWorker(alice, NODE_A);
    }

    /// 12. Reactivate requires at least Bronze tier (InvalidTier).
    function test_reactivate_requires_bronze_tier() public {
        _registerNode(alice, NODE_A);
        // INACTIVE → SUSPENDED is a valid transition
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);
        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.status, STATUS_SUSPENDED);
        assertEq(w.tier, TIER_NONE);

        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.InvalidTier.selector, TIER_NONE));
        registry.reactivateWorker(alice, NODE_A);
    }

    /// 13. A SUSPENDED worker holding Bronze reactivates back to ACTIVE.
    function test_reactivate_suspended_worker_with_bronze_tier() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);
        assertEq(_worker(alice, NODE_A).status, STATUS_SUSPENDED);
        assertEq(registry.activeWorkers(), 0);

        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_SUSPENDED, STATUS_ACTIVE);
        vm.prank(opsAdmin);
        registry.reactivateWorker(alice, NODE_A);

        assertEq(_worker(alice, NODE_A).status, STATUS_ACTIVE);
        assertEq(registry.activeWorkers(), 1);
    }

    /// 14. Admin deregistration — the last node drops the wallet's bookkeeping.
    function test_deregister_by_admin() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        assertEq(registry.activeWorkers(), 1);

        vm.prank(opsAdmin);
        registry.deregister(alice, NODE_A);

        assertEq(registry.totalWorkers(), 0);
        assertEq(registry.activeWorkers(), 0);
        assertFalse(registry.isRegistered(alice));
        assertFalse(registry.isNodeRegistered(alice, NODE_A));
    }

    /// 15. Deregistering one of two nodes keeps the wallet's remaining node
    ///     registered and its per-wallet bookkeeping alive.
    function test_deregister_one_of_two_nodes_keeps_wallet_inner_table() public {
        _registerNode(alice, NODE_A);
        _registerNode(alice, NODE_B);
        registry.getWorkerId(alice, NODE_A); // lookup succeeds while registered

        vm.prank(opsAdmin);
        registry.deregister(alice, NODE_A);

        assertEq(registry.totalWorkers(), 1);
        assertTrue(registry.isRegistered(alice)); // node-b still there
        assertFalse(registry.isNodeRegistered(alice, NODE_A));
        assertTrue(registry.isNodeRegistered(alice, NODE_B));
        assertEq(registry.walletNodeCount(alice), 1);
    }

    /// 16. A caller with no roles cannot register (NotAuthorized).
    function test_non_admin_cannot_register() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ORCHESTRATOR_ROLE, alice));
        registry.register(alice, NODE_A, _defaultCaps(), TIMESTAMP);
    }

    /// 17. Tier refresh is role-gated (NotAuthorized) — even the worker's own
    ///     wallet cannot refresh its tier.
    function test_non_admin_cannot_update_tier() public {
        _registerNode(alice, NODE_A);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ORCHESTRATOR_ROLE, alice));
        registry.updateWorkerTier(alice, NODE_A, TIMESTAMP);
    }

    /// 18. A non-admin cannot suspend a worker (NotAuthorized).
    function test_non_admin_cannot_suspend() public {
        _registerNode(alice, NODE_A);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ADMIN_ROLE, bob));
        registry.suspendWorker(alice, NODE_A);
    }

    /// 19. A non-admin cannot ban a worker (NotAuthorized).
    function test_non_admin_cannot_ban() public {
        _registerNode(alice, NODE_A);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ADMIN_ROLE, bob));
        registry.banWorker(alice, NODE_A);
    }

    /// 20. Deregistration is admin-only: even the OWNING wallet cannot
    ///     deregister itself (NotAuthorized).
    function test_non_admin_cannot_deregister() public {
        _registerNode(alice, NODE_A);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ADMIN_ROLE, alice));
        registry.deregister(alice, NODE_A);
    }

    /// 21. INACTIVE → SUSPENDED is a valid transition, with no counter underflow.
    function test_suspend_inactive_worker() public {
        _registerNode(alice, NODE_A);

        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_INACTIVE, STATUS_SUSPENDED);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);

        assertEq(_worker(alice, NODE_A).status, STATUS_SUSPENDED);
        assertEq(registry.activeWorkers(), 0);
    }

    /// 22. Upgrading straight to Silver — auto-activate fires for ANY
    ///     tier ≥ Bronze, not just Bronze.
    function test_tier_upgrade_to_silver() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, SILVER_REQUIREMENT);

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_SILVER);
        assertEq(w.status, STATUS_ACTIVE);
    }

    /// 23. Banning an already-BANNED worker reverts (InvalidStatusTransition).
    function test_ban_already_banned_worker_fails() public {
        _registerNode(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(WorkerRegistry.InvalidStatusTransition.selector, STATUS_BANNED, STATUS_BANNED)
        );
        registry.banWorker(alice, NODE_A);
    }

    /// 24. An admin can update capabilities — wholesale replacement of every
    ///     field, no partial merge.
    function test_admin_can_update_capabilities() public {
        _registerNode(alice, NODE_A);

        vm.prank(opsAdmin);
        registry.updateCapabilities(
            alice,
            NODE_A,
            WorkerRegistry.WorkerCapabilities({
                gpuModelHash: bytes32(uint256(0xDEAD)),
                gpuType: 2,
                gpuMemoryGb: 48,
                cpuCores: 32,
                processingType: 1,
                supportedCodecs: 0x0B,
                maxConcurrent: 8,
                region: 2
            })
        );

        WorkerRegistry.WorkerCapabilities memory caps = _worker(alice, NODE_A).capabilities;
        assertEq(caps.gpuType, 2);
        assertEq(caps.gpuModelHash, bytes32(uint256(0xDEAD)));
        assertEq(caps.gpuMemoryGb, 48);
        assertEq(caps.cpuCores, 32);
        assertEq(caps.processingType, 1);
        assertEq(caps.supportedCodecs, 0x0B);
        assertEq(caps.maxConcurrent, 8);
        assertEq(caps.region, 2);
    }

    /// 25. A non-admin cannot update capabilities — no wallet-signed
    ///     self-update path exists (NotAuthorized).
    function test_non_admin_cannot_update_capabilities() public {
        _registerNode(alice, NODE_A);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ORCHESTRATOR_ROLE, alice));
        registry.updateCapabilities(alice, NODE_A, _defaultCaps());
    }

    /// 26. Multiple workers register — the same nodeId under different
    ///     wallets is two independent workers.
    function test_multiple_workers_register() public {
        _registerNode(alice, NODE_A);
        _registerNode(bob, NODE_A);

        assertEq(registry.totalWorkers(), 2);
        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.isRegistered(bob));
        assertTrue(registry.isNodeRegistered(alice, NODE_A));
        assertTrue(registry.isNodeRegistered(bob, NODE_A));
    }

    /// 27. Suspending an ACTIVE worker decrements the active counter.
    function test_suspend_active_worker_decrements_active_count() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        assertEq(registry.activeWorkers(), 1);

        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);

        assertEq(_worker(alice, NODE_A).status, STATUS_SUSPENDED);
        assertEq(registry.activeWorkers(), 0);
    }

    /// 28. A tier update does not affect a suspended worker's status —
    ///     tier still updates on a suspended worker; status stays SUSPENDED.
    function test_tier_update_does_not_affect_suspended_worker_status() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);

        _setBalance(alice, SILVER_REQUIREMENT);
        _updateTier(alice, NODE_A);

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_SILVER);
        assertEq(w.status, STATUS_SUSPENDED);
        assertEq(registry.activeWorkers(), 0);
    }

    /// 29. Node lookup helpers — views never revert on unknown keys.
    function test_node_lookup_helpers() public {
        _registerNode(alice, NODE_A);
        _registerNode(alice, NODE_B);

        assertTrue(registry.isNodeRegistered(alice, NODE_A));
        assertTrue(registry.isNodeRegistered(alice, NODE_B));
        assertFalse(registry.isNodeRegistered(alice, bytes("node-missing")));
        assertFalse(registry.isNodeRegistered(bob, NODE_A)); // unknown wallet: no revert
        assertFalse(registry.isRegistered(bob));
        assertTrue(registry.getWorkerId(alice, NODE_A) != registry.getWorkerId(alice, NODE_B));
    }

    /// 30. getWorkerId reverts for an unknown wallet — plus the
    ///     second stage: known wallet, unknown node (WorkerNotRegistered both).
    function test_get_worker_id_reverts_for_unknown_wallet() public {
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.WorkerNotRegistered.selector, alice, NODE_A));
        registry.getWorkerId(alice, NODE_A);

        _registerNode(alice, NODE_A);
        vm.expectRevert(
            abi.encodeWithSelector(WorkerRegistry.WorkerNotRegistered.selector, alice, bytes("node-missing"))
        );
        registry.getWorkerId(alice, bytes("node-missing"));
    }

    /// 31. The orchestrator can register a worker — the least-privilege
    ///     role registers on behalf of a connecting agent (role granted in setUp).
    function test_orchestrator_can_register_worker() public {
        _registerAs(orchestrator, alice, NODE_A);

        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.isNodeRegistered(alice, NODE_A));
    }

    /// 32. A stranger holding no roles cannot register a worker (NotAuthorized).
    function test_stranger_cannot_register_worker() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ORCHESTRATOR_ROLE, attacker));
        registry.register(alice, NODE_A, _defaultCaps(), TIMESTAMP);
    }

    /// 33. The orchestrator can update capabilities for a node it registered.
    function test_orchestrator_can_update_capabilities() public {
        _registerAs(orchestrator, alice, NODE_A);

        vm.prank(orchestrator);
        registry.updateCapabilities(
            alice,
            NODE_A,
            WorkerRegistry.WorkerCapabilities({
                gpuModelHash: bytes32(uint256(0xDEAD)),
                gpuType: 2,
                gpuMemoryGb: 48,
                cpuCores: 32,
                processingType: 1,
                supportedCodecs: 0x0B,
                maxConcurrent: 22,
                region: 2
            })
        );

        WorkerRegistry.WorkerCapabilities memory caps = _worker(alice, NODE_A).capabilities;
        assertEq(caps.maxConcurrent, 22);
        assertEq(caps.supportedCodecs, 0x0B);
    }

    /// 34. A stranger holding no roles cannot update capabilities (NotAuthorized).
    function test_stranger_cannot_update_capabilities() public {
        _registerNode(alice, NODE_A);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ORCHESTRATOR_ROLE, attacker));
        registry.updateCapabilities(alice, NODE_A, _defaultCaps());
    }

    /// 35. setTierThresholds accepts strictly ascending thresholds.
    function test_set_tier_thresholds_accepts_ascending() public {
        vm.prank(superAdmin);
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);

        assertEq(registry.bronzeThreshold(), 1_000);
        assertEq(registry.silverThreshold(), 2_000);
        assertEq(registry.goldThreshold(), 3_000);
        assertEq(registry.platinumThreshold(), 4_000);
    }

    /// 36. setTierThresholds rejects a non-ascending set (InvalidTierThresholds).
    function test_set_tier_thresholds_rejects_non_ascending() public {
        vm.prank(superAdmin);
        vm.expectRevert(WorkerRegistry.InvalidTierThresholds.selector);
        registry.setTierThresholds(1_000, 1_000, 3_000, 4_000); // silver not > bronze
    }

    /// 37. setTierThresholds rejects a caller that is not the super admin
    ///     (NotAuthorized).
    function test_set_tier_thresholds_non_super_admin_fails() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, attacker));
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Gap cases the spec calls for but the numbered set never covered (spec §7)
    // ─────────────────────────────────────────────────────────────────────

    /// Tier refresh on a BANNED worker: scalar fields update, status never flips.
    function test_update_tier_on_banned_worker_updates_fields_but_not_status() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);
        assertEq(registry.activeWorkers(), 0);

        _setBalance(alice, SILVER_REQUIREMENT);
        vm.recordLogs();
        _updateTier(alice, NODE_A);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Only WorkerTierUpdated — no status event for a banned worker.
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("WorkerTierUpdated(address,bytes,uint8,uint8,uint256)"));

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_SILVER);
        assertEq(w.verifiedBalance, SILVER_REQUIREMENT);
        assertEq(w.status, STATUS_BANNED);
        assertEq(registry.activeWorkers(), 0);
    }

    /// A SUSPENDED worker CAN be banned; the active counter is untouched
    /// (it was already not counted).
    function test_ban_suspended_worker() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);
        assertEq(registry.activeWorkers(), 0);

        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerStatusChanged(alice, NODE_A, STATUS_SUSPENDED, STATUS_BANNED);
        vm.prank(opsAdmin);
        registry.banWorker(alice, NODE_A);

        assertEq(_worker(alice, NODE_A).status, STATUS_BANNED);
        assertTrue(registry.isBanned(alice));
        assertEq(registry.activeWorkers(), 0);
        assertEq(registry.totalWorkers(), 1); // ban ≠ deregister
    }

    /// Exact Gold/Platinum boundaries are inclusive; evaluated highest-first.
    function test_gold_and_platinum_boundaries_inclusive() public {
        assertEq(registry.calculateTier(BRONZE_REQUIREMENT - 1), TIER_NONE);
        assertEq(registry.calculateTier(BRONZE_REQUIREMENT), TIER_BRONZE);
        assertEq(registry.calculateTier(SILVER_REQUIREMENT), TIER_SILVER);
        assertEq(registry.calculateTier(GOLD_REQUIREMENT), TIER_GOLD);
        assertEq(registry.calculateTier(PLATINUM_REQUIREMENT - 1), TIER_GOLD);
        assertEq(registry.calculateTier(PLATINUM_REQUIREMENT), TIER_PLATINUM);
        assertEq(registry.calculateTier(type(uint256).max), TIER_PLATINUM);

        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, GOLD_REQUIREMENT);
        assertEq(_worker(alice, NODE_A).tier, TIER_GOLD);

        _activateAt(alice, NODE_A, PLATINUM_REQUIREMENT);
        assertEq(_worker(alice, NODE_A).tier, TIER_PLATINUM);
    }

    /// An ACTIVE worker dropping Gold→Bronze stays ACTIVE: deactivation
    /// happens only at exactly TIER_NONE, and no status event is emitted.
    function test_tier_drop_gold_to_bronze_keeps_active() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, GOLD_REQUIREMENT);
        assertEq(_worker(alice, NODE_A).tier, TIER_GOLD);

        _setBalance(alice, BRONZE_REQUIREMENT);
        vm.recordLogs();
        _updateTier(alice, NODE_A);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1); // TierUpdated only, no StatusChanged
        assertEq(logs[0].topics[0], keccak256("WorkerTierUpdated(address,bytes,uint8,uint8,uint256)"));

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_BRONZE);
        assertEq(w.status, STATUS_ACTIVE);
        assertEq(registry.activeWorkers(), 1);
    }

    /// An unchanged-tier refresh emits NOTHING but still writes
    /// verifiedBalance/lastVerified.
    function test_update_tier_unchanged_writes_fields_and_emits_nothing() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);

        vm.recordLogs();
        vm.prank(opsAdmin);
        registry.updateWorkerTier(alice, NODE_A, TIMESTAMP + 1);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0);

        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.lastVerified, TIMESTAMP + 1);
        assertEq(w.verifiedBalance, BRONZE_REQUIREMENT);
        assertEq(w.tier, TIER_BRONZE);
    }

    /// Deregistering SUSPENDED and BANNED workers: totalWorkers decrements,
    /// activeWorkers is untouched (they were not counted).
    function test_deregister_suspended_and_banned_worker_counter_behavior() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.suspendWorker(alice, NODE_A);
        vm.prank(opsAdmin);
        registry.deregister(alice, NODE_A);
        assertEq(registry.totalWorkers(), 0);
        assertEq(registry.activeWorkers(), 0);

        _registerNode(bob, NODE_A);
        _activateAt(bob, NODE_A, BRONZE_REQUIREMENT);
        vm.prank(opsAdmin);
        registry.banWorker(bob, NODE_A);
        vm.prank(opsAdmin);
        registry.deregister(bob, NODE_A);
        assertEq(registry.totalWorkers(), 0);
        assertEq(registry.activeWorkers(), 0);
        assertTrue(registry.isBanned(bob));
    }

    /// tierRequirement: real tiers map to the mutable thresholds; TIER_NONE
    /// and unrecognized values return 0 without reverting.
    function test_tier_requirement_view() public {
        assertEq(registry.tierRequirement(TIER_NONE), 0);
        assertEq(registry.tierRequirement(TIER_BRONZE), BRONZE_REQUIREMENT);
        assertEq(registry.tierRequirement(TIER_SILVER), SILVER_REQUIREMENT);
        assertEq(registry.tierRequirement(TIER_GOLD), GOLD_REQUIREMENT);
        assertEq(registry.tierRequirement(TIER_PLATINUM), PLATINUM_REQUIREMENT);
        assertEq(registry.tierRequirement(9), 0); // unrecognized → 0, no revert

        vm.prank(superAdmin);
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);
        assertEq(registry.tierRequirement(TIER_BRONZE), 1_000); // reads mutable state
    }

    /// hasCodec reads the stored bitmap; unknown nodes are all-false, no revert.
    function test_has_codec_view() public {
        _registerNode(alice, NODE_A); // codecs 0x0F: all four

        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_H264));
        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_HEVC));
        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_VP9));
        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_AV1));

        vm.prank(opsAdmin);
        registry.updateCapabilities(
            alice,
            NODE_A,
            WorkerRegistry.WorkerCapabilities({
                gpuModelHash: GPU_MODEL_HASH,
                gpuType: GPU_TYPE,
                gpuMemoryGb: GPU_MEMORY_GB,
                cpuCores: CPU_CORES,
                processingType: PROCESSING_TYPE,
                supportedCodecs: 0x0B, // H264 + HEVC + AV1, no VP9
                maxConcurrent: MAX_CONCURRENT,
                region: REGION
            })
        );

        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_H264));
        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_HEVC));
        assertFalse(registry.hasCodec(alice, NODE_A, CODEC_VP9));
        assertTrue(registry.hasCodec(alice, NODE_A, CODEC_AV1));

        assertFalse(registry.hasCodec(alice, NODE_B, CODEC_H264)); // unknown node → false
    }

    /// WorkerRegistered event carries the registered wallet (NOT the sender),
    /// tier hardcoded to TIER_NONE, and the caller-supplied timestamp.
    function test_registered_event_fields() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerRegistered(alice, NODE_A, TIER_NONE, TIMESTAMP);
        _registerNode(alice, NODE_A);
    }

    /// WorkerDeregistered event carries the wallet, nodeId, and the admin sender.
    function test_deregister_event_fields() public {
        _registerNode(alice, NODE_A);
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.WorkerDeregistered(alice, NODE_A, opsAdmin);
        vm.prank(opsAdmin);
        registry.deregister(alice, NODE_A);
    }

    /// TierThresholdsUpdated carries all four old/new pairs, the sender, and
    /// block.timestamp.
    function test_tier_thresholds_event_fields() public {
        vm.warp(1_800_000_000);
        vm.expectEmit(true, true, true, true, address(registry));
        emit WorkerRegistry.TierThresholdsUpdated(
            superAdmin,
            BRONZE_REQUIREMENT,
            1_000,
            SILVER_REQUIREMENT,
            2_000,
            GOLD_REQUIREMENT,
            3_000,
            PLATINUM_REQUIREMENT,
            4_000,
            1_800_000_000
        );
        vm.prank(superAdmin);
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);
    }

    /// Changing thresholds does NOT re-tier anyone immediately — each worker
    /// re-tiers on its next updateWorkerTier (spec §4.9 note).
    function test_threshold_change_applies_on_next_tier_update() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);
        assertEq(_worker(alice, NODE_A).tier, TIER_BRONZE);

        vm.prank(superAdmin);
        registry.setTierThresholds(
            BRONZE_REQUIREMENT * 2, SILVER_REQUIREMENT * 2, GOLD_REQUIREMENT * 2, PLATINUM_REQUIREMENT * 2
        );

        // Untouched until the next refresh.
        WorkerRegistry.Worker memory w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_BRONZE);
        assertEq(w.status, STATUS_ACTIVE);

        _updateTier(alice, NODE_A); // balance now below the new Bronze bar
        w = _worker(alice, NODE_A);
        assertEq(w.tier, TIER_NONE);
        assertEq(w.status, STATUS_INACTIVE);
        assertEq(registry.activeWorkers(), 0);
    }

    /// Remaining threshold-validation branches: zero bronze, gold ≤ silver,
    /// platinum ≤ gold, silver < bronze.
    function test_set_tier_thresholds_rejects_all_invalid_shapes() public {
        vm.startPrank(superAdmin);

        vm.expectRevert(WorkerRegistry.InvalidTierThresholds.selector);
        registry.setTierThresholds(0, 2, 3, 4); // bronze == 0

        vm.expectRevert(WorkerRegistry.InvalidTierThresholds.selector);
        registry.setTierThresholds(5, 4, 10, 20); // silver < bronze

        vm.expectRevert(WorkerRegistry.InvalidTierThresholds.selector);
        registry.setTierThresholds(1, 2, 2, 4); // gold not > silver

        vm.expectRevert(WorkerRegistry.InvalidTierThresholds.selector);
        registry.setTierThresholds(1, 2, 3, 3); // platinum not > gold

        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Role-matrix cases (super admin passes every gate; orchestrator is
    // excluded from moderation; per-function unauthorized reverts)
    // ─────────────────────────────────────────────────────────────────────

    /// The super admin passes both the admin and admin-or-orchestrator gates
    /// without holding ADMIN_ROLE or ORCHESTRATOR_ROLE explicitly — the
    /// super admin implicitly satisfies every lower gate, by design.
    function test_super_admin_passes_admin_and_orchestrator_gates() public {
        vm.prank(superAdmin);
        registry.register(bob, NODE_B, _defaultCaps(), TIMESTAMP);

        _setBalance(bob, BRONZE_REQUIREMENT);
        vm.startPrank(superAdmin);
        registry.updateWorkerTier(bob, NODE_B, TIMESTAMP);
        registry.updateCapabilities(bob, NODE_B, _defaultCaps());
        registry.suspendWorker(bob, NODE_B);
        registry.reactivateWorker(bob, NODE_B);
        registry.banWorker(bob, NODE_B);
        registry.deregister(bob, NODE_B);
        vm.stopPrank();

        assertEq(registry.totalWorkers(), 0);
        assertTrue(registry.isBanned(bob));
    }

    /// Moderation is admin-tier: the orchestrator is deliberately excluded
    /// from suspend/reactivate/ban/deregister.
    function test_orchestrator_cannot_call_admin_only_functions() public {
        _registerNode(alice, NODE_A);
        bytes memory err =
            abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ADMIN_ROLE, orchestrator);

        vm.prank(orchestrator);
        vm.expectRevert(err);
        registry.suspendWorker(alice, NODE_A);

        vm.prank(orchestrator);
        vm.expectRevert(err);
        registry.reactivateWorker(alice, NODE_A);

        vm.prank(orchestrator);
        vm.expectRevert(err);
        registry.banWorker(alice, NODE_A);

        vm.prank(orchestrator);
        vm.expectRevert(err);
        registry.deregister(alice, NODE_A);
    }

    /// setTierThresholds is super-admin only: ADMIN_ROLE and ORCHESTRATOR_ROLE
    /// are both rejected — this gate is deliberately super-admin, not admin.
    function test_admin_and_orchestrator_cannot_set_tier_thresholds() public {
        vm.prank(opsAdmin);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);

        vm.prank(orchestrator);
        vm.expectRevert(
            abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, orchestrator)
        );
        registry.setTierThresholds(1_000, 2_000, 3_000, 4_000);
    }

    /// Attacker (no roles) is rejected by reactivateWorker too — completes the
    /// unauthorized-revert matrix across every gated function.
    function test_non_admin_cannot_reactivate() public {
        _registerNode(alice, NODE_A);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, ADMIN_ROLE, attacker));
        registry.reactivateWorker(alice, NODE_A);
    }

    /// Every keyed mutator (and getWorker) reverts WorkerNotRegistered for an
    /// unknown (wallet, nodeId): a missing key reads back as a zeroed struct,
    /// so the existence check must be explicit rather than implied.
    function test_mutators_revert_on_unknown_worker() public {
        bytes memory err = abi.encodeWithSelector(WorkerRegistry.WorkerNotRegistered.selector, alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.updateWorkerTier(alice, NODE_A, TIMESTAMP);

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.updateCapabilities(alice, NODE_A, _defaultCaps());

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.suspendWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.reactivateWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.banWorker(alice, NODE_A);

        vm.prank(opsAdmin);
        vm.expectRevert(err);
        registry.deregister(alice, NODE_A);

        vm.expectRevert(err);
        registry.getWorker(alice, NODE_A);
    }

    // ─────────────────────────────────────────────────────────────────────
    // EVM-specific: initializer + UUPS upgrade authorization
    // ─────────────────────────────────────────────────────────────────────

    /// initialize() seeds the default thresholds and wires admin + token.
    function test_initialize_seeds_defaults_and_wiring() public view {
        assertEq(registry.bronzeThreshold(), BRONZE_REQUIREMENT);
        assertEq(registry.silverThreshold(), SILVER_REQUIREMENT);
        assertEq(registry.goldThreshold(), GOLD_REQUIREMENT);
        assertEq(registry.platinumThreshold(), PLATINUM_REQUIREMENT);
        assertEq(registry.totalWorkers(), 0);
        assertEq(registry.activeWorkers(), 0);
        assertEq(address(registry.admin()), address(admin));
        assertEq(address(registry.token()), address(token));
    }

    /// The initializer cannot run twice on the proxy, and the bare
    /// implementation has its initializers disabled by the constructor.
    function test_initializer_cannot_run_twice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        registry.initialize(address(admin), address(token));

        WorkerRegistry bareImpl = new WorkerRegistry();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bareImpl.initialize(address(admin), address(token));
    }

    /// initialize rejects zero addresses for both wiring params.
    function test_initialize_rejects_zero_addresses() public {
        WorkerRegistry impl = new WorkerRegistry();

        vm.expectRevert(WorkerRegistry.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(WorkerRegistry.initialize, (address(0), address(token))));

        vm.expectRevert(WorkerRegistry.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(WorkerRegistry.initialize, (address(admin), address(0))));
    }

    /// Only the super admin may upgrade: ADMIN_ROLE, ORCHESTRATOR_ROLE, and
    /// strangers are all rejected by _authorizeUpgrade.
    function test_non_super_admin_cannot_upgrade() public {
        WorkerRegistry newImpl = new WorkerRegistry();
        address[3] memory callers = [attacker, opsAdmin, orchestrator];

        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(
                abi.encodeWithSelector(WorkerRegistry.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, callers[i])
            );
            registry.upgradeToAndCall(address(newImpl), "");
        }
    }

    /// The super admin can upgrade in place; proxy storage survives.
    function test_super_admin_can_upgrade_and_state_survives() public {
        _registerNode(alice, NODE_A);
        _activateAt(alice, NODE_A, BRONZE_REQUIREMENT);

        WorkerRegistry newImpl = new WorkerRegistry();
        vm.prank(superAdmin);
        registry.upgradeToAndCall(address(newImpl), "");

        assertEq(
            address(uint160(uint256(vm.load(address(registry), IMPLEMENTATION_SLOT)))),
            address(newImpl)
        );
        // State lives in the proxy — untouched by the implementation swap.
        assertEq(registry.totalWorkers(), 1);
        assertEq(registry.activeWorkers(), 1);
        assertTrue(registry.isNodeRegistered(alice, NODE_A));
        assertEq(_worker(alice, NODE_A).tier, TIER_BRONZE);
    }
}
