// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title WorkerRegistry — Lampyra transcoding-worker registry (UUPS)
/// @notice Registry of transcoding workers keyed by (wallet, nodeId): one
///         record per box, any number of boxes per operator wallet. The
///         orchestrator (least-privilege role) auto-registers workers on
///         connect and periodically refreshes each worker's tier
///         (None/Bronze/Silver/Gold/Platinum) from the wallet's live $PYRA
///         `balanceOf`, which auto-activates/deactivates the worker. Admins
///         moderate (suspend per-worker, ban per-wallet, deregister); the
///         super admin retunes the four tier thresholds live.
/// @dev No staking, no token custody: this contract never holds tokens.
///
///      Deliberate design choices, documented:
///      - Tier balance is read directly from `token.balanceOf(wallet)` inside
///        `updateWorkerTier` rather than being passed in by the caller: the
///        balance lives on this chain, so the read is atomic and requires no
///        trust in the orchestrator.
///      - Tier is conceptually per-wallet but is STORED per-worker: a wallet's
///        nodes re-tier individually on their next refresh.
///      - There is no in-contract version counter and no migration hook — the
///        UUPS proxy is the version mechanism.
///      - Forward compatibility comes from the storage gap at the end of the
///        layout, not from an open-ended key/value container of extra state.
///      - The custom errors below are ABI-stable: never change or renumber a
///        shipped error signature, and never reuse a retired one.
contract WorkerRegistry is Initializable, UUPSUpgradeable {
    // ─────────────────────────────────────────────────────────────────────
    // Roles (mirror PyraAdmin's constants)
    // ─────────────────────────────────────────────────────────────────────

    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00; // super admin
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    // ─────────────────────────────────────────────────────────────────────
    // Tier / status / codec constants
    // ─────────────────────────────────────────────────────────────────────

    uint8 public constant TIER_NONE = 0;
    uint8 public constant TIER_BRONZE = 1;
    uint8 public constant TIER_SILVER = 2;
    uint8 public constant TIER_GOLD = 3;
    uint8 public constant TIER_PLATINUM = 4;

    uint8 public constant STATUS_INACTIVE = 0;
    uint8 public constant STATUS_ACTIVE = 1;
    uint8 public constant STATUS_SUSPENDED = 2;
    uint8 public constant STATUS_BANNED = 3;

    uint8 public constant CODEC_H264 = 0x01;
    uint8 public constant CODEC_HEVC = 0x02;
    uint8 public constant CODEC_VP9 = 0x04;
    uint8 public constant CODEC_AV1 = 0x08;

    /// @notice Default tier thresholds seeded at initialize (PYRA base units,
    ///         9 decimals). Mutable afterwards via setTierThresholds.
    uint256 public constant DEFAULT_BRONZE_THRESHOLD = 100_000 * 1e9; // 100,000 PYRA
    uint256 public constant DEFAULT_SILVER_THRESHOLD = 500_000 * 1e9; // 500,000 PYRA
    uint256 public constant DEFAULT_GOLD_THRESHOLD = 2_500_000 * 1e9; // 2,500,000 PYRA
    uint256 public constant DEFAULT_PLATINUM_THRESHOLD = 10_000_000 * 1e9; // 10,000,000 PYRA

    // ─────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Self-reported hardware profile for a worker node. None of the
    ///         values are validated on-chain — by design, dishonest reporting
    ///         is caught off-chain by the orchestrator's verification pipeline.
    struct WorkerCapabilities {
        bytes32 gpuModelHash; // keccak-256 of the GPU model string (e.g. "RTX 4090")
        uint8 gpuType; // 0 = none, 1 = NVIDIA, 2 = AMD, 3 = Intel
        uint16 gpuMemoryGb; // GPU VRAM in whole GB
        uint8 cpuCores; // logical CPU cores
        uint8 processingType; // primary mode: 0 = CPU, 1 = GPU
        uint8 supportedCodecs; // bitmap: H264 0x01 | HEVC 0x02 | VP9 0x04 | AV1 0x08
        uint8 maxConcurrent; // max simultaneous transcode streams
        uint16 region; // numeric region code for geo routing
    }

    /// @notice One registered worker node; (wallet, nodeId) is the unique key.
    struct Worker {
        bool exists; // explicit flag: registeredAt is caller-supplied and may be 0
        address wallet; // operator wallet — immutable after registration
        uint8 tier; // TIER_*: set only by updateWorkerTier
        uint8 status; // STATUS_*
        uint64 lastVerified; // epoch-millis of last tier refresh (caller-supplied)
        uint64 registeredAt; // epoch-millis passed to register (caller-supplied)
        uint256 verifiedBalance; // wallet's PYRA balance observed at last refresh
        bytes nodeId; // stable per-node id (the orchestrator's NodeID, e.g. "node-1")
        WorkerCapabilities capabilities;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────

    /// @notice The PyraAdmin access-control hub all role checks delegate to.
    IAccessControl public admin;

    /// @notice The PYRA token; tier balances are read live via balanceOf.
    IERC20 public token;

    /// @notice Count of currently registered workers, ALL statuses included.
    uint256 public totalWorkers;

    /// @notice Count of workers whose status is exactly STATUS_ACTIVE, kept
    ///         explicitly in sync at every status transition.
    uint256 public activeWorkers;

    /// @notice Minimum wallet balance for Bronze (super-admin knob; mutable
    ///         forever, no cap, no freeze — must track PYRA/USD).
    uint256 public bronzeThreshold;
    /// @notice Minimum wallet balance for Silver.
    uint256 public silverThreshold;
    /// @notice Minimum wallet balance for Gold.
    uint256 public goldThreshold;
    /// @notice Minimum wallet balance for Platinum.
    uint256 public platinumThreshold;

    /// @dev wallet → keccak256(nodeId) → Worker record.
    mapping(address wallet => mapping(bytes32 nodeKey => Worker)) private _workers;

    /// @notice Number of registered nodes per wallet (isRegistered = count > 0,
    ///         so a wallet whose last node is deregistered reads as
    ///         unregistered again).
    mapping(address wallet => uint256) public walletNodeCount;

    /// @notice Permanently banned wallets. Blocks NEW registrations. Never
    ///         cleared — there is no unban, and the flag survives deregistration.
    mapping(address wallet => bool) public isBanned;

    /// @dev Forward-compat storage gap (shrink when adding variables in
    ///      future upgrades) — new state must consume this gap so the existing
    ///      storage layout never shifts.
    uint256[50] private __gap;

    // ─────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────

    /// @dev `wallet` is the registered operator wallet (NOT the sender);
    ///      `tier` is always TIER_NONE at registration.
    event WorkerRegistered(address indexed wallet, bytes nodeId, uint8 tier, uint64 timestamp);

    /// @dev Emitted on every status transition (auto-activate/deactivate,
    ///      suspend, reactivate, ban). Per-node: a wallet's other nodes are
    ///      unaffected. Within updateWorkerTier this is emitted BEFORE any
    ///      WorkerTierUpdated (ordering is observable and preserved).
    event WorkerStatusChanged(address indexed wallet, bytes nodeId, uint8 oldStatus, uint8 newStatus);

    /// @dev Emitted only when the tier actually changed.
    event WorkerTierUpdated(
        address indexed wallet, bytes nodeId, uint8 oldTier, uint8 newTier, uint256 verifiedBalance
    );

    event WorkerDeregistered(address indexed wallet, bytes nodeId, address indexed removedBy);

    /// @dev `timestamp` is block.timestamp in SECONDS — note the unit differs
    ///      from the caller-supplied epoch-millis timestamps elsewhere here.
    event TierThresholdsUpdated(
        address indexed updatedBy,
        uint256 oldBronze,
        uint256 newBronze,
        uint256 oldSilver,
        uint256 newSilver,
        uint256 oldGold,
        uint256 newGold,
        uint256 oldPlatinum,
        uint256 newPlatinum,
        uint256 timestamp
    );

    // ─────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────

    /// @dev `role` is the least-privileged role that would have satisfied the
    ///      gate (the super admin passes every gate).
    error NotAuthorized(bytes32 role, address account);
    error WorkerAlreadyRegistered(address wallet, bytes nodeId);
    error WorkerNotRegistered(address wallet, bytes nodeId);
    error WorkerBanned(address wallet);
    error InvalidTier(uint8 tier);
    error InvalidStatusTransition(uint8 currentStatus, uint8 targetStatus);
    error InvalidTierThresholds();
    error ZeroAddress();

    // ─────────────────────────────────────────────────────────────────────
    // Auth modifiers
    // ─────────────────────────────────────────────────────────────────────

    modifier onlyRole(bytes32 role) {
        if (!admin.hasRole(role, msg.sender)) revert NotAuthorized(role, msg.sender);
        _;
    }

    /// @dev Satisfied by ADMIN_ROLE or the super admin — the super admin
    ///      passes every admin gate.
    modifier onlyAdmin() {
        if (!_isAdmin(msg.sender)) revert NotAuthorized(ADMIN_ROLE, msg.sender);
        _;
    }

    /// @dev Satisfied by ADMIN_ROLE, the super admin, or ORCHESTRATOR_ROLE.
    modifier onlyAdminOrOrchestrator() {
        if (!_isAdmin(msg.sender) && !admin.hasRole(ORCHESTRATOR_ROLE, msg.sender)) {
            revert NotAuthorized(ORCHESTRATOR_ROLE, msg.sender);
        }
        _;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initializer
    // ─────────────────────────────────────────────────────────────────────

    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the registry behind its UUPS proxy: wires the
    ///         PyraAdmin hub and the PYRA token, seeds the four default tier
    ///         thresholds, zero workers.
    /// @param admin_ The deployed PyraAdmin contract.
    /// @param token_ The PYRA B20 contract.
    function initialize(address admin_, address token_) external initializer {
        if (admin_ == address(0) || token_ == address(0)) revert ZeroAddress();
        __UUPSUpgradeable_init();
        admin = IAccessControl(admin_);
        token = IERC20(token_);
        bronzeThreshold = DEFAULT_BRONZE_THRESHOLD;
        silverThreshold = DEFAULT_SILVER_THRESHOLD;
        goldThreshold = DEFAULT_GOLD_THRESHOLD;
        platinumThreshold = DEFAULT_PLATINUM_THRESHOLD;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Worker lifecycle (admin or orchestrator)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Registers a new worker node for `workerWallet`. Called by the
    ///         orchestrator on agent connect (or by an admin) — the operator
    ///         wallet never signs; `workerWallet` is a parameter, not the
    ///         sender. The worker starts TIER_NONE / STATUS_INACTIVE with a
    ///         zeroed verification state.
    /// @param workerWallet Operator wallet that owns the node.
    /// @param nodeId Stable per-node identifier; (wallet, nodeId) is unique.
    /// @param capabilities Self-reported hardware profile — deliberately NOT
    ///        validated on-chain.
    /// @param timestamp Caller-supplied registration time, epoch-millis.
    function register(
        address workerWallet,
        bytes calldata nodeId,
        WorkerCapabilities calldata capabilities,
        uint64 timestamp
    ) external onlyAdminOrOrchestrator {
        if (isBanned[workerWallet]) revert WorkerBanned(workerWallet);

        bytes32 nodeKey = keccak256(nodeId);
        Worker storage w = _workers[workerWallet][nodeKey];
        if (w.exists) revert WorkerAlreadyRegistered(workerWallet, nodeId);

        w.exists = true;
        w.wallet = workerWallet;
        w.nodeId = nodeId;
        w.tier = TIER_NONE;
        w.status = STATUS_INACTIVE;
        w.lastVerified = 0;
        w.verifiedBalance = 0;
        w.registeredAt = timestamp;
        w.capabilities = capabilities;

        walletNodeCount[workerWallet] += 1;
        totalWorkers += 1;

        emit WorkerRegistered(workerWallet, nodeId, TIER_NONE, timestamp);
    }

    /// @notice Refreshes a worker's tier from the wallet's live PYRA balance.
    ///         Always rewrites tier/verifiedBalance/lastVerified — in ANY
    ///         status, including SUSPENDED and BANNED. Then exactly one
    ///         automatic status branch may fire: INACTIVE→ACTIVE when the new
    ///         tier is ≥ Bronze, or ACTIVE→INACTIVE when it is exactly None.
    ///         SUSPENDED/BANNED statuses are never touched here. Emits
    ///         WorkerStatusChanged (if any) before WorkerTierUpdated (only
    ///         when the tier actually changed).
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    /// @param timestamp Caller-supplied verification time, epoch-millis.
    /// @dev Tier reads the wallet's INSTANTANEOUS balanceOf (audit L2): a wallet
    ///      transiently funded around the sweep can earn a higher tier than its
    ///      sustained holdings justify. Accepted: only admin/orchestrator can
    ///      trigger the read, tier only gates auto-activation, and reputation/
    ///      anti-cheat live off-chain.
    function updateWorkerTier(address workerWallet, bytes calldata nodeId, uint64 timestamp)
        external
        onlyAdminOrOrchestrator
    {
        Worker storage w = _getWorker(workerWallet, nodeId);

        uint8 oldTier = w.tier;
        uint256 balance = token.balanceOf(workerWallet);
        uint8 newTier = calculateTier(balance);

        w.tier = newTier;
        w.verifiedBalance = balance;
        w.lastVerified = timestamp;

        if (newTier >= TIER_BRONZE && w.status == STATUS_INACTIVE) {
            // Auto-activate: fires for ANY tier ≥ Bronze, only from INACTIVE.
            w.status = STATUS_ACTIVE;
            activeWorkers += 1;
            emit WorkerStatusChanged(workerWallet, nodeId, STATUS_INACTIVE, STATUS_ACTIVE);
        } else if (newTier == TIER_NONE && w.status == STATUS_ACTIVE) {
            // Auto-deactivate: only at exactly TIER_NONE, only from ACTIVE
            // (an ACTIVE worker dropping Gold→Bronze stays ACTIVE).
            w.status = STATUS_INACTIVE;
            activeWorkers -= 1;
            emit WorkerStatusChanged(workerWallet, nodeId, STATUS_ACTIVE, STATUS_INACTIVE);
        }
        // else: no status change, no status event.

        if (oldTier != newTier) {
            emit WorkerTierUpdated(workerWallet, nodeId, oldTier, newTier, balance);
        }
    }

    /// @notice Replaces a worker's self-reported hardware profile wholesale.
    ///         Works in any status; zero on-chain validation; deliberately
    ///         emits NO event.
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    /// @param capabilities The new profile.
    function updateCapabilities(address workerWallet, bytes calldata nodeId, WorkerCapabilities calldata capabilities)
        external
        onlyAdminOrOrchestrator
    {
        Worker storage w = _getWorker(workerWallet, nodeId);
        w.capabilities = capabilities;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Moderation (admin only — the orchestrator is deliberately excluded)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Suspends a worker (valid from INACTIVE or ACTIVE; suspending an
    ///         INACTIVE worker is legal). The active counter only decrements
    ///         when the worker was ACTIVE.
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    function suspendWorker(address workerWallet, bytes calldata nodeId) external onlyAdmin {
        Worker storage w = _getWorker(workerWallet, nodeId);
        if (w.status == STATUS_SUSPENDED || w.status == STATUS_BANNED) {
            revert InvalidStatusTransition(w.status, STATUS_SUSPENDED);
        }

        uint8 oldStatus = w.status;
        w.status = STATUS_SUSPENDED;
        if (oldStatus == STATUS_ACTIVE) {
            activeWorkers -= 1;
        }

        emit WorkerStatusChanged(workerWallet, nodeId, oldStatus, STATUS_SUSPENDED);
    }

    /// @notice Reactivates a SUSPENDED worker back to ACTIVE (never to
    ///         INACTIVE). Requires tier ≥ Bronze — a worker whose wallet sold
    ///         off PYRA while suspended must have its tier refreshed first
    ///         (updateWorkerTier works on suspended workers).
    /// @dev Deliberate quirk: calling this on a non-SUSPENDED worker reverts
    ///      WorkerNotRegistered (NOT InvalidStatusTransition) — pinned by the
    ///      test suite.
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    function reactivateWorker(address workerWallet, bytes calldata nodeId) external onlyAdmin {
        Worker storage w = _getWorker(workerWallet, nodeId);
        if (w.status != STATUS_SUSPENDED) revert WorkerNotRegistered(workerWallet, nodeId);
        if (w.tier < TIER_BRONZE) revert InvalidTier(w.tier);

        w.status = STATUS_ACTIVE;
        activeWorkers += 1; // pre-state was SUSPENDED, so it was not counted

        emit WorkerStatusChanged(workerWallet, nodeId, STATUS_SUSPENDED, STATUS_ACTIVE);
    }

    /// @notice Bans a worker node and permanently flags its wallet. Valid from
    ///         INACTIVE, ACTIVE, or SUSPENDED. Wallet-level in intent,
    ///         per-worker in implementation: the first call blocks all NEW
    ///         registrations for the wallet (the orchestrator sweeps the
    ///         wallet's other nodes with further calls). IRREVERSIBLE — there
    ///         is no unban anywhere, and reactivateWorker rejects BANNED. The
    ///         worker stays registered (totalWorkers unchanged); ban ≠
    ///         deregister.
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    function banWorker(address workerWallet, bytes calldata nodeId) external onlyAdmin {
        Worker storage w = _getWorker(workerWallet, nodeId);
        if (w.status == STATUS_BANNED) revert InvalidStatusTransition(STATUS_BANNED, STATUS_BANNED);

        uint8 oldStatus = w.status;
        w.status = STATUS_BANNED;
        if (oldStatus == STATUS_ACTIVE) {
            activeWorkers -= 1;
        }
        if (!isBanned[workerWallet]) {
            isBanned[workerWallet] = true; // idempotent across the wallet's other nodes
        }

        emit WorkerStatusChanged(workerWallet, nodeId, oldStatus, STATUS_BANNED);
    }

    /// @notice Deregisters a worker node — any status, including BANNED. The
    ///         wallet's banned flag (if set) survives deregistration, so a
    ///         banned wallet still cannot re-register. Admin-only: even the
    ///         owning wallet cannot deregister itself.
    /// @param workerWallet Operator wallet of the node.
    /// @param nodeId Node identifier.
    function deregister(address workerWallet, bytes calldata nodeId) external onlyAdmin {
        Worker storage w = _getWorker(workerWallet, nodeId);

        if (w.status == STATUS_ACTIVE) {
            activeWorkers -= 1;
        }

        delete _workers[workerWallet][keccak256(nodeId)];
        walletNodeCount[workerWallet] -= 1; // last node → isRegistered(wallet) becomes false
        totalWorkers -= 1;

        emit WorkerDeregistered(workerWallet, nodeId, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Economic knobs (super admin only)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Retunes the four tier thresholds. Super-admin only. Values must
    ///         be strictly ascending with bronze > 0; NO upper bound, NO
    ///         freeze — mutable forever by design (thresholds must track the
    ///         PYRA/USD price). Changing thresholds does NOT re-tier anyone
    ///         immediately: each worker re-tiers on its next updateWorkerTier.
    /// @param newBronze New Bronze minimum (base units), must be > 0.
    /// @param newSilver New Silver minimum, must be > newBronze.
    /// @param newGold New Gold minimum, must be > newSilver.
    /// @param newPlatinum New Platinum minimum, must be > newGold.
    function setTierThresholds(uint256 newBronze, uint256 newSilver, uint256 newGold, uint256 newPlatinum)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (newBronze == 0 || newSilver <= newBronze || newGold <= newSilver || newPlatinum <= newGold) {
            revert InvalidTierThresholds();
        }

        uint256 oldBronze = bronzeThreshold;
        uint256 oldSilver = silverThreshold;
        uint256 oldGold = goldThreshold;
        uint256 oldPlatinum = platinumThreshold;

        bronzeThreshold = newBronze;
        silverThreshold = newSilver;
        goldThreshold = newGold;
        platinumThreshold = newPlatinum;

        emit TierThresholdsUpdated(
            msg.sender,
            oldBronze,
            newBronze,
            oldSilver,
            newSilver,
            oldGold,
            newGold,
            oldPlatinum,
            newPlatinum,
            block.timestamp
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────

    /// @notice True iff the wallet has at least one registered node.
    function isRegistered(address wallet) external view returns (bool) {
        return walletNodeCount[wallet] > 0;
    }

    /// @notice True iff (wallet, nodeId) is a registered node. Never reverts
    ///         on unknown keys.
    function isNodeRegistered(address wallet, bytes calldata nodeId) external view returns (bool) {
        return _workers[wallet][keccak256(nodeId)].exists;
    }

    /// @notice Deterministic id for a registered node, derived from
    ///         (wallet, nodeId). Reverts WorkerNotRegistered if the wallet has
    ///         no nodes, or if this nodeId is not registered under it.
    function getWorkerId(address wallet, bytes calldata nodeId) external view returns (bytes32) {
        if (walletNodeCount[wallet] == 0) revert WorkerNotRegistered(wallet, nodeId);
        if (!_workers[wallet][keccak256(nodeId)].exists) revert WorkerNotRegistered(wallet, nodeId);
        return keccak256(abi.encode(wallet, nodeId));
    }

    /// @notice Full worker record. Reverts WorkerNotRegistered if unknown.
    function getWorker(address wallet, bytes calldata nodeId) external view returns (Worker memory) {
        Worker storage w = _workers[wallet][keccak256(nodeId)];
        if (!w.exists) revert WorkerNotRegistered(wallet, nodeId);
        return w;
    }

    /// @notice The minimum balance for `tier`; 0 for TIER_NONE and any
    ///         unrecognized tier value (never reverts).
    function tierRequirement(uint8 tier) external view returns (uint256) {
        if (tier == TIER_BRONZE) return bronzeThreshold;
        if (tier == TIER_SILVER) return silverThreshold;
        if (tier == TIER_GOLD) return goldThreshold;
        if (tier == TIER_PLATINUM) return platinumThreshold;
        return 0;
    }

    /// @notice True iff the node's codec bitmap includes `codec`. Returns
    ///         false (never reverts) for unknown nodes.
    function hasCodec(address wallet, bytes calldata nodeId, uint8 codec) external view returns (bool) {
        return (_workers[wallet][keccak256(nodeId)].capabilities.supportedCodecs & codec) != 0;
    }

    /// @notice The tier a given balance earns under the CURRENT thresholds.
    ///         Boundaries are inclusive (a balance exactly at a threshold
    ///         earns that tier), evaluated highest-first.
    function calculateTier(uint256 balance) public view returns (uint8) {
        if (balance >= platinumThreshold) return TIER_PLATINUM;
        if (balance >= goldThreshold) return TIER_GOLD;
        if (balance >= silverThreshold) return TIER_SILVER;
        if (balance >= bronzeThreshold) return TIER_BRONZE;
        return TIER_NONE;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────────────────

    function _isAdmin(address account) private view returns (bool) {
        return admin.hasRole(ADMIN_ROLE, account) || admin.hasRole(DEFAULT_ADMIN_ROLE, account);
    }

    function _getWorker(address wallet, bytes calldata nodeId) private view returns (Worker storage) {
        Worker storage w = _workers[wallet][keccak256(nodeId)];
        if (!w.exists) revert WorkerNotRegistered(wallet, nodeId);
        return w;
    }

    /// @dev Only the super admin (the Safe) can upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
