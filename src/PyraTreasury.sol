// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title PyraTreasury — Lampyra network token-distribution vault (UUPS)
/// @notice Holds the full 10B $PYRA supply, tracks the six distribution pools as
///         internal accounting, enforces per-pool rolling-window withdrawal caps on
///         every admin-discretionary outflow, and runs linear team vesting
///         (cliff + linear-from-start) with one schedule per beneficiary, forever.
///
/// @dev Unit conventions:
///      - Token amounts are $PYRA base units (token has 9 decimals; 1 PYRA = 1e9).
///      - All durations/timestamps are in SECONDS (`block.timestamp`). Vesting math
///        is ratio-based so units cancel.
///      Deliberate design choices (documented per site):
///      - No on-chain version gate and no migration entrypoint — the UUPS proxy
///        always runs the latest code; future storage init uses `reinitializer(n)`.
///      - `moveBetweenPools` checks the source pool itself and reverts
///        `InsufficientBalance()`, so insufficiency surfaces as a named error rather
///        than an arithmetic panic; internal moves never touch the token.
///      - `addToCommunityPool`/`addToLiquidityPool` emit `PoolDeposited` — repo
///        convention requires every state mutation to emit.
///      - `releaseVestedTokens` on an unknown beneficiary reverts
///        `NoVestingSchedule()` rather than silently no-op'ing.
///      - `initializeDistribution` additionally requires the contract to actually
///        hold the full supply, so pool accounting can never be phantom (the B20
///        factory's initCalls mint the full supply to this proxy).
contract PyraTreasury is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Roles (mirrors PyraAdmin)
    // ---------------------------------------------------------------------

    bytes32 private constant DEFAULT_ADMIN_ROLE = bytes32(0); // super admin (Safe)
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    // ---------------------------------------------------------------------
    // Constants (amounts in base units, durations in seconds)
    // ---------------------------------------------------------------------

    /// @notice Full fixed supply: 10B PYRA in base units (9 decimals).
    uint256 public constant TOTAL_SUPPLY = 10_000_000_000_000_000_000;

    uint256 public constant PRESALE_ALLOCATION = 2_500_000_000_000_000_000; // 2.5B (25%)
    uint256 public constant TEAM_ALLOCATION = 2_500_000_000_000_000_000; // 2.5B (25%)
    uint256 public constant LIQUIDITY_ALLOCATION = 3_000_000_000_000_000_000; // 3.0B (30%)
    uint256 public constant COMMUNITY_ALLOCATION = 1_000_000_000_000_000_000; // 1.0B (10%)
    uint256 public constant RESERVE_ALLOCATION = 1_000_000_000_000_000_000; // 1.0B (10%)

    /// @notice Platform fee in basis points (2.5%). A constant here, NOT a knob —
    ///         the tunable fee lives in EscrowPool.
    uint256 public constant PLATFORM_FEE_BPS = 250;
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default rolling-window length: 24 hours (in seconds).
    uint256 public constant DEFAULT_CAP_WINDOW = 86_400;

    uint256 public constant DEFAULT_PRESALE_CAP = 1_000_000_000_000; // 1,000 PYRA / window
    uint256 public constant DEFAULT_COMMUNITY_CAP = 100_000_000_000_000; // 100,000 PYRA / window
    uint256 public constant DEFAULT_LIQUIDITY_CAP = 10_000_000_000_000; // 10,000 PYRA / window
    uint256 public constant DEFAULT_RESERVE_CAP = 1_000_000_000_000; // 1,000 PYRA / window
    uint256 public constant DEFAULT_FEE_CAP = 50_000_000_000_000; // 50,000 PYRA / window

    // Pool ids — uint8 is the wire type taken by `moveBetweenPools`.
    uint8 public constant POOL_PRESALE = 1;
    uint8 public constant POOL_TEAM = 2;
    uint8 public constant POOL_LIQUIDITY = 3;
    uint8 public constant POOL_COMMUNITY = 4;
    uint8 public constant POOL_RESERVE = 5;
    uint8 public constant POOL_FEE = 6;

    // ---------------------------------------------------------------------
    // Errors — auth uses the shared NotAuthorized(role, account) convention.
    // Names (and therefore selectors) are ABI-stable: never rename or reorder,
    // off-chain consumers decode by selector.
    // ---------------------------------------------------------------------

    error NotAuthorized(bytes32 role, address account); // covers both ops-admin and super-admin checks
    error InsufficientBalance();
    error VestingNotStarted();
    error NoTokensToRelease();
    error InvalidAmount();
    /// @dev initialize() received a zero admin/token address (deploy-time guard).
    error ZeroAddress();
    error VestingAlreadyExists();
    error SupplyAlreadyLocked();
    error AdminWithdrawalsPaused();
    error AdminWithdrawalCapExceeded();
    error InvalidPool();
    error NoVestingSchedule(); // unknown beneficiary (see contract @dev)

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event TreasuryInitialized(uint256 totalSupply, uint256 timestamp);
    event SupplyLocked(uint256 timestamp);
    event VestingScheduleCreated(
        address indexed beneficiary, uint256 amount, uint256 startTime, uint256 duration, uint256 cliffDuration
    );
    event VestingReleased(
        address indexed beneficiary, uint256 releasedNow, uint256 totalReleased, uint256 timestamp
    );
    /// @dev `windowUsed` is the cumulative amount in the current window AFTER this withdrawal.
    event PoolWithdrawn(
        string pool, uint256 amount, address indexed recipient, uint256 timestamp, uint256 windowUsed
    );
    /// @dev `newWindow` is the EFFECTIVE global window after the call (not the raw param).
    event AdminCapUpdated(string pool, uint256 newCap, uint256 newWindow, uint256 timestamp);
    event FeesDeposited(uint256 amount, address indexed depositor, uint256 timestamp);
    event PoolsRebalanced(
        address indexed sender, uint8 fromPool, uint8 toPool, uint256 amount, uint256 timestamp
    );
    /// @dev Emitted by the `addTo*Pool` inflows — every state mutation emits.
    event PoolDeposited(string pool, uint256 amount, address indexed depositor, uint256 timestamp);

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    struct CapState {
        uint256 cap; // 0 = discretionary withdrawals paused; deliberately no upper bound
        uint256 windowStart; // seconds; fixed-start rolling window
        uint256 windowUsed; // cumulative withdrawn in current window
    }

    struct VestingSchedule {
        address beneficiary;
        uint256 totalAmount; // fixed at creation; != 0 doubles as the existence sentinel
        uint256 releasedAmount; // cumulative released
        uint256 startTime; // seconds; vesting clock starts at creation
        uint256 duration; // total linear-vesting duration (seconds)
        uint256 cliffDuration; // cliff (seconds), <= duration
    }

    /// @notice The PyraAdmin access-control registry.
    IAccessControl public admin;
    /// @notice The $PYRA token.
    IERC20 public token;

    /// @notice True once `initializeDistribution` has credited the five pools.
    bool public initialized;
    /// @notice True once `lockSupply` has been called (mint authority ceremony; the
    ///         token itself can never mint again regardless).
    bool public supplyLocked;

    /// @notice Rolling-window length in seconds, shared by ALL five capped pools.
    uint256 public adminWindow;

    /// @notice Sum of unreleased vesting balances escrowed inside this contract.
    ///         Invariant: token.balanceOf(this) == Σ(six pools) + vestingEscrow.
    uint256 public vestingEscrow;

    mapping(uint8 poolId => uint256) private _pools;
    mapping(uint8 poolId => CapState) private _caps; // ids 1,3,4,5,6 (team pool is uncapped: vesting only)
    mapping(address beneficiary => VestingSchedule) private _vesting;

    uint256[50] private __gap;

    // ---------------------------------------------------------------------
    // Auth modifiers
    // ---------------------------------------------------------------------

    modifier onlyRole(bytes32 role) {
        if (!admin.hasRole(role, msg.sender)) revert NotAuthorized(role, msg.sender);
        _;
    }

    /// @dev True for the super admin OR any ops admin.
    modifier onlyAdmin() {
        if (!_isAdmin(msg.sender)) revert NotAuthorized(ADMIN_ROLE, msg.sender);
        _;
    }

    /// @dev True for the super admin, any ops admin, OR the orchestrator.
    modifier onlyAdminOrOrchestrator() {
        if (!_isAdmin(msg.sender) && !admin.hasRole(ORCHESTRATOR_ROLE, msg.sender)) {
            revert NotAuthorized(ADMIN_ROLE, msg.sender);
        }
        _;
    }

    function _isAdmin(address account) private view returns (bool) {
        return admin.hasRole(ADMIN_ROLE, account) || admin.hasRole(DEFAULT_ADMIN_ROLE, account);
    }

    // ---------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------

    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the treasury with the admin registry and token, default
    ///         window length, and default per-pool withdrawal caps. Distribution is
    ///         NOT performed here (see `initializeDistribution`).
    function initialize(address admin_, address token_) external initializer {
        if (admin_ == address(0) || token_ == address(0)) revert ZeroAddress();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        admin = IAccessControl(admin_);
        token = IERC20(token_);

        adminWindow = DEFAULT_CAP_WINDOW;
        _caps[POOL_PRESALE] = CapState({cap: DEFAULT_PRESALE_CAP, windowStart: 0, windowUsed: 0});
        _caps[POOL_COMMUNITY] = CapState({cap: DEFAULT_COMMUNITY_CAP, windowStart: 0, windowUsed: 0});
        _caps[POOL_LIQUIDITY] = CapState({cap: DEFAULT_LIQUIDITY_CAP, windowStart: 0, windowUsed: 0});
        _caps[POOL_RESERVE] = CapState({cap: DEFAULT_RESERVE_CAP, windowStart: 0, windowUsed: 0});
        _caps[POOL_FEE] = CapState({cap: DEFAULT_FEE_CAP, windowStart: 0, windowUsed: 0});
    }

    /// @notice One-shot: credits the five distribution pools with the fixed
    ///         allocations (presale/team 2.5B, liquidity 3.0B, community/reserve
    ///         1.0B). The contract must already hold the full 10B mint.
    /// @dev Deliberate: double-init reverts InvalidAmount, not a dedicated error.
    function initializeDistribution() external onlyAdmin {
        if (initialized) revert InvalidAmount();
        if (supplyLocked) revert SupplyAlreadyLocked();
        if (token.balanceOf(address(this)) < TOTAL_SUPPLY) revert InsufficientBalance();

        _pools[POOL_PRESALE] = PRESALE_ALLOCATION;
        _pools[POOL_TEAM] = TEAM_ALLOCATION;
        _pools[POOL_LIQUIDITY] = LIQUIDITY_ALLOCATION;
        _pools[POOL_COMMUNITY] = COMMUNITY_ALLOCATION;
        _pools[POOL_RESERVE] = RESERVE_ALLOCATION;
        // fee pool starts at 0; fed only by depositFees / moveBetweenPools.

        initialized = true;
        emit TreasuryInitialized(TOTAL_SUPPLY, block.timestamp);
    }

    /// @notice Permanently marks the supply as locked. Ceremonial only — the PYRA
    ///         B20's supply is already fixed at creation (MINT_ROLE never granted,
    ///         admin renounced via renounceLastAdmin), so this is a state flag +
    ///         event and nothing more.
    ///         ⚠ Monitors must NOT treat this flag as proof of supply immutability
    ///         (audit L3): verify the token itself — mint() must revert and no
    ///         DEFAULT_ADMIN/MINT_ROLE holders may exist on the B20.
    /// @dev Deliberate: locking before distribution reverts InvalidAmount; a second
    ///      lock reverts SupplyAlreadyLocked.
    function lockSupply() external onlyAdmin {
        if (!initialized) revert InvalidAmount();
        if (supplyLocked) revert SupplyAlreadyLocked();
        supplyLocked = true;
        emit SupplyLocked(block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Team vesting
    // ---------------------------------------------------------------------

    /// @notice Creates a linear vesting schedule (cliff + linear-from-start) for
    ///         `beneficiary`, escrowing `amount` out of the team pool. Super-admin
    ///         only. One schedule per beneficiary, forever (never deleted).
    function createTeamVesting(address beneficiary, uint256 amount, uint256 cliffDuration, uint256 vestingDuration)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (amount == 0) revert InvalidAmount();
        if (vestingDuration == 0) revert InvalidAmount();
        if (cliffDuration > vestingDuration) revert InvalidAmount();
        if (_pools[POOL_TEAM] < amount) revert InsufficientBalance();
        if (_vesting[beneficiary].totalAmount != 0) revert VestingAlreadyExists();

        _pools[POOL_TEAM] -= amount;
        vestingEscrow += amount;
        _vesting[beneficiary] = VestingSchedule({
            beneficiary: beneficiary,
            totalAmount: amount,
            releasedAmount: 0,
            startTime: block.timestamp,
            duration: vestingDuration,
            cliffDuration: cliffDuration
        });

        emit VestingScheduleCreated(beneficiary, amount, block.timestamp, vestingDuration, cliffDuration);
    }

    /// @notice Releases every newly-vested token of `beneficiary`'s schedule to the
    ///         beneficiary. PERMISSIONLESS — anyone may call; tokens always go to
    ///         the stored beneficiary. Vesting is linear from `startTime` (not from
    ///         cliff end); floor division.
    function releaseVestedTokens(address beneficiary) external nonReentrant {
        VestingSchedule storage s = _vesting[beneficiary];
        if (s.totalAmount == 0) revert NoVestingSchedule();
        if (block.timestamp < s.startTime + s.cliffDuration) revert VestingNotStarted();

        uint256 elapsed = block.timestamp - s.startTime;
        uint256 vestedTotal = elapsed >= s.duration ? s.totalAmount : (s.totalAmount * elapsed) / s.duration;
        if (vestedTotal <= s.releasedAmount) revert NoTokensToRelease();

        uint256 toRelease = vestedTotal - s.releasedAmount;
        s.releasedAmount = vestedTotal;
        vestingEscrow -= toRelease;

        emit VestingReleased(beneficiary, toRelease, vestedTotal, block.timestamp);
        token.safeTransfer(s.beneficiary, toRelease);
    }

    // ---------------------------------------------------------------------
    // Capped withdrawals (identical shape; only pool / auth / tag differ)
    // Check order is load-bearing and must not be shuffled: auth -> amount>0 ->
    // balance -> paused -> window roll -> cap. Tokens go to msg.sender.
    // ---------------------------------------------------------------------

    /// @notice Withdraws from the presale pool to the caller, subject to the
    ///         presale rolling-window cap. Admin only.
    function withdrawPresale(uint256 amount) external onlyAdmin nonReentrant {
        _withdrawCapped(POOL_PRESALE, "presale", amount);
    }

    /// @notice Withdraws from the community pool to the caller, subject to the
    ///         community rolling-window cap. Admin OR orchestrator (the only
    ///         orchestrator-accessible pool; used for worker rewards).
    function withdrawCommunityRewards(uint256 amount) external onlyAdminOrOrchestrator nonReentrant {
        _withdrawCapped(POOL_COMMUNITY, "community", amount);
    }

    /// @notice Withdraws from the liquidity pool to the caller, subject to the
    ///         liquidity rolling-window cap. Admin only.
    function withdrawLiquidity(uint256 amount) external onlyAdmin nonReentrant {
        _withdrawCapped(POOL_LIQUIDITY, "liquidity", amount);
    }

    /// @notice Withdraws from the reserve pool ("break glass") to the caller,
    ///         subject to the reserve rolling-window cap. Admin only.
    function withdrawReserve(uint256 amount) external onlyAdmin nonReentrant {
        _withdrawCapped(POOL_RESERVE, "reserve", amount);
    }

    /// @notice Withdraws from the fee pool to the caller, subject to the fee
    ///         rolling-window cap. Admin only.
    function withdrawFees(uint256 amount) external onlyAdmin nonReentrant {
        _withdrawCapped(POOL_FEE, "fee", amount);
    }

    function _withdrawCapped(uint8 poolId, string memory poolName, uint256 amount) private {
        if (amount == 0) revert InvalidAmount();
        if (_pools[poolId] < amount) revert InsufficientBalance(); // balance check BEFORE cap check

        CapState storage c = _caps[poolId];
        if (c.cap == 0) revert AdminWithdrawalsPaused();

        uint256 nowTs = block.timestamp;
        // Backwards-clock guard. Unreachable in production (block.timestamp is
        // non-decreasing) — kept for robustness: a regressed clock would otherwise
        // leave the window unable to roll, wedging the pool at its used total.
        if (nowTs < c.windowStart) {
            c.windowStart = nowTs;
            c.windowUsed = 0;
        }
        // Fixed-start rolling window: rolls at the first withdrawal after expiry;
        // the start does NOT slide with withdrawals inside the window.
        if (nowTs >= c.windowStart + adminWindow) {
            c.windowStart = nowTs;
            c.windowUsed = 0;
        }
        if (c.windowUsed + amount > c.cap) revert AdminWithdrawalCapExceeded();
        c.windowUsed += amount;

        _pools[poolId] -= amount;
        emit PoolWithdrawn(poolName, amount, msg.sender, nowTs, c.windowUsed);
        token.safeTransfer(msg.sender, amount);
    }

    // ---------------------------------------------------------------------
    // Cap setters — SUPER-ADMIN only, deliberately no hard cap on the new value
    // (0 = pause .. unbounded, may exceed pool balance). Setting a cap resets THAT
    // pool's window; a nonzero window param changes the GLOBAL window for ALL pools.
    // ---------------------------------------------------------------------

    /// @notice Sets the presale withdrawal cap (0 pauses) and resets its window.
    ///         `newWindow` == 0 keeps the current global window; nonzero changes it
    ///         for ALL pools.
    function setPresaleCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateCap(POOL_PRESALE, "presale", newCap, newWindow);
    }

    /// @notice Sets the community withdrawal cap (0 pauses) and resets its window.
    ///         `newWindow` == 0 keeps the current global window; nonzero changes it
    ///         for ALL pools.
    function setCommunityCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateCap(POOL_COMMUNITY, "community", newCap, newWindow);
    }

    /// @notice Sets the liquidity withdrawal cap (0 pauses) and resets its window.
    ///         `newWindow` == 0 keeps the current global window; nonzero changes it
    ///         for ALL pools.
    function setLiquidityCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateCap(POOL_LIQUIDITY, "liquidity", newCap, newWindow);
    }

    /// @notice Sets the reserve withdrawal cap (0 pauses) and resets its window.
    ///         `newWindow` == 0 keeps the current global window; nonzero changes it
    ///         for ALL pools.
    function setReserveCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateCap(POOL_RESERVE, "reserve", newCap, newWindow);
    }

    /// @notice Sets the fee withdrawal cap (0 pauses) and resets its window.
    ///         `newWindow` == 0 keeps the current global window; nonzero changes it
    ///         for ALL pools.
    function setFeeCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateCap(POOL_FEE, "fee", newCap, newWindow);
    }

    function _updateCap(uint8 poolId, string memory poolName, uint256 newCap, uint256 newWindow) private {
        if (newWindow > 0) adminWindow = newWindow; // 0 = keep current (global side effect when nonzero)
        CapState storage c = _caps[poolId];
        c.cap = newCap; // deliberately unvalidated: 0 (pause) .. unbounded
        c.windowStart = block.timestamp; // window reset so the change takes effect immediately
        c.windowUsed = 0;
        emit AdminCapUpdated(poolName, newCap, adminWindow, block.timestamp);
    }

    /// @notice Sets the global rolling-window length (seconds) for ALL capped
    ///         pools. Super-admin only; must be > 0. Does NOT reset any per-pool
    ///         window (re-set a cap to also reset its window).
    function setAdminWindow(uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newWindow == 0) revert InvalidAmount();
        adminWindow = newWindow;
        emit AdminCapUpdated("admin_window", newWindow, newWindow, block.timestamp);
    }

    // ---------------------------------------------------------------------
    // Pool rebalance + inflows
    // ---------------------------------------------------------------------

    /// @notice Moves `amount` between two internal pools (ids 1..6). Super-admin
    ///         only. BYPASSES withdrawal caps — caps bound outflows, not internal
    ///         moves. All six pools (including team and fee) are valid endpoints.
    function moveBetweenPools(uint8 fromPool, uint8 toPool, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (amount == 0) revert InvalidAmount();
        if (fromPool == toPool) revert InvalidPool();
        if (fromPool < POOL_PRESALE || fromPool > POOL_FEE) revert InvalidPool();
        if (toPool < POOL_PRESALE || toPool > POOL_FEE) revert InvalidPool();
        // Explicit source-pool check so insufficiency surfaces as
        // InsufficientBalance() rather than an arithmetic panic.
        if (_pools[fromPool] < amount) revert InsufficientBalance();

        _pools[fromPool] -= amount;
        _pools[toPool] += amount;
        emit PoolsRebalanced(msg.sender, fromPool, toPool, amount, block.timestamp);
    }

    /// @notice Pulls `amount` $PYRA from the caller (prior approval required) into
    ///         the community pool. Admin only; uncapped inflow; zero accepted
    ///         (deliberately no amount check).
    function addToCommunityPool(uint256 amount) external onlyAdmin nonReentrant {
        _pools[POOL_COMMUNITY] += amount;
        emit PoolDeposited("community", amount, msg.sender, block.timestamp);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    /// @notice Pulls `amount` $PYRA from the caller (prior approval required) into
    ///         the liquidity pool. Admin only; uncapped inflow; zero accepted
    ///         (deliberately no amount check).
    function addToLiquidityPool(uint256 amount) external onlyAdmin nonReentrant {
        _pools[POOL_LIQUIDITY] += amount;
        emit PoolDeposited("liquidity", amount, msg.sender, block.timestamp);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    /// @notice Pulls `amount` $PYRA from the caller (prior approval required) into
    ///         the long-term fee pool. PERMISSIONLESS (intended for bridging fees
    ///         in from EscrowPool, but anyone may deposit). Amount must be > 0.
    function depositFees(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();
        _pools[POOL_FEE] += amount;
        emit FeesDeposited(amount, msg.sender, block.timestamp);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    // ---------------------------------------------------------------------
    // Pure helpers
    // ---------------------------------------------------------------------

    /// @notice Returns the 2.5% platform fee for `amount` (floor division).
    function calculatePlatformFee(uint256 amount) external pure returns (uint256) {
        return (amount * PLATFORM_FEE_BPS) / BPS_DENOMINATOR;
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice Presale pool balance (base units).
    function presalePoolBalance() external view returns (uint256) {
        return _pools[POOL_PRESALE];
    }

    /// @notice Team pool balance (base units).
    function teamPoolBalance() external view returns (uint256) {
        return _pools[POOL_TEAM];
    }

    /// @notice Liquidity pool balance (base units).
    function liquidityPoolBalance() external view returns (uint256) {
        return _pools[POOL_LIQUIDITY];
    }

    /// @notice Community pool balance (base units).
    function communityPoolBalance() external view returns (uint256) {
        return _pools[POOL_COMMUNITY];
    }

    /// @notice Reserve pool balance (base units).
    function reservePoolBalance() external view returns (uint256) {
        return _pools[POOL_RESERVE];
    }

    /// @notice Fee pool balance (base units).
    function feePoolBalance() external view returns (uint256) {
        return _pools[POOL_FEE];
    }

    /// @notice True iff the supply-lock ceremony has run. A flag only — see
    ///         `lockSupply` for why it is not proof of supply immutability.
    function isSupplyLocked() external view returns (bool) {
        return supplyLocked;
    }

    /// @notice Cap status for a pool tag ("presale"|"community"|"liquidity"|
    ///         "reserve"|"fee"). Returns (0,0,0) for any unknown tag — deliberately
    ///         no revert.
    function capStatus(string calldata pool)
        external
        view
        returns (uint256 cap, uint256 windowStart, uint256 windowUsed)
    {
        uint8 poolId = _poolIdByName(pool);
        if (poolId == 0) return (0, 0, 0);
        CapState storage c = _caps[poolId];
        return (c.cap, c.windowStart, c.windowUsed);
    }

    /// @notice Full vesting schedule for `beneficiary` (zeroed struct if none).
    function vestingScheduleFor(address beneficiary) external view returns (VestingSchedule memory) {
        return _vesting[beneficiary];
    }

    /// @notice True iff `beneficiary` has (ever had) a vesting schedule.
    function hasVestingSchedule(address beneficiary) external view returns (bool) {
        return _vesting[beneficiary].totalAmount != 0;
    }

    function _poolIdByName(string calldata pool) private pure returns (uint8) {
        bytes32 h = keccak256(bytes(pool));
        if (h == keccak256("presale")) return POOL_PRESALE;
        if (h == keccak256("community")) return POOL_COMMUNITY;
        if (h == keccak256("liquidity")) return POOL_LIQUIDITY;
        if (h == keccak256("reserve")) return POOL_RESERVE;
        if (h == keccak256("fee")) return POOL_FEE;
        return 0;
    }

    // ---------------------------------------------------------------------
    // UUPS
    // ---------------------------------------------------------------------

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
