// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title EscrowPool — pooled $PYRA payment escrow for the Lampyra network
/// @notice Clients deposit PYRA into one shared pool (per-client ledger
///         on-chain, per-job usage tracked off-chain), and the orchestrator
///         settles all worker payouts in a periodic atomic batch, withholding
///         a tunable platform fee into a separate admin-withdrawable fee pool.
///         Rolling-window caps bound fee withdrawals (default on) and worker
///         payouts (default off) as key-compromise blast-radius limits.
/// @dev Deliberate design decisions, all load-bearing:
///      - A whole settlement cycle is ONE atomic `settleBatch` tx: it either
///        pays every worker in the batch or reverts entirely. No multi-step
///        state machine, so no settlement-in-progress mutex, no partially
///        paid cycle can ever be left behind, and no cancel path needs to
///        reverse payments. `withdraw` is therefore never blocked by an
///        in-flight settlement.
///      - Cycle replay is prevented by the `settledCycles` dedup mapping,
///        so a retried or duplicated batch can never double-pay.
///      - Upgrades go through the UUPS proxy and are gated to the super
///        admin; there is no per-call version check to keep in sync.
///      - uint256 math is exact: fee math and the lifetime counters are
///        plain checked arithmetic — no intermediate widening and no
///        saturating counters are needed at any reachable magnitude.
///      - Timestamps are seconds (block.timestamp). Because block
///        timestamps are monotonic, the rolling windows need no guard
///        against time running backwards and deliberately have none.
///      IMPORTANT: per-client ledger entries are NOT debited by settlements —
///      the off-chain ledger is authoritative for per-job usage, so the sum
///      of client ledger balances can exceed `pool` after settlements.
contract EscrowPool is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Basis-point denominator for the platform-fee math.
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Hard ceiling on `setPlatformFeeBps` — 500 bps = 5%.
    uint256 public constant MAX_FEE_BPS = 500;

    /// @notice Genesis seed for the tunable `platformFeeBps` (250 bps = 2.5%).
    uint256 public constant DEFAULT_PLATFORM_FEE_BPS = 250;

    /// @notice Default rolling-window length for both caps: 24 hours (seconds).
    uint256 public constant DEFAULT_CAP_WINDOW = 86_400;

    /// @notice Fee-withdrawal cap default: 100k PYRA per 24h window, in base
    ///         units (1 PYRA = 1e9 base units; PYRA B20 has 9 decimals).
    uint256 public constant DEFAULT_FEE_CAP = 100_000 * 1e9;

    // Role constants mirrored from PyraAdmin (kept private per conventions).
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    // ─────────────────────────────────────────────────────────────────────
    // Errors (names are ABI — never change a shipped custom-error signature)
    // ─────────────────────────────────────────────────────────────────────

    /// @dev Caller lacks the role that gates the function. `role` is the
    ///      least-privileged role that would have been sufficient.
    error NotAuthorized(bytes32 role, address account);
    /// @dev `withdraw` by an address that never deposited, or `withdrawFees`
    ///      for more than the fee pool holds.
    error InsufficientBalance();
    /// @dev A payout (or client withdrawal) exceeds the aggregate `pool`.
    error InsufficientPoolBalance();
    /// @dev Zero amount where a positive amount is required.
    error InvalidAmount();
    /// @dev initialize() received a zero admin/token address (deploy-time guard).
    error ZeroAddress();
    /// @dev `withdraw` amount exceeds the caller's ledger balance.
    error WithdrawExceedsAvailable();
    /// @dev Fee withdrawals are paused (`feeCap == 0`).
    error AdminWithdrawalsPaused();
    /// @dev Fee withdrawal would exceed `feeCap` in the current window.
    error AdminWithdrawalCapExceeded();
    /// @dev `setPlatformFeeBps` above MAX_FEE_BPS.
    error FeeTooHigh();
    /// @dev A settlement payout would exceed `payoutCap` in the current window.
    error PayoutCapExceeded();
    /// @dev `settleBatch` replay for a cycle id that already settled.
    error CycleAlreadySettled(uint64 cycleId);
    /// @dev `settleBatch` array lengths differ.
    error LengthMismatch();

    // ─────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────

    /// @notice A client deposited into the pool. `ref` is a caller-supplied
    ///         attribution tag consumed by the off-chain watcher (replaces
    ///         bare transfer-watching).
    event ClientDeposit(address indexed client, uint256 amount, uint256 newBalance, bytes32 ref);
    /// @notice A client withdrew from their ledger balance.
    event ClientWithdraw(address indexed client, uint256 amount, uint256 remainingBalance);
    /// @notice A worker was paid `netAmount` (post-fee) in cycle `cycleId`.
    event WorkerPaid(uint64 indexed cycleId, address indexed worker, uint256 netAmount);
    /// @notice A settlement cycle completed. `totalPaid` is net of fees;
    ///         `workersPaid` counts non-zero payments, not distinct addresses.
    event SettlementFinalized(uint64 indexed cycleId, uint256 totalPaid, uint256 feesCollected, uint256 workersPaid);
    /// @notice Platform fees were swept from the fee pool.
    event FeesWithdrawn(uint256 amount, address indexed recipient);
    /// @notice Fee-withdrawal cap retuned. `newWindow` is the effective
    ///         post-update window length (a 0 argument keeps the old one).
    event FeeCapUpdated(uint256 newCap, uint256 newWindow);
    /// @notice Payout cap retuned. `newWindow` is the effective post-update value.
    event PayoutCapUpdated(uint256 newCap, uint256 newWindow);
    /// @notice Platform fee retuned.
    event PlatformFeeUpdated(uint256 oldBps, uint256 newBps);

    // ─────────────────────────────────────────────────────────────────────
    // Storage (append-only across upgrades; never reorder/retype)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice The PyraAdmin access-control registry.
    IAccessControl public admin;

    /// @notice The PYRA token held in escrow.
    IERC20 public token;

    /// @notice Aggregate accounting balance of all client deposits (minus
    ///         client withdrawals and gross worker payouts). Invariant:
    ///         `token.balanceOf(this) >= pool + feePool` (direct transfers
    ///         into the contract are unattributed dust).
    uint256 public pool;

    /// @notice Platform fees withheld by settlements, pending `withdrawFees`.
    uint256 public feePool;

    /// @notice Per-client deposit ledger. Updated ONLY by deposit/withdraw —
    ///         NOT debited by settlements (off-chain ledger is authoritative
    ///         for per-job usage). 0 for unknown addresses.
    mapping(address => uint256) public clientBalance;

    /// @notice True once an address has ever deposited. Deliberately never
    ///         cleared: a fully-withdrawn client keeps its zero-balance entry,
    ///         which is what distinguishes InsufficientBalance (never
    ///         deposited) from WithdrawExceedsAvailable (deposited, but not
    ///         that much).
    mapping(address => bool) public hasDeposited;

    /// @notice Settlement-cycle dedup: once true, that cycle id can never be
    ///         settled again.
    mapping(uint64 => bool) public settledCycles;

    /// @notice Highest settled cycle id (0 = none). Informational; the
    ///         `settledCycles` mapping is the replay authority.
    uint64 public currentCycle;

    /// @notice Timestamp (seconds) of the most recent settlement; 0 if none.
    uint256 public lastSettlement;

    /// @notice Lifetime client deposits.
    uint256 public totalDeposited;

    /// @notice Lifetime client withdrawals.
    uint256 public totalWithdrawn;

    /// @notice Lifetime NET (post-fee) worker payouts.
    uint256 public totalPaidWorkers;

    /// @notice Lifetime platform fees collected.
    uint256 public totalFeesCollected;

    /// @notice Live platform fee in bps applied per payout (hard cap 500).
    uint256 public platformFeeBps;

    /// @notice Max `withdrawFees` outflow per window. 0 = PAUSED (all fee
    ///         withdrawals revert) — semantics differ from `payoutCap`'s 0!
    uint256 public feeCap;

    /// @notice Rolling-window length (seconds) for the fee-withdrawal cap.
    uint256 public feeWindow;

    /// @notice Timestamp the current fee window opened (0 = first touch
    ///         rolls a fresh window).
    uint256 public feeWindowStart;

    /// @notice Cumulative `withdrawFees` outflow this window.
    uint256 public feeWindowUsed;

    /// @notice Max GROSS worker payout per window. 0 = cap DISABLED
    ///         (unlimited), deliberately NOT "paused" — pausing payouts
    ///         would brick settlement. Enable pre-mainnet sized ~2–3x peak
    ///         daily payout volume.
    uint256 public payoutCap;

    /// @notice Rolling-window length (seconds) for the payout cap.
    uint256 public payoutWindow;

    /// @notice Timestamp the current payout window opened.
    uint256 public payoutWindowStart;

    /// @notice Cumulative GROSS payout this window (gross, not net).
    uint256 public payoutWindowUsed;

    uint256[50] private __gap;

    // ─────────────────────────────────────────────────────────────────────
    // Auth
    // ─────────────────────────────────────────────────────────────────────

    modifier onlyRole(bytes32 role) {
        if (!admin.hasRole(role, msg.sender)) revert NotAuthorized(role, msg.sender);
        _;
    }

    /// @dev Admin gate: ADMIN_ROLE or the super admin — the super admin IS an
    ///      admin, matching the PyraAdmin registry's own admin check.
    modifier onlyAdmin() {
        if (!admin.hasRole(ADMIN_ROLE, msg.sender) && !admin.hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized(ADMIN_ROLE, msg.sender);
        }
        _;
    }

    /// @dev Settlement gate: orchestrator, admin, or super admin.
    modifier onlyAdminOrOrchestrator() {
        if (
            !admin.hasRole(ORCHESTRATOR_ROLE, msg.sender) && !admin.hasRole(ADMIN_ROLE, msg.sender)
                && !admin.hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotAuthorized(ORCHESTRATOR_ROLE, msg.sender);
        }
        _;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initialization / upgrade
    // ─────────────────────────────────────────────────────────────────────

    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the proxy with the PyraAdmin registry and the
    ///         PYRA token, seeding the genesis knob values: 2.5% platform
    ///         fee, 100k-PYRA/24h fee-withdrawal cap, payout cap disabled.
    /// @param admin_ The deployed PyraAdmin address.
    /// @param token_ The PYRA B20 address.
    function initialize(address admin_, address token_) external initializer {
        if (admin_ == address(0) || token_ == address(0)) revert ZeroAddress();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        admin = IAccessControl(admin_);
        token = IERC20(token_);
        platformFeeBps = DEFAULT_PLATFORM_FEE_BPS;
        feeCap = DEFAULT_FEE_CAP;
        feeWindow = DEFAULT_CAP_WINDOW;
        payoutWindow = DEFAULT_CAP_WINDOW;
        // payoutCap stays 0 = disabled; window/lifetime state stays 0.
    }

    /// @dev Only the super admin (Safe) can upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ─────────────────────────────────────────────────────────────────────
    // Client escrow
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Deposits `amount` PYRA into the pool, credited to the caller's
    ///         ledger balance. Requires prior ERC20 approval (or permit).
    ///         Permissionless and never blocked. `ref` is an opaque
    ///         attribution tag echoed in the event for the off-chain watcher.
    /// @param amount PYRA base units to deposit; must be > 0.
    /// @param ref Caller-supplied attribution reference.
    /// @dev Effects before the token pull (CEI) + nonReentrant (audit L1).
    ///      Assumes PYRA is not fee-on-transfer (true for the B20): the ledger
    ///      credits the requested amount, not the amount received.
    function deposit(uint256 amount, bytes32 ref) external nonReentrant {
        if (amount == 0) revert InvalidAmount();
        hasDeposited[msg.sender] = true;
        uint256 newBalance = clientBalance[msg.sender] + amount;
        clientBalance[msg.sender] = newBalance;
        pool += amount;
        totalDeposited += amount;
        emit ClientDeposit(msg.sender, amount, newBalance, ref);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    /// @notice Withdraws `amount` PYRA from the caller's ledger balance to
    ///         the caller. Never blocked by settlements (they are atomic).
    /// @dev Deliberate semantics: a zero withdraw is permitted (emits the
    ///      event); an address that never deposited reverts
    ///      InsufficientBalance, an over-withdrawal reverts
    ///      WithdrawExceedsAvailable. If settlements have drained the shared
    ///      pool below the caller's ledger promise, this reverts
    ///      InsufficientPoolBalance — an explicit, named failure rather than
    ///      an opaque one from the token transfer.
    /// @param amount PYRA base units to withdraw.
    function withdraw(uint256 amount) external nonReentrant {
        if (!hasDeposited[msg.sender]) revert InsufficientBalance();
        uint256 balance = clientBalance[msg.sender];
        if (balance < amount) revert WithdrawExceedsAvailable();
        if (pool < amount) revert InsufficientPoolBalance();
        uint256 remaining = balance - amount;
        clientBalance[msg.sender] = remaining;
        pool -= amount;
        totalWithdrawn += amount;
        token.safeTransfer(msg.sender, amount);
        emit ClientWithdraw(msg.sender, amount, remaining);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Settles one batch cycle atomically: pays every worker its
    ///         gross amount minus the platform fee (withheld into the fee
    ///         pool), enforcing the rolling-window payout cap on gross.
    ///         Each cycle id can settle exactly once; a reverted settlement
    ///         leaves the cycle unsettled and can be retried with the same
    ///         id. Zero-amount entries are skipped (no event, not counted).
    /// @dev Per-entry order is deliberate and load-bearing: fee math →
    ///      pool-balance check → payout-cap check → effects → transfer.
    ///      Client ledger balances are NOT debited — payouts draw from the
    ///      aggregate pool; the off-chain ledger reconciles per-client usage.
    /// @param cycleId Off-chain settlement cycle id (dedup key).
    /// @param workers Payout recipients (arbitrary addresses; trust is on
    ///        the settlement key).
    /// @param grossAmounts Gross PYRA base units per worker, pre-fee.
    function settleBatch(uint64 cycleId, address[] calldata workers, uint256[] calldata grossAmounts)
        external
        nonReentrant
        onlyAdminOrOrchestrator
    {
        if (workers.length != grossAmounts.length) revert LengthMismatch();
        if (settledCycles[cycleId]) revert CycleAlreadySettled(cycleId);
        settledCycles[cycleId] = true;
        if (cycleId > currentCycle) currentCycle = cycleId;

        uint256 feeBps = platformFeeBps;
        uint256 totalPaid;
        uint256 feesCollected;
        uint256 workersPaid;

        for (uint256 i = 0; i < workers.length; i++) {
            uint256 gross = grossAmounts[i];
            // Deliberate: zero-amount entries are silent no-ops — no event,
            // no counter change.
            if (gross == 0) continue;

            uint256 fee = (gross * feeBps) / BPS_DENOMINATOR;
            uint256 net = gross - fee;

            // Pool-balance check runs BEFORE the payout-cap check (deliberate
            // ordering): an underfunded pool surfaces InsufficientPoolBalance
            // even when the cap would also trip.
            if (pool < gross) revert InsufficientPoolBalance();

            if (payoutCap > 0) {
                if (block.timestamp >= payoutWindowStart + payoutWindow) {
                    payoutWindowStart = block.timestamp;
                    payoutWindowUsed = 0;
                }
                // The cap counts GROSS, not net.
                if (payoutWindowUsed + gross > payoutCap) revert PayoutCapExceeded();
                payoutWindowUsed += gross;
            }

            pool -= gross;
            feePool += fee;
            totalPaid += net;
            feesCollected += fee;
            workersPaid += 1;

            token.safeTransfer(workers[i], net);
            emit WorkerPaid(cycleId, workers[i], net);
        }

        lastSettlement = block.timestamp;
        totalPaidWorkers += totalPaid;
        totalFeesCollected += feesCollected;
        emit SettlementFinalized(cycleId, totalPaid, feesCollected, workersPaid);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fee sweep
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Sweeps `amount` of collected platform fees to `recipient`,
    ///         subject to the rolling-window fee-withdrawal cap. Admin only
    ///         (the orchestrator key deliberately cannot reach this).
    /// @dev Check order is deliberate: amount → fee-pool balance → cap pause
    ///      → window roll → cap. A cap-exceeded call leaves the pool
    ///      untouched.
    /// @param amount PYRA base units to sweep; must be > 0.
    /// @param recipient Destination address.
    function withdrawFees(uint256 amount, address recipient) external nonReentrant onlyAdmin {
        if (amount == 0) revert InvalidAmount();
        if (feePool < amount) revert InsufficientBalance();
        uint256 cap = feeCap;
        if (cap == 0) revert AdminWithdrawalsPaused();
        if (block.timestamp >= feeWindowStart + feeWindow) {
            feeWindowStart = block.timestamp;
            feeWindowUsed = 0;
        }
        if (feeWindowUsed + amount > cap) revert AdminWithdrawalCapExceeded();
        feeWindowUsed += amount;
        feePool -= amount;
        token.safeTransfer(recipient, amount);
        emit FeesWithdrawn(amount, recipient);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Knobs (super-admin only)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Retunes the fee-withdrawal cap. `newCap == 0` PAUSES all fee
    ///         withdrawals; `newWindow == 0` keeps the current window length.
    ///         The window always resets so the change takes effect
    ///         immediately. No upper bound (deliberate).
    /// @param newCap Max fee-sweep outflow per window, in PYRA base units.
    /// @param newWindow New window length in seconds, or 0 to keep.
    function setFeeCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        feeCap = newCap;
        if (newWindow > 0) feeWindow = newWindow;
        feeWindowStart = block.timestamp;
        feeWindowUsed = 0;
        emit FeeCapUpdated(newCap, feeWindow);
    }

    /// @notice Retunes the worker-payout cap. `newCap == 0` DISABLES the cap
    ///         (unlimited — NOT a pause; pausing payouts would brick
    ///         settlement); `newWindow == 0` keeps the current window length.
    ///         The window always resets. No upper bound (deliberate).
    /// @param newCap Max GROSS payout per window, in PYRA base units.
    /// @param newWindow New window length in seconds, or 0 to keep.
    function setPayoutCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        payoutCap = newCap;
        if (newWindow > 0) payoutWindow = newWindow;
        payoutWindowStart = block.timestamp;
        payoutWindowUsed = 0;
        emit PayoutCapUpdated(newCap, payoutWindow);
    }

    /// @notice Retunes the platform fee applied per payout. Hard-capped at
    ///         MAX_FEE_BPS (5%); 0 is allowed (fee-free). Super-admin only —
    ///         a revenue parameter the hot orchestrator key must not reach.
    /// @param newBps New fee in basis points, <= 500.
    function setPlatformFeeBps(uint256 newBps) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newBps > MAX_FEE_BPS) revert FeeTooHigh();
        uint256 oldBps = platformFeeBps;
        platformFeeBps = newBps;
        emit PlatformFeeUpdated(oldBps, newBps);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Raw fee-withdrawal-cap state: (cap, window length, window
    ///         start, used this window). Does NOT virtually roll the window.
    function feeCapStatus() external view returns (uint256, uint256, uint256, uint256) {
        return (feeCap, feeWindow, feeWindowStart, feeWindowUsed);
    }

    /// @notice Raw payout-cap state: (cap, window length, window start, used
    ///         this window). Cap 0 = disabled. Does NOT virtually roll.
    function payoutCapStatus() external view returns (uint256, uint256, uint256, uint256) {
        return (payoutCap, payoutWindow, payoutWindowStart, payoutWindowUsed);
    }
}
