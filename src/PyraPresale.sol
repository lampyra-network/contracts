// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @title PyraPresale — 5-stage $PYRA presale, paid in USDC (UUPS proxy)
/// @notice Sells PYRA across 5 stages with a linear bonding curve inside each
///         stage (price rises start→end as the stage sells). Tokens are NOT
///         delivered at buy time — they vest `immediateReleasePct` (default
///         25%) immediately plus the remainder linearly over `vestingDuration`
///         (default 90 days) from a token-weighted first-purchase timestamp,
///         claimed via repeated `claimVested()` pulls. All tunable sale
///         parameters freeze forever on the first successful purchase.
/// @dev Deliberate design choices, all load-bearing:
///      - Initialization is once-only, enforced by the `initializer`
///        modifier; `initialize` is intentionally NOT role-gated (whoever
///        holds and approves the allocation seeds the sale, once).
///      - Buyer purchase records live in this contract; there is no separate
///        registry contract to keep in sync.
///      - Payments: the buyer passes `maxPayment` (USDC base units) and the
///        contract pulls EXACTLY the integrated cost via `transferFrom`, so
///        there is no excess to refund and no refund branch to get wrong.
///        The two no-op return paths (wallet cap exhausted; sub-unit or
///        sold-out dust) are deliberate early `return`s: success, no state
///        change, no transfer, no event.
///      - Prices are quoted in USDC base units per one whole PYRA (1e9 base
///        units): cost = pyraAmount * price / PRICE_SCALE, PRICE_SCALE = 1e9.
///        The interpolated curve therefore quantizes to $0.000001 steps
///        (1,000–15,000 distinct prices per stage) — accepted coarseness of
///        pricing a 9-decimal token in a 6-decimal currency.
///      - All timestamps and every duration constant are `block.timestamp`
///        seconds.
///      - Custom error signatures are ABI — never change them. Retired
///        codes 4, 5, 6, 8, 9, 14 stay retired and are never reassigned.
///      - `outstandingObligations` (purchased-but-unclaimed PYRA) makes
///        `withdrawUnsoldTokens` unable to drain buyer-owed tokens.
///      - Explicit accounting mirrors (`_tokenPool`, `usdcRaised`) are kept
///        instead of reading raw ERC20 balances, so direct token donations
///        cannot skew sale math (donated funds are simply unaccounted).
///      - Every state mutation emits, including
///        initialize/advance/finalize/withdraw-unsold, so the full sale
///        history is reconstructible from logs alone.
///      - There is NO buyer refund path, by design: raised USDC is admin
///        property from the moment of purchase.
contract PyraPresale is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────

    /// @dev Per-buyer purchase record.
    struct UserPurchase {
        uint256[5] purchasedPerStage; // tokens bought per stage; index 0 = stage 1
        uint256 totalPurchased; // sum across all stages
        uint256 tokensReleased; // cumulative tokens claimed via claimVested()
        uint256 usdcPaid; // cumulative integrated cost actually paid (not gross intent)
        uint256 purchaseTime; // vesting anchor (seconds); token-weighted average on repeat buys
        bool exists; // record-initialized flag (a mapping has no membership test)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Roles (declared canonically in PyraAdmin; copied per conventions)
    // ─────────────────────────────────────────────────────────────────────

    /// @dev Super admin (the Safe holding the founder's key). OZ default role.
    bytes32 private constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE"); // unused here; kept for consistency

    // ─────────────────────────────────────────────────────────────────────
    // Constants (durations in seconds; USDC amounts in 6-decimal base units)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Number of presale stages.
    uint8 public constant NUM_STAGES = 5;

    /// @notice Tokens sold per stage: 500M PYRA (9 decimals).
    uint256 public constant TOKENS_PER_STAGE = 500_000_000 * 1e9;

    /// @notice Full 5-stage allocation pulled at initialize: 2.5B PYRA.
    uint256 public constant PRESALE_ALLOCATION = 2_500_000_000 * 1e9;

    /// @notice Default per-wallet per-stage purchase cap: 5M PYRA.
    uint256 public constant MAX_PER_WALLET_PER_STAGE = 5_000_000 * 1e9;

    /// @notice Default share released immediately at purchase (percent).
    uint256 public constant IMMEDIATE_RELEASE_PCT = 25;

    /// @notice Default linear vesting duration for the remainder: 90 days.
    uint256 public constant VESTING_DURATION = 90 days;

    /// @notice Hard ceiling on vesting duration: 5 years (fat-finger guard —
    ///         vesting terms freeze forever on the first purchase).
    uint256 public constant MAX_VESTING_DURATION = 1825 days;

    /// @notice Default rolling-window length for raised-USDC withdrawals: 24h.
    uint256 public constant DEFAULT_USDC_WITHDRAW_WINDOW = 1 days;

    /// @notice Default raised-USDC withdrawal cap per window: 1,000 USDC.
    uint256 public constant DEFAULT_USDC_WITHDRAW_CAP = 1_000 * 1e6;

    /// @notice Price scale: prices are USDC base units per one WHOLE PYRA
    ///         (1e9 base units). cost = tokens * price / PRICE_SCALE.
    uint256 public constant PRICE_SCALE = 1e9;

    // Bonding-curve stage prices (USDC base units per whole PYRA).
    uint256 public constant STAGE_1_START_PRICE = 3_500; // $0.00350
    uint256 public constant STAGE_1_END_PRICE = 4_500; // $0.00450
    uint256 public constant STAGE_2_START_PRICE = 4_500; // $0.00450
    uint256 public constant STAGE_2_END_PRICE = 6_000; // $0.00600
    uint256 public constant STAGE_3_START_PRICE = 6_000; // $0.00600
    uint256 public constant STAGE_3_END_PRICE = 8_500; // $0.00850
    uint256 public constant STAGE_4_START_PRICE = 8_500; // $0.00850
    uint256 public constant STAGE_4_END_PRICE = 15_000; // $0.01500
    uint256 public constant STAGE_5_START_PRICE = 15_000; // $0.01500
    uint256 public constant STAGE_5_END_PRICE = 30_000; // $0.03000

    // ─────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────

    /// @notice The PyraAdmin access-control registry.
    IAccessControl public admin;

    /// @notice The PYRA token being sold.
    IERC20 public token;

    /// @notice The USDC payment token (6 decimals).
    IERC20 public usdc;

    /// @notice Active stage, 1-indexed (1–5). Advances on sell-out (auto) or
    ///         `advanceStage` (manual, one-way). Never exceeds 5.
    uint8 public currentStage;

    /// @notice Purchases accepted iff true. Set false only by
    ///         `finalizePresale` (irreversibly).
    bool public isActive;

    /// @notice Set true by `finalizePresale`. Gates `withdrawUnsoldTokens`.
    ///         Vesting claims are unaffected.
    bool public finalized;

    /// @notice Set true by the first successful purchase; all pre-freeze
    ///         setters revert forever after. Never resets.
    bool public parametersFrozen;

    /// @notice Timestamp of initialize (seconds). Informational only — never
    ///         read by logic.
    uint256 public startTime;

    /// @notice Accumulated purchase USDC still held (accounting mirror, not
    ///         raw balance). Admin-withdrawable at any time, cap-limited.
    uint256 public usdcRaised;

    /// @notice Sum of purchased-but-unclaimed PYRA. Invariant:
    ///         outstandingObligations <= tokensRemaining().
    uint256 public outstandingObligations;

    /// @dev PYRA reserved for the presale (accounting mirror of the pool).
    uint256 internal _tokenPool;

    /// @dev Tokens sold per stage; index 0 = stage 1.
    uint256[5] internal _stageSold;

    /// @notice Max USDC withdrawable per rolling window. 0 = withdrawals
    ///         PAUSED (emergency brake). No upper bound.
    uint256 public usdcWithdrawCap;

    /// @notice Rolling-window length in seconds.
    uint256 public usdcWithdrawWindow;

    /// @dev Start of the current withdrawal window (seconds).
    uint256 private _usdcWithdrawWindowStart;

    /// @dev USDC withdrawn in the current window.
    uint256 private _usdcWithdrawWindowUsed;

    /// @dev Per-stage curve start/end prices (PRICE_SCALE units, i.e. USDC
    ///      base units per whole PYRA). Seeded from the STAGE_* constants;
    ///      logic always reads these, never the constants.
    uint256[5] internal _stageStartPrices;
    uint256[5] internal _stageEndPrices;

    /// @notice Per-wallet per-stage purchase cap. No bounds — 0 effectively
    ///         pauses purchases (every buy becomes a no-op return).
    uint256 public maxPerWalletPerStage;

    /// @notice Percent of a purchase released immediately (<= 100).
    uint256 public immediateReleasePct;

    /// @notice Linear vesting duration for the remainder (seconds).
    uint256 public vestingDuration;

    /// @dev buyer → purchase record.
    mapping(address => UserPurchase) internal _purchases;

    /// @dev Forward-compat storage gap: new state in a UUPS upgrade is carved
    ///      out of here, never appended after it, so the layout stays fixed.
    ///      Shrink by the number of slots consumed in future upgrades.
    uint256[50] private __gap;

    // ─────────────────────────────────────────────────────────────────────
    // Events (timestamps in seconds; `caller` is the acting admin/buyer)
    // ─────────────────────────────────────────────────────────────────────

    /// @dev `stage` is the stage AT purchase time (pre-auto-advance);
    ///      `usdcPaid` is the integrated cost actually pulled (not the gross
    ///      `maxPayment`); `price` is the average (trapezoid) price paid,
    ///      PRICE_SCALE units — NOT the spot price.
    event TokensPurchased(address indexed buyer, uint8 stage, uint256 tokens, uint256 usdcPaid, uint256 price);

    /// @dev `amount` is this claim; `totalReleased` is cumulative after it.
    event TokensVested(address indexed user, uint256 amount, uint256 totalReleased);

    /// @dev `remaining` is usdcRaised after the withdrawal.
    event RaisedUsdcWithdrawn(address indexed caller, uint256 amount, uint256 remaining, uint256 timestamp);

    /// @dev Watchers should alert on large cap increases.
    event UsdcWithdrawCapUpdated(
        address indexed caller,
        uint256 oldCap,
        uint256 newCap,
        uint256 oldWindow,
        uint256 newWindow,
        uint256 timestamp
    );

    /// @dev Deliberately carries no price payload — state is the source of truth.
    event StagePricesUpdated(address indexed caller, uint256 timestamp);

    event MaxPerWalletUpdated(address indexed caller, uint256 oldMax, uint256 newMax, uint256 timestamp);

    event VestingTermsUpdated(
        address indexed caller,
        uint256 oldImmediatePct,
        uint256 newImmediatePct,
        uint256 oldVestingDuration,
        uint256 newVestingDuration,
        uint256 timestamp
    );

    // Lifecycle events — initialize, stage advance, finalize and unsold-token
    // withdrawal all log, so no state mutation is invisible to indexers.
    event PresaleInitialized(address indexed caller, address token, address usdc, uint256 pool, uint256 timestamp);
    event StageAdvanced(address indexed caller, uint8 newStage);
    event PresaleFinalized(address indexed caller, uint256 timestamp);
    event UnsoldTokensWithdrawn(address indexed caller, uint256 amount);

    // ─────────────────────────────────────────────────────────────────────
    // Errors. The trailing numbers are the stable code numbering; codes 4, 5,
    // 6, 8, 9, 13 and 14 are retired and are never reassigned. Codes 0 (admin)
    // and 22 (super admin) are both served by NotAuthorized(role, account).
    // ─────────────────────────────────────────────────────────────────────

    error NotAuthorized(bytes32 role, address account); // 0 (admin) / 22 (super admin)
    error EPresaleNotActive(); // 1 — deliberately reused by withdrawUnsoldTokens when !finalized
    error EStageNotActive(); // 2 — defensive; unreachable by construction
    error EInsufficientPayment(); // 3 — withdrawRaisedUsdc amount exceeds usdcRaised
    error ENoTokensToVest(); // 7
    error EInvalidStage(); // 10
    error EOverflow(); // 11 — only ever a zero divisor in curve math; the product cannot overflow uint256
    error EPurchaseNotFound(); // 12
    error EInsufficientTokens(); // 15
    /// @dev initialize() received a zero admin/token/usdc address (deploy-time guard).
    error ZeroAddress();
    error EZeroWithdrawAmount(); // 16 — deliberately reused by setUsdcWithdrawCap for window == 0
    error EUsdcWithdrawCapExceeded(); // 17
    error EUsdcWithdrawsPaused(); // 18
    error EParametersFrozen(); // 19
    error EInvalidStagePrices(); // 20
    error EInvalidReleasePct(); // 21
    error EInvalidBounds(); // 23

    // ─────────────────────────────────────────────────────────────────────
    // Auth
    // ─────────────────────────────────────────────────────────────────────

    modifier onlyRole(bytes32 role) {
        if (!admin.hasRole(role, msg.sender)) revert NotAuthorized(role, msg.sender);
        _;
    }

    /// @dev Deliberately passes for regular admins AND the super admin — the
    ///      super admin satisfies every admin check without a separate grant.
    modifier onlyAdmin() {
        if (!admin.hasRole(ADMIN_ROLE, msg.sender) && !admin.hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized(ADMIN_ROLE, msg.sender);
        }
        _;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────

    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the presale and pulls the full 2.5B PYRA
    ///         allocation from the caller (who must have approved this
    ///         proxy). Reverts with EInsufficientTokens if the caller's PYRA
    ///         balance is below the full 5-stage allocation — a partially
    ///         funded sale is never allowed to open.
    /// @param admin_ The deployed PyraAdmin address.
    /// @param token_ The PYRA B20 address.
    /// @param usdc_ The USDC token address (6 decimals).
    function initialize(address admin_, address token_, address usdc_) external initializer {
        if (admin_ == address(0) || token_ == address(0) || usdc_ == address(0)) revert ZeroAddress();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        admin = IAccessControl(admin_);
        token = IERC20(token_);
        usdc = IERC20(usdc_);

        currentStage = 1;
        isActive = true;
        startTime = block.timestamp;

        usdcWithdrawCap = DEFAULT_USDC_WITHDRAW_CAP;
        usdcWithdrawWindow = DEFAULT_USDC_WITHDRAW_WINDOW;

        _stageStartPrices =
            [STAGE_1_START_PRICE, STAGE_2_START_PRICE, STAGE_3_START_PRICE, STAGE_4_START_PRICE, STAGE_5_START_PRICE];
        _stageEndPrices =
            [STAGE_1_END_PRICE, STAGE_2_END_PRICE, STAGE_3_END_PRICE, STAGE_4_END_PRICE, STAGE_5_END_PRICE];

        maxPerWalletPerStage = MAX_PER_WALLET_PER_STAGE;
        immediateReleasePct = IMMEDIATE_RELEASE_PCT;
        vestingDuration = VESTING_DURATION;

        if (token.balanceOf(msg.sender) < PRESALE_ALLOCATION) revert EInsufficientTokens();
        _tokenPool = PRESALE_ALLOCATION;
        emit PresaleInitialized(msg.sender, token_, usdc_, PRESALE_ALLOCATION, block.timestamp);
        token.safeTransferFrom(msg.sender, address(this), PRESALE_ALLOCATION);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Purchase & claim (permissionless)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Buys PYRA in the active stage at the integrated (trapezoid)
    ///         bonding-curve price. Pulls EXACTLY the computed cost in USDC
    ///         (never more than `maxPayment`); the caller must have approved
    ///         at least `maxPayment`. If the caller's per-stage wallet cap is
    ///         exhausted, or the payment is sub-unit dust, or the final stage
    ///         is sold out, the call deliberately succeeds as a NO-OP (no
    ///         state change, no transfer, no event) rather than reverting.
    /// @param maxPayment Maximum USDC (base units) the buyer is willing to pay.
    function purchase(uint256 maxPayment) external nonReentrant {
        if (!isActive) revert EPresaleNotActive();
        if (currentStage > NUM_STAGES) revert EStageNotActive(); // defensive; unreachable

        uint256 stageIdx = currentStage - 1;
        uint256 startPrice = _stageStartPrices[stageIdx];
        uint256 endPrice = _stageEndPrices[stageIdx];
        uint256 sold = _stageSold[stageIdx];
        uint256 currentPrice = _calculateCurrentPrice(startPrice, endPrice, sold);

        // Spot estimate, then clamp to stage remainder, then to wallet cap.
        uint256 actualTokens = _mulDiv(maxPayment, PRICE_SCALE, currentPrice);
        uint256 remainingInStage = TOKENS_PER_STAGE - sold;
        if (actualTokens > remainingInStage) actualTokens = remainingInStage;

        uint256 existing = _purchases[msg.sender].purchasedPerStage[stageIdx];
        uint256 maxAllowed = maxPerWalletPerStage > existing ? maxPerWalletPerStage - existing : 0;
        // No-op return path #1: wallet cap exhausted — success, no effects.
        if (maxAllowed == 0) return;
        if (actualTokens > maxAllowed) actualTokens = maxAllowed;

        // Integrated (trapezoidal) cost — exact for a linear curve.
        uint256 priceAfter = _calculateCurrentPrice(startPrice, endPrice, sold + actualTokens);
        uint256 avgPrice = (currentPrice + priceAfter) / 2;
        uint256 actualCost = _mulDiv(actualTokens, avgPrice, PRICE_SCALE);

        // Second pass if the spot estimate was too generous. The re-clamp
        // order (stage remainder THEN wallet cap) is deliberate and pins the
        // resulting amount — do not reorder.
        if (actualCost > maxPayment) {
            actualTokens = _mulDiv(maxPayment, PRICE_SCALE, avgPrice);
            if (actualTokens > remainingInStage) actualTokens = remainingInStage;
            if (actualTokens > maxAllowed) actualTokens = maxAllowed;
            uint256 adjEnd = _calculateCurrentPrice(startPrice, endPrice, sold + actualTokens);
            avgPrice = (currentPrice + adjEnd) / 2;
            actualCost = _mulDiv(actualTokens, avgPrice, PRICE_SCALE);
        }
        // Floors may leave a sub-unit residue in the buyer's favor or the
        // protocol's; guaranteed: actualCost <= maxPayment.

        // No-op return path #2: dust payment or stage 5 sold out — success,
        // no effects.
        if (actualCost == 0) return;

        // Effects: purchase record (token-weighted vesting anchor on repeat).
        UserPurchase storage p = _purchases[msg.sender];
        if (p.exists) {
            uint256 combined = p.totalPurchased + actualTokens;
            p.purchaseTime = (p.totalPurchased * p.purchaseTime + actualTokens * block.timestamp) / combined;
            p.purchasedPerStage[stageIdx] += actualTokens;
            p.totalPurchased = combined;
            p.usdcPaid += actualCost;
        } else {
            p.exists = true;
            p.purchasedPerStage[stageIdx] = actualTokens;
            p.totalPurchased = actualTokens;
            p.usdcPaid = actualCost;
            p.purchaseTime = block.timestamp;
        }

        // Effects: stage bookkeeping. The event carries the PRE-advance stage.
        uint8 purchaseStage = currentStage;
        _stageSold[stageIdx] += actualTokens;
        if (_stageSold[stageIdx] >= TOKENS_PER_STAGE && currentStage < NUM_STAGES) {
            currentStage += 1; // stage-5 sellout does NOT deactivate the presale
            emit StageAdvanced(msg.sender, currentStage);
        }
        outstandingObligations += actualTokens;
        usdcRaised += actualCost;
        parametersFrozen = true; // unconditional; no-op after the first purchase

        emit TokensPurchased(msg.sender, purchaseStage, actualTokens, actualCost, avgPrice);

        // Interaction: pull exactly the integrated cost.
        usdc.safeTransferFrom(msg.sender, address(this), actualCost);
    }

    /// @notice Claims every currently-vested, not-yet-released token for the
    ///         caller. Repeatable; works during and after finalization, with
    ///         no admin involvement. Reverts if nothing is newly claimable.
    function claimVested() external nonReentrant {
        UserPurchase storage p = _purchases[msg.sender];
        if (!p.exists) revert EPurchaseNotFound();

        (,, uint256 toRelease) = _vestingStatus(p);
        if (toRelease == 0) revert ENoTokensToVest();

        p.tokensReleased += toRelease;
        outstandingObligations -= toRelease; // invariant holds by construction
        _tokenPool -= toRelease;

        emit TokensVested(msg.sender, toRelease, p.tokensReleased);

        token.safeTransfer(msg.sender, toRelease);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Admin operations (regular admin; super admin passes too)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Manually advances to the next stage (one-way). Reverts beyond
    ///         stage 5 or once the presale is finalized.
    function advanceStage() external onlyAdmin {
        if (!isActive) revert EPresaleNotActive();
        if (currentStage >= NUM_STAGES) revert EInvalidStage();
        currentStage += 1;
        emit StageAdvanced(msg.sender, currentStage);
    }

    /// @notice Ends the presale irreversibly: purchases stop, and unsold
    ///         tokens become withdrawable. Vesting claims are unaffected.
    ///         Idempotent; callable at any time.
    function finalizePresale() external onlyAdmin {
        isActive = false;
        finalized = true;
        emit PresaleFinalized(msg.sender, block.timestamp);
    }

    /// @notice Withdraws `amount` of raised USDC to the caller, limited by a
    ///         rolling-window cap (cap 0 = paused). Callable during the
    ///         presale AND after finalization — raised USDC is admin property
    ///         from the moment of purchase; there is no refund path.
    /// @param amount USDC base units to withdraw (must be > 0).
    /// @dev Trust note (audit L5): pays msg.sender — any single ADMIN_ROLE
    ///      holder can route raised USDC to their own wallet, bounded only by
    ///      the rolling cap. Size ADMIN_ROLE membership accordingly.
    function withdrawRaisedUsdc(uint256 amount) external onlyAdmin nonReentrant {
        if (amount == 0) revert EZeroWithdrawAmount();
        if (usdcWithdrawCap == 0) revert EUsdcWithdrawsPaused();

        // Window roll. The backwards-clock branch is unreachable while block
        // timestamps are monotonic, but is kept as a harmless safety net.
        uint256 nowTs = block.timestamp;
        if (nowTs < _usdcWithdrawWindowStart) {
            _usdcWithdrawWindowStart = nowTs;
            _usdcWithdrawWindowUsed = 0;
        }
        if (nowTs >= _usdcWithdrawWindowStart + usdcWithdrawWindow) {
            _usdcWithdrawWindowStart = nowTs;
            _usdcWithdrawWindowUsed = 0;
        }

        // Deliberate check order: cap BEFORE balance.
        if (_usdcWithdrawWindowUsed + amount > usdcWithdrawCap) revert EUsdcWithdrawCapExceeded();
        if (amount > usdcRaised) revert EInsufficientPayment();

        _usdcWithdrawWindowUsed += amount;
        usdcRaised -= amount;

        emit RaisedUsdcWithdrawn(msg.sender, amount, usdcRaised, nowTs);

        usdc.safeTransfer(msg.sender, amount);
    }

    /// @notice Withdraws exactly the unsold slack (pool minus outstanding
    ///         buyer obligations) to the caller. Requires finalization.
    ///         Buyer-owed tokens can never be drained. Reverts when the
    ///         slack is zero (repeat calls revert — claims decrement pool and
    ///         obligations equally, so no new slack appears).
    /// @dev Trust note (audit L5): pays msg.sender — combined with
    ///      finalizePresale (also onlyAdmin), a single ops admin can end the sale
    ///      and sweep unsold PYRA to their own wallet. Size ADMIN_ROLE accordingly.
    function withdrawUnsoldTokens() external onlyAdmin nonReentrant {
        if (!finalized) revert EPresaleNotActive(); // deliberately reuses code 1
        if (_tokenPool < outstandingObligations) revert EInsufficientTokens(); // invariant assert
        uint256 withdrawable = _tokenPool - outstandingObligations;
        if (withdrawable == 0) revert EInsufficientTokens();

        _tokenPool -= withdrawable;

        emit UnsoldTokensWithdrawn(msg.sender, withdrawable);

        token.safeTransfer(msg.sender, withdrawable);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Super-admin knobs
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Sets the raised-USDC withdrawal cap and window. NOT gated by
    ///         the parameter freeze — this is a security knob adjustable for
    ///         the life of the presale. Cap 0 = documented pause/emergency
    ///         brake; no upper bound. Does NOT reset the current window's
    ///         usage. Window length 0 is rejected (pause via cap instead).
    /// @param newCap New per-window cap in USDC base units (0 pauses).
    /// @param newWindow New window length in seconds (> 0).
    function setUsdcWithdrawCap(uint256 newCap, uint256 newWindow) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newWindow == 0) revert EZeroWithdrawAmount(); // deliberately reuses code 16

        uint256 oldCap = usdcWithdrawCap;
        uint256 oldWindow = usdcWithdrawWindow;
        usdcWithdrawCap = newCap;
        usdcWithdrawWindow = newWindow;

        emit UsdcWithdrawCapUpdated(msg.sender, oldCap, newCap, oldWindow, newWindow, block.timestamp);
    }

    /// @notice Replaces both stage-price ladders wholesale. Pre-freeze only.
    ///         Each stage needs start > 0 and end >= start; the ladder must
    ///         not step DOWN between stages (end[i] <= start[i+1]).
    /// @param newStartPrices 5 per-stage curve start prices (PRICE_SCALE units).
    /// @param newEndPrices 5 per-stage curve end prices (PRICE_SCALE units).
    function setStagePrices(uint256[] calldata newStartPrices, uint256[] calldata newEndPrices)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (parametersFrozen) revert EParametersFrozen();
        if (newStartPrices.length != NUM_STAGES) revert EInvalidStagePrices();
        if (newEndPrices.length != NUM_STAGES) revert EInvalidStagePrices();
        for (uint256 i = 0; i < NUM_STAGES; ++i) {
            if (newStartPrices[i] == 0) revert EInvalidStagePrices(); // zero price => infinite tokens per unit
            if (newEndPrices[i] < newStartPrices[i]) revert EInvalidStagePrices();
            if (i + 1 < NUM_STAGES && newEndPrices[i] > newStartPrices[i + 1]) revert EInvalidBounds();
        }
        for (uint256 i = 0; i < NUM_STAGES; ++i) {
            _stageStartPrices[i] = newStartPrices[i];
            _stageEndPrices[i] = newEndPrices[i];
        }

        emit StagePricesUpdated(msg.sender, block.timestamp);
    }

    /// @notice Sets the per-wallet per-stage cap. Pre-freeze only. No bounds:
    ///         0 is legal and effectively pauses purchases (every buy becomes
    ///         a no-op return).
    /// @param newMax New cap in PYRA base units.
    function setMaxPerWalletPerStage(uint256 newMax) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (parametersFrozen) revert EParametersFrozen();

        uint256 oldMax = maxPerWalletPerStage;
        maxPerWalletPerStage = newMax;

        emit MaxPerWalletUpdated(msg.sender, oldMax, newMax, block.timestamp);
    }

    /// @notice Sets the vesting terms. Pre-freeze only. Immediate percent
    ///         <= 100; duration in (0, 5 years] — the ceiling exists because
    ///         these terms freeze forever on the first buy.
    /// @param newImmediatePct Percent released immediately (<= 100).
    /// @param newVestingDuration Linear vesting duration in seconds.
    function setVestingTerms(uint256 newImmediatePct, uint256 newVestingDuration)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (parametersFrozen) revert EParametersFrozen();
        if (newImmediatePct > 100) revert EInvalidReleasePct();
        if (newVestingDuration == 0) revert EInvalidBounds();
        if (newVestingDuration > MAX_VESTING_DURATION) revert EInvalidBounds();

        uint256 oldPct = immediateReleasePct;
        uint256 oldDuration = vestingDuration;
        immediateReleasePct = newImmediatePct;
        vestingDuration = newVestingDuration;

        emit VestingTermsUpdated(msg.sender, oldPct, newImmediatePct, oldDuration, newVestingDuration, block.timestamp);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Views (index conventions differ per function — read each doc comment)
    // ─────────────────────────────────────────────────────────────────────

    /// @notice Tokens bought by `user` in stage index `stageIdx` (0-indexed;
    ///         index 0 = stage 1). Returns 0 for an unknown user; reverts on
    ///         an out-of-range index for a known user.
    function getUserStagePurchase(address user, uint256 stageIdx) external view returns (uint256) {
        UserPurchase storage p = _purchases[user];
        if (!p.exists) return 0;
        return p.purchasedPerStage[stageIdx];
    }

    /// @notice Total tokens bought by `user` across all stages (0 if unknown).
    function getUserTotalPurchase(address user) external view returns (uint256) {
        return _purchases[user].totalPurchased;
    }

    /// @notice Vesting status for `user`: (totalPurchased, tokensReleased,
    ///         claimableNow). Returns (0, 0, 0) for an unknown user.
    ///         `claimableNow` uses EXACTLY the claimVested math — this is the
    ///         claim preview the frontend relies on.
    function getUserVestingStatus(address user)
        external
        view
        returns (uint256 totalPurchased, uint256 tokensReleased, uint256 claimableNow)
    {
        UserPurchase storage p = _purchases[user];
        if (!p.exists) return (0, 0, 0);
        return _vestingStatus(p);
    }

    /// @notice Tokens sold in `stage` (1-indexed, 1–5). Reverts for stage 0
    ///         or stage > 5 (array bounds check).
    function stageSold(uint8 stage) external view returns (uint256) {
        return _stageSold[stage - 1];
    }

    /// @notice PYRA still held for the presale (buyer obligations + unsold).
    function tokensRemaining() external view returns (uint256) {
        return _tokenPool;
    }

    /// @notice Preview of withdrawUnsoldTokens: pool minus obligations,
    ///         saturating at 0 (never reverts).
    function withdrawableUnsold() external view returns (uint256) {
        return _tokenPool > outstandingObligations ? _tokenPool - outstandingObligations : 0;
    }

    /// @notice Raw stored withdrawal-window state (start, used). Does NOT
    ///         simulate a window roll.
    function usdcWithdrawWindowState() external view returns (uint256 windowStart, uint256 windowUsed) {
        return (_usdcWithdrawWindowStart, _usdcWithdrawWindowUsed);
    }

    /// @notice Spot price for the active stage at the current amount sold
    ///         (PRICE_SCALE units — USDC base units per whole PYRA).
    function getCurrentPrice() external view returns (uint256) {
        uint256 stageIdx = currentStage - 1;
        return _calculateCurrentPrice(_stageStartPrices[stageIdx], _stageEndPrices[stageIdx], _stageSold[stageIdx]);
    }

    /// @notice Copy of the per-stage curve start-price ladder.
    function stageStartPrices() external view returns (uint256[5] memory) {
        return _stageStartPrices;
    }

    /// @notice Copy of the per-stage curve end-price ladder.
    function stageEndPrices() external view returns (uint256[5] memory) {
        return _stageEndPrices;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────────────────

    /// @dev Linear interpolation start + range * sold / TOKENS_PER_STAGE. The
    ///      two floors (progress, then the range product) are deliberate and
    ///      must stay separate — do not fold them into one division.
    function _calculateCurrentPrice(uint256 startPrice, uint256 endPrice, uint256 sold)
        internal
        pure
        returns (uint256)
    {
        uint256 priceRange = endPrice - startPrice; // setters enforce end >= start
        uint256 progress = _mulDiv(sold, PRICE_SCALE, TOKENS_PER_STAGE);
        return startPrice + _mulDiv(priceRange, progress, PRICE_SCALE);
    }

    /// @dev floor(a * b / c) with a zero-divisor guard. Math.mulDiv carries a
    ///      512-bit intermediate, so the product itself cannot overflow —
    ///      EOverflow therefore only ever signals c == 0.
    function _mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        if (c == 0) revert EOverflow();
        return Math.mulDiv(a, b, c);
    }

    /// @dev Exact claim math. Both tranches floor separately, so a lifetime
    ///      claim total may fall 1 base unit short of totalPurchased —
    ///      accepted as-is (do not "fix" with a remainder).
    function _vestingStatus(UserPurchase storage p)
        internal
        view
        returns (uint256 total, uint256 released, uint256 claimable)
    {
        total = p.totalPurchased;
        released = p.tokensReleased;

        uint256 elapsed = block.timestamp > p.purchaseTime ? block.timestamp - p.purchaseTime : 0;
        uint256 vestingAmount = (total * (100 - immediateReleasePct)) / 100;
        uint256 totalVested =
            elapsed >= vestingDuration ? vestingAmount : (vestingAmount * elapsed) / vestingDuration;
        uint256 immediate = (total * immediateReleasePct) / 100;
        uint256 totalClaimable = immediate + totalVested;
        claimable = totalClaimable > released ? totalClaimable - released : 0;
    }

    /// @dev Only the super admin (the Safe) may upgrade the implementation.
    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
