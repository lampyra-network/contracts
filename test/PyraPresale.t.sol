// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, stdError} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {PyraPresale} from "../src/PyraPresale.sol";
import {PyraAdmin} from "../src/PyraAdmin.sol";
import {MockPYRA} from "./mocks/MockPYRA.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";

/// @dev Foundry harness exposing test-only helpers that force purchase
/// records directly (incl. the obligations bookkeeping). Test-only child
/// contract — never production code.
contract PresaleHarness is PyraPresale {
    /// Test-only: force a purchase record for `buyer`, split evenly across stages.
    function insertPurchaseForTesting(address buyer, uint256 totalPurchased_, uint256 purchaseTime_) external {
        UserPurchase storage p = _purchases[buyer];
        if (p.exists) {
            uint256 unreleased = p.totalPurchased > p.tokensReleased ? p.totalPurchased - p.tokensReleased : 0;
            outstandingObligations = outstandingObligations > unreleased ? outstandingObligations - unreleased : 0;
        }
        for (uint256 i = 0; i < 5; ++i) {
            p.purchasedPerStage[i] = totalPurchased_ / 5;
        }
        p.exists = true;
        p.totalPurchased = totalPurchased_;
        p.tokensReleased = 0;
        p.usdcPaid = 0;
        p.purchaseTime = purchaseTime_;
        outstandingObligations += totalPurchased_;
    }

    /// Direct obligations override to exercise the invariant-assert branch.
    function setObligationsForTesting(uint256 v) external {
        outstandingObligations = v;
    }
}

/// @notice Full behavioural suite for the presale: initializer, UUPS upgrade
///         auth, per-function unauthorized reverts, USDC(6-dec)xPYRA(9-dec)
///         price-math edges, freeze-on-first-buy, vesting boundary timestamps,
///         stage advancement, finalization and both withdrawal paths.
///         Payments are USDC-only. The contract uses a PULL model: it pulls
///         exactly the integrated cost rather than taking `maxPayment` and
///         refunding the excess, so the two "nothing to buy" cases are success
///         NO-OPs instead of reverts — no-op path #1: the wallet cap is
///         already filled; no-op path #2: the integrated cost floors to zero.
contract PyraPresaleTest is Test {
    // 1 PYRA = 1e9 base units; 1 USDC = 1e6 base units.
    uint256 private constant PYRA = 1e9;
    uint256 private constant USDC_UNIT = 1e6;

    uint256 private constant TOKENS_PER_STAGE = 500_000_000 * PYRA; // 5e17
    uint256 private constant ALLOCATION = 2_500_000_000 * PYRA; // 2.5e18
    uint256 private constant WALLET_CAP = 5_000_000 * PYRA; // 5e15
    uint256 private constant PRICE_SCALE = 1e9;

    // Vesting / withdraw-window durations, in seconds.
    uint256 private constant VESTING_DURATION = 7_776_000; // 90 days
    uint256 private constant MAX_VESTING_DURATION = 157_680_000; // 5 years
    uint256 private constant WITHDRAW_WINDOW = 86_400; // 24h
    uint256 private constant DEFAULT_WITHDRAW_CAP = 1_000 * USDC_UNIT; // 1e9

    // Stage price ladder (USDC base units per whole PYRA).
    uint256 private constant S1_START = 3_500;
    uint256 private constant S1_END = 4_500;

    // Hand-computed expected purchase outcomes (floor math, spot price 3500):
    // tokens = floor(pay * 1e9 / price); cost = floor(tokens * avg / 1e9).
    uint256 private constant T_1USDC_S1 = 285_714_285_714; // 1 USDC in stage 1
    uint256 private constant C_1USDC_S1 = 999_999;
    uint256 private constant T_1USDC_S2 = 222_222_222_222; // 1 USDC in stage 2 (price 4500)
    uint256 private constant C_1USDC_S2 = 999_999;
    uint256 private constant T_10USDC_S1 = 2_857_142_857_142;
    uint256 private constant C_10USDC_S1 = 9_999_999;
    // Wallet-cap fill via overpayment: 5e15 tokens, avg price (3500+3510)/2 = 3505.
    uint256 private constant CAP_FILL_COST = 17_525_000_000;
    // $10k buy triggers the second (re-estimate) pass: avg settles at 3502.
    uint256 private constant T_10K_USDC = 2_855_511_136_493_432;
    uint256 private constant C_10K_USDC = 9_999_999_999;

    bytes32 private constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    PyraAdmin internal pyraAdmin;
    PyraPresale internal presale;
    MockPYRA internal token;
    MockUSDC internal usdc;

    address internal superAdmin = makeAddr("superAdmin");
    address internal opsAdmin = makeAddr("opsAdmin");
    address internal orchestrator = makeAddr("orchestrator");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal attacker = makeAddr("attacker");

    function setUp() public {
        vm.warp(1000); // fixture: clock at t=1000 at initialize

        pyraAdmin = new PyraAdmin(0, superAdmin);
        vm.startPrank(superAdmin);
        pyraAdmin.grantRole(ADMIN_ROLE, opsAdmin);
        pyraAdmin.grantRole(ORCHESTRATOR_ROLE, orchestrator);
        vm.stopPrank();

        token = new MockPYRA(address(this)); // test contract holds the 10B supply
        usdc = new MockUSDC();

        presale = _deployPresale();

        usdc.mint(alice, 1_000_000_000 * USDC_UNIT);
        usdc.mint(bob, 1_000_000_000 * USDC_UNIT);
        _approveBuyer(presale, alice);
        _approveBuyer(presale, bob);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// @dev Canonical UUPS deployment (conventions): initialize runs in the
    ///      proxy constructor and pulls the 2.5B PYRA allocation from the
    ///      deployer, so the proxy address is pre-approved via prediction.
    function _deployPresale() internal returns (PyraPresale p) {
        return _proxyInit(address(new PyraPresale()));
    }

    function _deployHarness() internal returns (PresaleHarness h) {
        return PresaleHarness(address(_proxyInit(address(new PresaleHarness()))));
    }

    function _proxyInit(address impl) internal returns (PyraPresale p) {
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        token.approve(predicted, ALLOCATION);
        p = PyraPresale(
            address(
                new ERC1967Proxy(
                    impl, abi.encodeCall(PyraPresale.initialize, (address(pyraAdmin), address(token), address(usdc)))
                )
            )
        );
        assertEq(address(p), predicted, "proxy address prediction mismatch");
    }

    function _approveBuyer(PyraPresale p, address who) internal {
        vm.prank(who);
        usdc.approve(address(p), type(uint256).max);
    }

    function _buy(PyraPresale p, address buyer, uint256 maxPay) internal {
        vm.prank(buyer);
        p.purchase(maxPay);
    }

    function _ladder5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e)
        internal
        pure
        returns (uint256[] memory arr)
    {
        arr = new uint256[](5);
        arr[0] = a;
        arr[1] = b;
        arr[2] = c;
        arr[3] = d;
        arr[4] = e;
    }

    /// @dev Accounting mirrors always back the real ERC20 balances.
    function _assertSolvent(PyraPresale p) internal view {
        assertEq(usdc.balanceOf(address(p)), p.usdcRaised(), "usdc mirror");
        assertEq(token.balanceOf(address(p)), p.tokensRemaining(), "pyra mirror");
    }

    /// @dev Pre-freeze cap raise so a single wallet can buy out whole stages.
    function _raiseWalletCapToStage(PyraPresale p) internal {
        vm.prank(superAdmin);
        p.setMaxPerWalletPerStage(TOKENS_PER_STAGE);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Constants pin (ladder + converted durations)
    // ─────────────────────────────────────────────────────────────────────

    function test_Constants_MatchSpec() public view {
        assertEq(presale.NUM_STAGES(), 5);
        assertEq(presale.TOKENS_PER_STAGE(), TOKENS_PER_STAGE);
        assertEq(presale.PRESALE_ALLOCATION(), ALLOCATION);
        assertEq(presale.MAX_PER_WALLET_PER_STAGE(), WALLET_CAP);
        assertEq(presale.IMMEDIATE_RELEASE_PCT(), 25);
        assertEq(presale.VESTING_DURATION(), VESTING_DURATION);
        assertEq(presale.MAX_VESTING_DURATION(), MAX_VESTING_DURATION);
        assertEq(presale.DEFAULT_USDC_WITHDRAW_WINDOW(), WITHDRAW_WINDOW);
        assertEq(presale.DEFAULT_USDC_WITHDRAW_CAP(), DEFAULT_WITHDRAW_CAP);
        assertEq(presale.PRICE_SCALE(), PRICE_SCALE);
        assertEq(presale.STAGE_1_START_PRICE(), 3_500);
        assertEq(presale.STAGE_1_END_PRICE(), 4_500);
        assertEq(presale.STAGE_2_START_PRICE(), 4_500);
        assertEq(presale.STAGE_2_END_PRICE(), 6_000);
        assertEq(presale.STAGE_3_START_PRICE(), 6_000);
        assertEq(presale.STAGE_3_END_PRICE(), 8_500);
        assertEq(presale.STAGE_4_START_PRICE(), 8_500);
        assertEq(presale.STAGE_4_END_PRICE(), 15_000);
        assertEq(presale.STAGE_5_START_PRICE(), 15_000);
        assertEq(presale.STAGE_5_END_PRICE(), 30_000);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────

    function test_RevertWhen_InitializeWithInsufficientTokens() public {
        PyraPresale p = PyraPresale(address(new ERC1967Proxy(address(new PyraPresale()), "")));
        address poor = makeAddr("poorDeployer");
        token.transfer(poor, 1_250_000_000 * PYRA); // half the allocation

        vm.startPrank(poor);
        token.approve(address(p), type(uint256).max);
        vm.expectRevert(PyraPresale.EInsufficientTokens.selector);
        p.initialize(address(pyraAdmin), address(token), address(usdc));
        vm.stopPrank();
    }

    function test_Initialize_SucceedsWithExactAmount() public {
        PyraPresale p = PyraPresale(address(new ERC1967Proxy(address(new PyraPresale()), "")));
        address deployer = makeAddr("exactDeployer");
        token.transfer(deployer, ALLOCATION);

        vm.startPrank(deployer);
        token.approve(address(p), ALLOCATION);
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.PresaleInitialized(deployer, address(token), address(usdc), ALLOCATION, block.timestamp);
        p.initialize(address(pyraAdmin), address(token), address(usdc));
        vm.stopPrank();

        assertEq(p.currentStage(), 1);
        assertTrue(p.isActive());
        assertEq(p.usdcRaised(), 0);
        assertEq(p.tokensRemaining(), ALLOCATION);
        assertEq(token.balanceOf(address(p)), ALLOCATION);
        assertEq(token.balanceOf(deployer), 0); // pulled exactly the allocation
    }

    /// Initialize seeds every tunable to its documented default.
    function test_Initialize_SeedsDefaults() public view {
        assertEq(presale.currentStage(), 1);
        assertTrue(presale.isActive());
        assertFalse(presale.finalized());
        assertFalse(presale.parametersFrozen());
        assertEq(presale.startTime(), 1000);
        assertEq(presale.usdcRaised(), 0);
        assertEq(presale.outstandingObligations(), 0);
        assertEq(presale.usdcWithdrawCap(), DEFAULT_WITHDRAW_CAP);
        assertEq(presale.usdcWithdrawWindow(), WITHDRAW_WINDOW);
        assertEq(presale.maxPerWalletPerStage(), WALLET_CAP);
        assertEq(presale.immediateReleasePct(), 25);
        assertEq(presale.vestingDuration(), VESTING_DURATION);
        assertEq(presale.getCurrentPrice(), S1_START);
        (uint256 windowStart, uint256 windowUsed) = presale.usdcWithdrawWindowState();
        assertEq(windowStart, 0);
        assertEq(windowUsed, 0);

        uint256[5] memory starts = presale.stageStartPrices();
        uint256[5] memory ends = presale.stageEndPrices();
        uint256[5] memory expStarts = [uint256(3_500), 4_500, 6_000, 8_500, 15_000];
        uint256[5] memory expEnds = [uint256(4_500), 6_000, 8_500, 15_000, 30_000];
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(starts[i], expStarts[i]);
            assertEq(ends[i], expEnds[i]);
        }
        _assertSolvent(presale);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Purchases
    // ─────────────────────────────────────────────────────────────────────

    /// Basic stage-1 purchase (+ exact event pin).
    function test_BasicPurchase_Stage1() public {
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.TokensPurchased(alice, 1, T_1USDC_S1, C_1USDC_S1, 3_500);
        _buy(presale, alice, 1 * USDC_UNIT);

        assertEq(presale.getUserTotalPurchase(alice), T_1USDC_S1);
        assertEq(presale.usdcRaised(), C_1USDC_S1);
        assertEq(presale.outstandingObligations(), T_1USDC_S1);
        assertEq(presale.currentStage(), 1);
        assertTrue(presale.parametersFrozen());
        _assertSolvent(presale);
    }

    /// Cost is the integrated AVERAGE price, not spot. $10k is deliberately
    /// large: a small buy cannot shift the $0.000001-quantized curve at all,
    /// and this size also exercises the second (re-estimate at avg price) pass.
    function test_IntegratedPricing_UsesAveragePrice() public {
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.TokensPurchased(alice, 1, T_10K_USDC, C_10K_USDC, 3_502);
        _buy(presale, alice, 10_000 * USDC_UNIT);

        uint256 bought = presale.getUserTotalPurchase(alice);
        assertEq(bought, T_10K_USDC);
        assertEq(presale.usdcRaised(), C_10K_USDC);
        // Integrated cost strictly above the spot-at-start cost.
        assertGt(presale.usdcRaised(), (bought * S1_START) / PRICE_SCALE);
        // Guaranteed: final cost <= payment intent.
        assertLe(presale.usdcRaised(), 10_000 * USDC_UNIT);
        // Curve advanced past the start price.
        assertGt(presale.getCurrentPrice(), S1_START);
        assertLe(presale.getCurrentPrice(), S1_END);
    }

    /// Pull model: the contract pulls only the integrated cost, never the full
    /// maxPayment.
    function test_Purchase_PullsOnlyCost_NotMaxPayment() public {
        uint256 balBefore = usdc.balanceOf(alice);
        _buy(presale, alice, 100_000 * USDC_UNIT); // way over the cap cost

        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP);
        assertEq(presale.usdcRaised(), CAP_FILL_COST);
        assertEq(balBefore - usdc.balanceOf(alice), CAP_FILL_COST); // excess never left the buyer
        assertLt(presale.usdcRaised(), 100_000 * USDC_UNIT);
        _assertSolvent(presale);
    }

    function test_WalletLimit_CapsAtMaxPerStage() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);
        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP);
        assertEq(presale.getUserStagePurchase(alice, 0), WALLET_CAP);
        assertEq(presale.currentStage(), 1); // 5M of 500M sold: stage unchanged
    }

    /// AN-06. Pull model: once the wallet cap is filled, a repeat buy is a
    /// success NO-OP — no state change, no transfer, no event.
    function test_WalletLimit_NoOpAfterCapReached() public {
        _buy(presale, alice, 100_000 * USDC_UNIT); // cap filled
        uint256 balBefore = usdc.balanceOf(alice);
        uint256 raisedBefore = presale.usdcRaised();

        vm.recordLogs();
        _buy(presale, alice, 1 * USDC_UNIT);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 0, "no-op path must emit nothing");
        assertEq(usdc.balanceOf(alice), balBefore);
        assertEq(presale.usdcRaised(), raisedBefore);
        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP);
    }

    /// Weighted-average purchase time: two equal batches at t=1000 and t=5000
    /// anchor vesting at exactly t=3000.
    function test_WeightedAveragePurchaseTime() public {
        uint256 t1 = block.timestamp; // 1000
        _buy(presale, alice, 1 * USDC_UNIT);
        vm.warp(t1 + 4000); // t2 = 5000
        _buy(presale, alice, 1 * USDC_UNIT); // price unmoved: identical batch

        uint256 total = presale.getUserTotalPurchase(alice);
        assertEq(total, 2 * T_1USDC_S1);

        (uint256 tp, uint256 released, uint256 claimable) = presale.getUserVestingStatus(alice);
        assertEq(tp, total);
        assertEq(released, 0);

        uint256 immediateOnly = (total * 25) / 100;
        uint256 vestPortion = (total * 75) / 100;
        // Exact: anchor = (T1 + T2) / 2 = 3000, elapsed = 2000.
        assertEq(claimable, immediateOnly + (vestPortion * 2000) / VESTING_DURATION);
        // Bound: strictly between anchored-at-t2 and anchored-at-t1.
        assertGe(claimable, immediateOnly);
        assertLe(claimable, immediateOnly + (vestPortion * 4000) / VESTING_DURATION);
    }

    /// AN-06. Zero payment is a success NO-OP (never a revert) and does NOT
    /// freeze parameters.
    function test_ZeroPaymentPurchase_NoOp() public {
        vm.recordLogs();
        _buy(presale, alice, 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 0);
        assertEq(presale.getUserTotalPurchase(alice), 0);
        assertEq(presale.usdcRaised(), 0);
        assertFalse(presale.parametersFrozen()); // no-op paths never freeze
    }

    function test_MultipleBuyers_SameStage() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        _buy(presale, bob, 2 * USDC_UNIT);

        uint256 aliceTotal = presale.getUserTotalPurchase(alice);
        uint256 bobTotal = presale.getUserTotalPurchase(bob);
        assertGt(aliceTotal, 0);
        assertGt(bobTotal, 0);
        assertGt(bobTotal, aliceTotal);
        assertEq(presale.stageSold(1), aliceTotal + bobTotal);
    }

    function test_PurchaseAcrossStages() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        vm.prank(opsAdmin);
        presale.advanceStage();
        _buy(presale, alice, 1 * USDC_UNIT);

        uint256 s1 = presale.getUserStagePurchase(alice, 0);
        uint256 s2 = presale.getUserStagePurchase(alice, 1);
        assertEq(s1, T_1USDC_S1);
        assertEq(s2, T_1USDC_S2);
        assertGt(s1, 0);
        assertGt(s2, 0);
        assertLt(s2, s1); // higher stage price => fewer tokens for the same payment
        assertEq(presale.getUserTotalPurchase(alice), s1 + s2);
    }

    /// getCurrentPrice reflects stage progress ($10k-scale buy so the
    /// quantized curve visibly shifts).
    function test_GetCurrentPrice_ReflectsProgress() public {
        assertEq(presale.getCurrentPrice(), S1_START);
        _buy(presale, alice, 10_000 * USDC_UNIT);
        uint256 price = presale.getCurrentPrice();
        assertGt(price, S1_START);
        assertLe(price, S1_END);
    }

    function test_WalletLimit_ResetsInNewStage() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);
        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP);

        vm.prank(opsAdmin);
        presale.advanceStage();

        _buy(presale, alice, 1 * USDC_UNIT); // succeeds: per-stage caps are independent
        assertEq(presale.getUserStagePurchase(alice, 1), T_1USDC_S2);
        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP + T_1USDC_S2);
    }

    /// Per-stage recording: purchases and stageSold are booked against the
    /// stage that was active at buy time.
    function test_PerStagePurchaseRecording() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(presale.getUserStagePurchase(alice, 0), T_1USDC_S1);
        assertEq(presale.stageSold(1), T_1USDC_S1);

        vm.prank(opsAdmin);
        presale.advanceStage();

        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(presale.getUserStagePurchase(alice, 1), T_1USDC_S2);
        assertEq(presale.stageSold(2), T_1USDC_S2);
    }

    function test_RevertWhen_PurchaseAfterFinalize() public {
        vm.prank(opsAdmin);
        presale.finalizePresale();

        vm.expectRevert(PyraPresale.EPresaleNotActive.selector);
        vm.prank(alice);
        presale.purchase(1 * USDC_UNIT);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Price-math edges (USDC 6-dec x PYRA 9-dec)
    // ─────────────────────────────────────────────────────────────────────

    /// Rounding direction: the integrated cost floors, so the residue stays
    /// with the buyer (pays 999_999 of a 1_000_000 intent).
    function test_Rounding_CostFloorsInBuyerFavor() public {
        uint256 balBefore = usdc.balanceOf(alice);
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(balBefore - usdc.balanceOf(alice), C_1USDC_S1); // 1 unit dust kept
        assertEq(presale.usdcRaised(), C_1USDC_S1);
    }

    /// Sub-unit dust: 1 USDC base unit buys tokens whose floored cost is 0 —
    /// no-op path #2 (success, no state change). 2 base units cost 1.
    function test_DustPayment_NoOpAtOneUnit_ChargesAtTwo() public {
        vm.recordLogs();
        _buy(presale, alice, 1); // floor(285714 * 3500 / 1e9) == 0 -> no-op
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(presale.getUserTotalPurchase(alice), 0);
        assertFalse(presale.parametersFrozen());

        _buy(presale, alice, 2); // floor(571428 * 3500 / 1e9) == 1 -> real buy
        assertEq(presale.getUserTotalPurchase(alice), 571_428);
        assertEq(presale.usdcRaised(), 1);
        assertTrue(presale.parametersFrozen());
    }

    /// Per-wallet cap boundary: a partial fill then an overpay lands EXACTLY
    /// on the cap; the wallet is then fully capped (further buys no-op).
    function test_WalletCapBoundary_ExactFill() public {
        _buy(presale, alice, 1 * USDC_UNIT); // T_1USDC_S1 tokens
        _buy(presale, alice, 100_000 * USDC_UNIT); // clamped to cap - T_1USDC_S1

        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP); // exact boundary
        // Second chunk: avg price (3500+3510)/2 = 3505 over the remaining tokens.
        uint256 chunk2Cost = ((WALLET_CAP - T_1USDC_S1) * 3_505) / PRICE_SCALE;
        assertEq(presale.usdcRaised(), C_1USDC_S1 + chunk2Cost);

        uint256 balBefore = usdc.balanceOf(alice);
        _buy(presale, alice, 1 * USDC_UNIT); // no-op now
        assertEq(usdc.balanceOf(alice), balBefore);
        assertEq(presale.getUserTotalPurchase(alice), WALLET_CAP);
    }

    /// Stage sell-out auto-advances and the TokensPurchased event carries the
    /// PRE-advance stage (deliberate).
    function test_AutoAdvance_OnStageSellout() public {
        _raiseWalletCapToStage(presale);
        address whale = makeAddr("whale");
        usdc.mint(whale, 100_000_000 * USDC_UNIT);
        _approveBuyer(presale, whale);

        // Full stage 1: 5e17 tokens, avg (3500+4500)/2 = 4000 -> cost 2e12.
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.StageAdvanced(whale, 2);
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.TokensPurchased(whale, 1, TOKENS_PER_STAGE, 2_000_000 * USDC_UNIT, 4_000);
        _buy(presale, whale, 3_000_000 * USDC_UNIT);

        assertEq(presale.currentStage(), 2);
        assertEq(presale.stageSold(1), TOKENS_PER_STAGE);
        assertEq(presale.usdcRaised(), 2_000_000_000_000);
        _assertSolvent(presale);
    }

    /// Stage-5 sellout does NOT deactivate the presale; subsequent buys are
    /// success no-ops (path #1 for the capped whale, path #2 for fresh buyers).
    function test_Stage5Sellout_StaysActive_FurtherBuysNoOp() public {
        _raiseWalletCapToStage(presale);
        address whale = makeAddr("whale");
        usdc.mint(whale, 100_000_000 * USDC_UNIT);
        _approveBuyer(presale, whale);
        for (uint256 i = 0; i < 5; ++i) {
            _buy(presale, whale, 20_000_000 * USDC_UNIT);
        }

        // Stage avgs 4000/5250/7250/11750/22500 over 5e8 whole tokens each.
        assertEq(presale.usdcRaised(), 25_375_000_000_000);
        assertEq(presale.currentStage(), 5);
        assertTrue(presale.isActive()); // never auto-finalizes
        assertEq(presale.outstandingObligations(), ALLOCATION);
        assertEq(presale.withdrawableUnsold(), 0);
        for (uint8 s = 1; s <= 5; ++s) {
            assertEq(presale.stageSold(s), TOKENS_PER_STAGE);
        }

        // Whale: wallet cap exhausted in stage 5 -> path #1 no-op.
        vm.recordLogs();
        _buy(presale, whale, 1 * USDC_UNIT);
        assertEq(vm.getRecordedLogs().length, 0);
        // Fresh buyer: stage sold out -> actualTokens 0 -> path #2 no-op.
        vm.recordLogs();
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(vm.getRecordedLogs().length, 0);

        // Everything sold: nothing withdrawable as unsold even after finalize.
        vm.startPrank(opsAdmin);
        presale.finalizePresale();
        vm.expectRevert(PyraPresale.EInsufficientTokens.selector);
        presale.withdrawUnsoldTokens();
        vm.stopPrank();

        // Vesting is unaffected: the whale claims the immediate tranche.
        vm.prank(whale);
        presale.claimVested();
        assertEq(token.balanceOf(whale), (ALLOCATION * 25) / 100);
        _assertSolvent(presale);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Vesting + claims (incl. boundary timestamps)
    // ─────────────────────────────────────────────────────────────────────

    function test_ClaimVested_25PctImmediate() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        uint256 total = presale.getUserTotalPurchase(alice);
        uint256 immediate = (total * 25) / 100;

        (,, uint256 claimable) = presale.getUserVestingStatus(alice);
        assertEq(claimable, immediate);

        vm.expectEmit(true, true, true, true);
        emit PyraPresale.TokensVested(alice, immediate, immediate);
        vm.prank(alice);
        presale.claimVested();

        (, uint256 released, uint256 remaining) = presale.getUserVestingStatus(alice);
        assertEq(released, immediate);
        assertEq(remaining, 0);
        assertEq(token.balanceOf(alice), immediate);
        assertEq(presale.outstandingObligations(), total - immediate);
        _assertSolvent(presale);
    }

    function test_ClaimVested_FullAfter90Days() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);

        vm.warp(t0 + VESTING_DURATION + 1);
        (uint256 total,, uint256 claimable) = presale.getUserVestingStatus(alice);
        assertLe(total - claimable, 1); // both tranches floor separately

        vm.prank(alice);
        presale.claimVested();
        (, uint256 released, uint256 remaining) = presale.getUserVestingStatus(alice);
        assertLe(total - released, 1);
        assertEq(remaining, 0);
        assertEq(token.balanceOf(alice), released);
    }

    function test_ClaimVested_UnderflowGuard() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);

        vm.warp(t0 + VESTING_DURATION / 3);
        vm.prank(alice);
        presale.claimVested();

        // +1s: claim only if the view says claimable > 0 (locks in
        // no-arithmetic-revert on tiny deltas).
        vm.warp(t0 + VESTING_DURATION / 3 + 1);
        (,, uint256 c) = presale.getUserVestingStatus(alice);
        if (c > 0) {
            vm.prank(alice);
            presale.claimVested();
        }

        vm.warp(t0 + VESTING_DURATION + 1);
        vm.prank(alice);
        presale.claimVested();

        (uint256 total, uint256 released, uint256 remaining) = presale.getUserVestingStatus(alice);
        assertLe(total - released, 1);
        assertEq(remaining, 0);
        assertEq(token.balanceOf(alice), released);
    }

    function test_RevertWhen_ClaimTwiceAtSameTimestamp() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);

        vm.warp(t0 + VESTING_DURATION / 2);
        vm.startPrank(alice);
        presale.claimVested();
        vm.expectRevert(PyraPresale.ENoTokensToVest.selector);
        presale.claimVested();
        vm.stopPrank();
    }

    /// Vesting at the midpoint — exact 62.5% floor math.
    function test_PartialVesting_AtMidpoint() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);
        uint256 total = presale.getUserTotalPurchase(alice);

        vm.warp(t0 + VESTING_DURATION / 2); // 45 days
        (,, uint256 claimable) = presale.getUserVestingStatus(alice);
        uint256 expected = (total * 25) / 100 + (((total * 75) / 100) * (VESTING_DURATION / 2)) / VESTING_DURATION;
        assertEq(claimable, expected);
    }

    /// Nothing is delivered at buy time; only claims drain the pool.
    function test_TokensRemaining_DecreasesOnlyOnClaim() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(presale.tokensRemaining(), ALLOCATION); // untouched by the buy

        vm.warp(t0 + VESTING_DURATION + 1);
        vm.prank(alice);
        presale.claimVested();

        (uint256 total, uint256 released,) = presale.getUserVestingStatus(alice);
        assertEq(presale.tokensRemaining(), ALLOCATION - released);
        assertLe(total - released, 1);
        _assertSolvent(presale);
    }

    /// Claim math at the boundary timestamps — start (elapsed 0), mid, 1s
    /// before end, exactly end (>= flips to the full tranche), after.
    function test_VestingBoundaries_StartMidEndAfter() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);
        uint256 total = presale.getUserTotalPurchase(alice);
        uint256 immediate = (total * 25) / 100;
        uint256 vestAmt = (total * 75) / 100;

        (,, uint256 c) = presale.getUserVestingStatus(alice); // start
        assertEq(c, immediate);

        vm.warp(t0 + VESTING_DURATION / 2); // mid
        (,, c) = presale.getUserVestingStatus(alice);
        assertEq(c, immediate + (vestAmt * (VESTING_DURATION / 2)) / VESTING_DURATION);

        vm.warp(t0 + VESTING_DURATION - 1); // 1s before end: still linear
        (,, c) = presale.getUserVestingStatus(alice);
        assertEq(c, immediate + (vestAmt * (VESTING_DURATION - 1)) / VESTING_DURATION);
        assertLt(c, immediate + vestAmt);

        vm.warp(t0 + VESTING_DURATION); // exactly end: elapsed >= duration
        (,, c) = presale.getUserVestingStatus(alice);
        assertEq(c, immediate + vestAmt);
        assertLe(total - c, 1);

        vm.warp(t0 + VESTING_DURATION + 365 days); // after end: capped
        (,, c) = presale.getUserVestingStatus(alice);
        assertEq(c, immediate + vestAmt);
    }

    /// Claiming with no purchase record.
    function test_RevertWhen_ClaimWithoutPurchase() public {
        vm.expectRevert(PyraPresale.EPurchaseNotFound.selector);
        vm.prank(alice);
        presale.claimVested();
    }

    /// AN-01 regression: vesting math at the maximum conceivable total does not
    /// overflow. uint256 removes the hazard outright — kept as a behavior pin.
    function test_Harness_VestingAtMaxCap_NoOverflow() public {
        PresaleHarness h = _deployHarness();
        uint256 total = WALLET_CAP * 5; // max conceivable total for one wallet
        h.insertPurchaseForTesting(bob, total, block.timestamp);
        assertEq(h.outstandingObligations(), total);

        vm.warp(block.timestamp + VESTING_DURATION + 1);
        (uint256 tp,, uint256 claimable) = h.getUserVestingStatus(bob);
        assertEq(tp, total);
        assertLe(total - claimable, 1);

        vm.prank(bob);
        h.claimVested();
        assertLe(total - token.balanceOf(bob), 1);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Pre-freeze setters + freeze semantics
    // ─────────────────────────────────────────────────────────────────────

    /// Vesting duration of 5y + 1s is rejected.
    function test_RevertWhen_VestingDurationExceedsMax() public {
        vm.expectRevert(PyraPresale.EInvalidBounds.selector);
        vm.prank(superAdmin);
        presale.setVestingTerms(25, MAX_VESTING_DURATION + 1);
    }

    /// Vesting duration of exactly 5y is accepted.
    function test_SetVestingTerms_AcceptsMaxDuration() public {
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.VestingTermsUpdated(superAdmin, 25, 25, VESTING_DURATION, MAX_VESTING_DURATION, block.timestamp);
        vm.prank(superAdmin);
        presale.setVestingTerms(25, MAX_VESTING_DURATION);
        assertEq(presale.vestingDuration(), MAX_VESTING_DURATION);
        assertEq(presale.immediateReleasePct(), 25);
    }

    function test_RevertWhen_VestingDurationZero() public {
        vm.expectRevert(PyraPresale.EInvalidBounds.selector);
        vm.prank(superAdmin);
        presale.setVestingTerms(25, 0);
    }

    /// Release pct hard cap: 101 reverts, 100 is legal.
    function test_SetVestingTerms_PctBounds() public {
        vm.startPrank(superAdmin);
        vm.expectRevert(PyraPresale.EInvalidReleasePct.selector);
        presale.setVestingTerms(101, VESTING_DURATION);
        presale.setVestingTerms(100, VESTING_DURATION);
        vm.stopPrank();
        assertEq(presale.immediateReleasePct(), 100);

        // Functional: pct=100 releases everything at purchase time, exactly.
        _buy(presale, alice, 1 * USDC_UNIT);
        (,, uint256 claimable) = presale.getUserVestingStatus(alice);
        assertEq(claimable, T_1USDC_S1);
        vm.prank(alice);
        presale.claimVested();
        assertEq(token.balanceOf(alice), T_1USDC_S1);
    }

    /// pct=0: nothing immediate — claim at purchase time reverts, full amount
    /// vests linearly with zero rounding loss (100-0 tranche).
    function test_SetVestingTerms_ZeroImmediatePct() public {
        vm.prank(superAdmin);
        presale.setVestingTerms(0, VESTING_DURATION);

        uint256 t0 = block.timestamp;
        _buy(presale, alice, 1 * USDC_UNIT);
        vm.expectRevert(PyraPresale.ENoTokensToVest.selector);
        vm.prank(alice);
        presale.claimVested();

        vm.warp(t0 + VESTING_DURATION);
        vm.prank(alice);
        presale.claimVested();
        assertEq(token.balanceOf(alice), T_1USDC_S1); // exact: single tranche
    }

    function test_RevertWhen_StagePricesCrossStageStepDown() public {
        // ends[0] = 2500 > starts[1] = 2000: ladder steps DOWN between stages.
        vm.expectRevert(PyraPresale.EInvalidBounds.selector);
        vm.prank(superAdmin);
        presale.setStagePrices(_ladder5(1_000, 2_000, 3_000, 4_000, 5_000), _ladder5(2_500, 2_500, 3_500, 4_500, 5_500));
    }

    /// A monotonic ladder with end[i] == start[i+1] is accepted.
    function test_SetStagePrices_AcceptsMonotonicLadder() public {
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.StagePricesUpdated(superAdmin, block.timestamp);
        vm.prank(superAdmin);
        presale.setStagePrices(_ladder5(1_000, 2_000, 3_000, 4_000, 5_000), _ladder5(2_000, 3_000, 4_000, 5_000, 6_000));

        uint256[5] memory starts = presale.stageStartPrices();
        uint256[5] memory ends = presale.stageEndPrices();
        for (uint256 i = 0; i < 5; ++i) {
            assertEq(starts[i], (i + 1) * 1_000);
            assertEq(ends[i], (i + 2) * 1_000);
        }
        assertEq(presale.getCurrentPrice(), 1_000); // stage 1 now starts at the new price
    }

    /// A wrong array length is rejected — for either array.
    function test_RevertWhen_StagePricesWrongLength() public {
        uint256[] memory four = new uint256[](4);
        four[0] = 1_000;
        four[1] = 2_000;
        four[2] = 3_000;
        four[3] = 4_000;
        uint256[] memory five = _ladder5(1_000, 2_000, 3_000, 4_000, 5_000);

        vm.startPrank(superAdmin);
        vm.expectRevert(PyraPresale.EInvalidStagePrices.selector);
        presale.setStagePrices(four, five);
        vm.expectRevert(PyraPresale.EInvalidStagePrices.selector);
        presale.setStagePrices(five, four);
        vm.stopPrank();
    }

    /// Per-stage validation: start == 0 and end < start both reject with
    /// EInvalidStagePrices (spec §4.8 checks 6a/6b).
    function test_RevertWhen_StagePricesInvalidPerStage() public {
        vm.startPrank(superAdmin);
        vm.expectRevert(PyraPresale.EInvalidStagePrices.selector);
        presale.setStagePrices(_ladder5(0, 2_000, 3_000, 4_000, 5_000), _ladder5(2_000, 3_000, 4_000, 5_000, 6_000));
        vm.expectRevert(PyraPresale.EInvalidStagePrices.selector);
        presale.setStagePrices(_ladder5(1_000, 2_000, 3_000, 4_000, 5_000), _ladder5(2_000, 3_000, 2_999, 5_000, 6_000));
        vm.stopPrank();
    }

    /// After the first purchase all three pre-freeze setters revert; the
    /// withdraw-cap knob is NOT frozen.
    function test_RevertWhen_SettersAfterFirstPurchase() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        assertTrue(presale.parametersFrozen());

        vm.startPrank(superAdmin);
        vm.expectRevert(PyraPresale.EParametersFrozen.selector);
        presale.setMaxPerWalletPerStage(1);
        vm.expectRevert(PyraPresale.EParametersFrozen.selector);
        presale.setVestingTerms(10, VESTING_DURATION);
        vm.expectRevert(PyraPresale.EParametersFrozen.selector);
        presale.setStagePrices(_ladder5(1_000, 2_000, 3_000, 4_000, 5_000), _ladder5(2_000, 3_000, 4_000, 5_000, 6_000));

        // Security knob stays live for the whole presale (deliberate).
        presale.setUsdcWithdrawCap(5_000 * USDC_UNIT, 3_600);
        vm.stopPrank();
        assertEq(presale.usdcWithdrawCap(), 5_000 * USDC_UNIT);
        assertEq(presale.usdcWithdrawWindow(), 3_600);
    }

    /// A buyer AND a regular ops admin both fail the super-admin gate.
    function test_RevertWhen_NonSuperAdminSetsMaxPerWallet() public {
        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, alice));
        vm.prank(alice);
        presale.setMaxPerWalletPerStage(1);

        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        vm.prank(opsAdmin);
        presale.setMaxPerWalletPerStage(1);
    }

    /// Cap 0 pauses purchases via the no-op path — and since no purchase
    /// SUCCEEDS, parameters never freeze and the setter stays usable.
    function test_MaxPerWalletZero_PausesPurchases_WithoutFreezing() public {
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.MaxPerWalletUpdated(superAdmin, WALLET_CAP, 0, block.timestamp);
        vm.prank(superAdmin);
        presale.setMaxPerWalletPerStage(0);

        vm.recordLogs();
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(vm.getRecordedLogs().length, 0); // path #1 no-op
        assertEq(presale.getUserTotalPurchase(alice), 0);
        assertFalse(presale.parametersFrozen());

        // Un-pause and buy normally.
        vm.prank(superAdmin);
        presale.setMaxPerWalletPerStage(WALLET_CAP);
        _buy(presale, alice, 1 * USDC_UNIT);
        assertEq(presale.getUserTotalPurchase(alice), T_1USDC_S1);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Stage advancement
    // ─────────────────────────────────────────────────────────────────────

    /// Manual advance walks 1 -> 2 -> 3 -> 4 -> 5.
    function test_AdvanceStage_Progression() public {
        assertEq(presale.currentStage(), 1);
        vm.startPrank(opsAdmin);
        for (uint8 expected = 2; expected <= 5; ++expected) {
            vm.expectEmit(true, true, true, true);
            emit PyraPresale.StageAdvanced(opsAdmin, expected);
            presale.advanceStage();
            assertEq(presale.currentStage(), expected);
        }
        vm.stopPrank();
    }

    function test_RevertWhen_AdvanceBeyondStage5() public {
        vm.startPrank(opsAdmin);
        for (uint256 i = 0; i < 4; ++i) {
            presale.advanceStage();
        }
        assertEq(presale.currentStage(), 5);
        vm.expectRevert(PyraPresale.EInvalidStage.selector);
        presale.advanceStage();
        vm.stopPrank();
    }

    function test_RevertWhen_NonAdminAdvancesStage() public {
        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, ADMIN_ROLE, alice));
        vm.prank(alice);
        presale.advanceStage();
    }

    /// Advancing a finalized presale hits the still-active gate (check order:
    /// admin first, then active).
    function test_RevertWhen_AdvanceAfterFinalize() public {
        vm.startPrank(opsAdmin);
        presale.finalizePresale();
        vm.expectRevert(PyraPresale.EPresaleNotActive.selector);
        presale.advanceStage();
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Finalization (incl. idempotence)
    // ─────────────────────────────────────────────────────────────────────

    function test_RevertWhen_NonAdminFinalizes() public {
        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, ADMIN_ROLE, alice));
        vm.prank(alice);
        presale.finalizePresale();
    }

    /// Finalize is idempotent, irreversible, callable before any sale.
    function test_Finalize_IdempotentAndIrreversible() public {
        vm.startPrank(opsAdmin);
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.PresaleFinalized(opsAdmin, block.timestamp);
        presale.finalizePresale();
        assertFalse(presale.isActive());
        assertTrue(presale.finalized());

        presale.finalizePresale(); // idempotent second call
        assertFalse(presale.isActive());
        assertTrue(presale.finalized());
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Raised-USDC withdrawals (+ check-order pins)
    // ─────────────────────────────────────────────────────────────────────

    /// Admin-only: withdraw exactly the raised amount mid-presale (no finalize
    /// needed).
    function test_WithdrawRaisedUsdc_Admin() public {
        _buy(presale, alice, 1 * USDC_UNIT);
        uint256 raised = presale.usdcRaised();
        assertEq(raised, C_1USDC_S1);

        vm.expectEmit(true, true, true, true);
        emit PyraPresale.RaisedUsdcWithdrawn(opsAdmin, raised, 0, block.timestamp);
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(raised);

        assertEq(usdc.balanceOf(opsAdmin), raised);
        assertEq(presale.usdcRaised(), 0);
        _assertSolvent(presale);
    }

    /// Non-admin caller with amount 0: the admin check fires FIRST (locks in
    /// check order).
    function test_RevertWhen_NonAdminWithdrawsRaised_AdminCheckFirst() public {
        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, ADMIN_ROLE, alice));
        vm.prank(alice);
        presale.withdrawRaisedUsdc(0);
    }

    /// Audit L1: a zero withdrawal amount is rejected.
    function test_RevertWhen_WithdrawRaisedZero() public {
        vm.expectRevert(PyraPresale.EZeroWithdrawAmount.selector);
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(0);
    }

    /// Audit L1: withdrawals are capped at the per-window limit.
    function test_RevertWhen_WithdrawExceedsWindowCap() public {
        _buy(presale, alice, 100_000 * USDC_UNIT); // raised 17,525 USDC >> the 1k cap

        vm.startPrank(opsAdmin);
        presale.withdrawRaisedUsdc(DEFAULT_WITHDRAW_CAP); // exactly at cap: succeeds
        vm.expectRevert(PyraPresale.EUsdcWithdrawCapExceeded.selector);
        presale.withdrawRaisedUsdc(1); // 1 base unit over, same window
        vm.stopPrank();
        assertEq(usdc.balanceOf(opsAdmin), DEFAULT_WITHDRAW_CAP);
    }

    /// Audit L1: cap = 0 pauses raised-USDC withdrawals entirely.
    function test_RevertWhen_WithdrawsPausedByZeroCap() public {
        vm.prank(superAdmin);
        presale.setUsdcWithdrawCap(0, WITHDRAW_WINDOW);
        vm.warp(block.timestamp + 1);

        vm.expectRevert(PyraPresale.EUsdcWithdrawsPaused.selector);
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(1);
    }

    /// Audit L1: the window rolls after expiry, restoring the full cap.
    function test_WithdrawWindow_RollsAfterExpiry() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);
        uint256 t0 = block.timestamp;

        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(DEFAULT_WITHDRAW_CAP);
        (uint256 wStart, uint256 wUsed) = presale.usdcWithdrawWindowState();
        assertEq(wStart, 0); // first-ever withdrawal never rolled the window
        assertEq(wUsed, DEFAULT_WITHDRAW_CAP);

        vm.warp(t0 + WITHDRAW_WINDOW + 1); // fresh window
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(DEFAULT_WITHDRAW_CAP); // full cap again
        assertEq(usdc.balanceOf(opsAdmin), 2 * DEFAULT_WITHDRAW_CAP);

        (wStart, wUsed) = presale.usdcWithdrawWindowState();
        assertEq(wStart, t0 + WITHDRAW_WINDOW + 1);
        assertEq(wUsed, DEFAULT_WITHDRAW_CAP);
    }

    /// Audit L1: raising the cap raises the ceiling for later withdrawals.
    function test_SetWithdrawCap_RaisesCeiling() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);

        vm.expectEmit(true, true, true, true);
        emit PyraPresale.UsdcWithdrawCapUpdated(
            superAdmin, DEFAULT_WITHDRAW_CAP, 4_000 * USDC_UNIT, WITHDRAW_WINDOW, WITHDRAW_WINDOW, block.timestamp
        );
        vm.prank(superAdmin);
        presale.setUsdcWithdrawCap(4_000 * USDC_UNIT, WITHDRAW_WINDOW);
        assertEq(presale.usdcWithdrawCap(), 4_000 * USDC_UNIT);

        // A single 3k withdraw (over the old 1k default) now succeeds.
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(3_000 * USDC_UNIT);
        assertEq(usdc.balanceOf(opsAdmin), 3_000 * USDC_UNIT);
    }

    /// Changing the cap does NOT reset the current window's usage (deliberate).
    function test_SetWithdrawCap_DoesNotResetWindowUsage() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);

        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(DEFAULT_WITHDRAW_CAP); // used = 1k

        vm.prank(superAdmin);
        presale.setUsdcWithdrawCap(1_500 * USDC_UNIT, WITHDRAW_WINDOW);

        vm.startPrank(opsAdmin);
        vm.expectRevert(PyraPresale.EUsdcWithdrawCapExceeded.selector);
        presale.withdrawRaisedUsdc(1_000 * USDC_UNIT); // 1k used + 1k > 1.5k
        presale.withdrawRaisedUsdc(500 * USDC_UNIT); // exactly fills the new cap
        vm.stopPrank();
        assertEq(usdc.balanceOf(opsAdmin), 1_500 * USDC_UNIT);
    }

    /// Window length 0 is rejected with the ZERO-AMOUNT error — deliberate
    /// error reuse (to pause withdrawals, set cap = 0 instead).
    function test_RevertWhen_SetCapWindowZero() public {
        vm.expectRevert(PyraPresale.EZeroWithdrawAmount.selector);
        vm.prank(superAdmin);
        presale.setUsdcWithdrawCap(1, 0);
    }

    /// Check order: the cap check fires BEFORE the balance check; within cap,
    /// over balance reverts EInsufficientPayment.
    function test_WithdrawRaised_CapCheckBeforeBalanceCheck() public {
        _buy(presale, alice, 1 * USDC_UNIT); // raised = 999_999 only

        vm.startPrank(opsAdmin);
        // Violates BOTH cap (2e9 > 1e9) and balance: cap error wins.
        vm.expectRevert(PyraPresale.EUsdcWithdrawCapExceeded.selector);
        presale.withdrawRaisedUsdc(2 * DEFAULT_WITHDRAW_CAP);
        // Within cap, over balance.
        vm.expectRevert(PyraPresale.EInsufficientPayment.selector);
        presale.withdrawRaisedUsdc(DEFAULT_WITHDRAW_CAP);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Unsold-token withdrawal
    // ─────────────────────────────────────────────────────────────────────

    /// Audit C1: withdrawing unsold tokens preserves buyer obligations.
    function test_C1_WithdrawUnsold_PreservesObligations() public {
        uint256 t0 = block.timestamp;
        _buy(presale, alice, 10 * USDC_UNIT);
        uint256 bought = presale.getUserTotalPurchase(alice);
        assertEq(bought, T_10USDC_S1);

        assertEq(presale.tokensRemaining(), ALLOCATION);
        assertEq(presale.outstandingObligations(), bought);
        assertEq(presale.withdrawableUnsold(), ALLOCATION - bought);

        vm.startPrank(opsAdmin);
        presale.finalizePresale();
        vm.expectEmit(true, true, true, true);
        emit PyraPresale.UnsoldTokensWithdrawn(opsAdmin, ALLOCATION - bought);
        presale.withdrawUnsoldTokens();
        vm.stopPrank();

        assertEq(token.balanceOf(opsAdmin), ALLOCATION - bought);
        assertEq(presale.tokensRemaining(), bought); // buyer-owed tokens stay
        assertEq(presale.outstandingObligations(), bought);
        assertEq(presale.withdrawableUnsold(), 0);

        // Repeat call: no new slack ever appears (claims decrement both sides).
        vm.expectRevert(PyraPresale.EInsufficientTokens.selector);
        vm.prank(opsAdmin);
        presale.withdrawUnsoldTokens();

        // Vesting was not impaired: full claim after 91 days.
        vm.warp(t0 + VESTING_DURATION + 86_400);
        vm.prank(alice);
        presale.claimVested();
        assertLe(bought - token.balanceOf(alice), 1);
        _assertSolvent(presale);
    }

    /// Audit C1: withdrawing unsold REVERTS when the pool is fully obligated
    /// (+ the pool < obligations invariant branch, harness-forced).
    function test_Harness_RevertWhen_WithdrawUnsold_PoolFullyObligated() public {
        PresaleHarness h = _deployHarness();
        h.insertPurchaseForTesting(bob, ALLOCATION, block.timestamp); // entire pool owed
        assertEq(h.withdrawableUnsold(), 0);

        vm.startPrank(opsAdmin);
        h.finalizePresale();
        vm.expectRevert(PyraPresale.EInsufficientTokens.selector);
        h.withdrawUnsoldTokens();
        vm.stopPrank();

        // Invariant breach (pool < obligations): same error, and the
        // withdrawable preview saturates to 0 instead of reverting.
        h.setObligationsForTesting(ALLOCATION + 1);
        assertEq(h.withdrawableUnsold(), 0);
        vm.expectRevert(PyraPresale.EInsufficientTokens.selector);
        vm.prank(opsAdmin);
        h.withdrawUnsoldTokens();
    }

    /// withdrawUnsoldTokens before finalize deliberately reuses the NOT-ACTIVE error.
    function test_RevertWhen_WithdrawUnsoldBeforeFinalize() public {
        vm.expectRevert(PyraPresale.EPresaleNotActive.selector);
        vm.prank(opsAdmin);
        presale.withdrawUnsoldTokens();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Views (index conventions, unknown users, saturation)
    // ─────────────────────────────────────────────────────────────────────

    function test_Views_UnknownUserReturnsZeros() public view {
        assertEq(presale.getUserTotalPurchase(alice), 0);
        assertEq(presale.getUserStagePurchase(alice, 0), 0);
        assertEq(presale.getUserStagePurchase(alice, 99), 0); // no bounds hit for unknown users
        (uint256 t, uint256 r, uint256 c) = presale.getUserVestingStatus(alice);
        assertEq(t, 0);
        assertEq(r, 0);
        assertEq(c, 0);
    }

    /// Deliberate: an out-of-range stage index REVERTS for a KNOWN user
    /// (0-indexed view), and the 1-indexed stageSold reverts at 0 and 6.
    function test_RevertWhen_ViewIndexOutOfRange() public {
        _buy(presale, alice, 1 * USDC_UNIT);

        vm.expectRevert(stdError.indexOOBError);
        presale.getUserStagePurchase(alice, 5);

        vm.expectRevert(stdError.arithmeticError); // stage - 1 underflows
        presale.stageSold(0);
        vm.expectRevert(stdError.indexOOBError);
        presale.stageSold(6);
        assertEq(presale.stageSold(1), T_1USDC_S1); // 1-indexed happy path
        assertEq(presale.stageSold(5), 0);
    }

    /// Raw window state view never simulates a roll.
    function test_WindowStateView_ReturnsRawState() public {
        _buy(presale, alice, 100_000 * USDC_UNIT);
        vm.prank(opsAdmin);
        presale.withdrawRaisedUsdc(1 * USDC_UNIT);

        (uint256 wStart, uint256 wUsed) = presale.usdcWithdrawWindowState();
        assertEq(wStart, 0); // never rolled: raw stored value
        assertEq(wUsed, 1 * USDC_UNIT);

        // Far past expiry the view STILL returns the stored (unrolled) state.
        vm.warp(block.timestamp + 10 * WITHDRAW_WINDOW);
        (wStart, wUsed) = presale.usdcWithdrawWindowState();
        assertEq(wStart, 0);
        assertEq(wUsed, 1 * USDC_UNIT);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initializer + UUPS upgrade auth
    // ─────────────────────────────────────────────────────────────────────

    function test_RevertWhen_InitializerRunsTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        presale.initialize(address(pyraAdmin), address(token), address(usdc));
    }

    /// Audit L4: zero admin/token/usdc addresses must be rejected at initialize.
    function test_RevertWhen_InitializeZeroAddress() public {
        PyraPresale impl = new PyraPresale();
        vm.expectRevert(PyraPresale.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(PyraPresale.initialize, (address(0), address(token), address(usdc))));
        vm.expectRevert(PyraPresale.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(PyraPresale.initialize, (address(pyraAdmin), address(0), address(usdc))));
        vm.expectRevert(PyraPresale.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(PyraPresale.initialize, (address(pyraAdmin), address(token), address(0))));
    }

    function test_RevertWhen_ImplementationInitializedDirectly() public {
        PyraPresale impl = new PyraPresale(); // constructor disables initializers
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(pyraAdmin), address(token), address(usdc));
    }

    function test_RevertWhen_NonSuperAdminUpgrades() public {
        PyraPresale newImpl = new PyraPresale();

        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, attacker));
        vm.prank(attacker);
        presale.upgradeToAndCall(address(newImpl), "");

        // A regular ops admin must not be able to upgrade either.
        vm.expectRevert(abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        vm.prank(opsAdmin);
        presale.upgradeToAndCall(address(newImpl), "");
    }

    function test_SuperAdminCanUpgrade_StatePreserved() public {
        _buy(presale, alice, 1 * USDC_UNIT);

        PyraPresale newImpl = new PyraPresale();
        vm.prank(superAdmin);
        presale.upgradeToAndCall(address(newImpl), "");

        // Sale state survives the upgrade.
        assertEq(presale.getUserTotalPurchase(alice), T_1USDC_S1);
        assertEq(presale.usdcRaised(), C_1USDC_S1);
        assertEq(presale.currentStage(), 1);
        assertTrue(presale.parametersFrozen());
        assertEq(presale.tokensRemaining(), ALLOCATION);

        // And the contract remains functional.
        _buy(presale, bob, 1 * USDC_UNIT);
        assertEq(presale.getUserTotalPurchase(bob), T_1USDC_S1);
        _assertSolvent(presale);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Unauthorized-role revert for EVERY gated function
    // ─────────────────────────────────────────────────────────────────────

    function test_RevertWhen_UnauthorizedCallsAdminGatedFunctions() public {
        bytes memory err = abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, ADMIN_ROLE, attacker);
        vm.startPrank(attacker);
        vm.expectRevert(err);
        presale.advanceStage();
        vm.expectRevert(err);
        presale.finalizePresale();
        vm.expectRevert(err);
        presale.withdrawRaisedUsdc(1);
        vm.expectRevert(err);
        presale.withdrawUnsoldTokens();
        vm.stopPrank();

        // The orchestrator hot key holds no presale authority either.
        bytes memory errOrch = abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, ADMIN_ROLE, orchestrator);
        vm.startPrank(orchestrator);
        vm.expectRevert(errOrch);
        presale.advanceStage();
        vm.expectRevert(errOrch);
        presale.finalizePresale();
        vm.expectRevert(errOrch);
        presale.withdrawRaisedUsdc(1);
        vm.expectRevert(errOrch);
        presale.withdrawUnsoldTokens();
        vm.stopPrank();
    }

    function test_RevertWhen_UnauthorizedCallsSuperAdminGatedFunctions() public {
        bytes memory err = abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, attacker);
        uint256[] memory starts = _ladder5(1_000, 2_000, 3_000, 4_000, 5_000);
        uint256[] memory ends = _ladder5(2_000, 3_000, 4_000, 5_000, 6_000);

        vm.startPrank(attacker);
        vm.expectRevert(err);
        presale.setUsdcWithdrawCap(1, 1);
        vm.expectRevert(err);
        presale.setStagePrices(starts, ends);
        vm.expectRevert(err);
        presale.setMaxPerWalletPerStage(1);
        vm.expectRevert(err);
        presale.setVestingTerms(25, VESTING_DURATION);
        vm.stopPrank();

        // A regular ops admin fails the super-admin gate too (the super-admin
        // set is strictly smaller than the admin set).
        bytes memory errOps = abi.encodeWithSelector(PyraPresale.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin);
        vm.startPrank(opsAdmin);
        vm.expectRevert(errOps);
        presale.setUsdcWithdrawCap(1, 1);
        vm.expectRevert(errOps);
        presale.setStagePrices(starts, ends);
        vm.expectRevert(errOps);
        presale.setVestingTerms(25, VESTING_DURATION);
        vm.stopPrank();
    }

    /// The super admin passes every regular-admin check.
    function test_SuperAdminPassesAdminGates() public {
        _buy(presale, alice, 1 * USDC_UNIT);

        vm.startPrank(superAdmin);
        presale.advanceStage();
        assertEq(presale.currentStage(), 2);

        presale.withdrawRaisedUsdc(C_1USDC_S1);
        assertEq(usdc.balanceOf(superAdmin), C_1USDC_S1);

        presale.finalizePresale();
        presale.withdrawUnsoldTokens();
        vm.stopPrank();
        assertEq(token.balanceOf(superAdmin), ALLOCATION - T_1USDC_S1);
    }
}
