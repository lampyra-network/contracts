// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {PyraTreasury} from "../src/PyraTreasury.sol";
import {MockPYRA} from "./mocks/MockPYRA.sol";
import {PyraAdmin} from "../src/PyraAdmin.sol";

/// @notice Full behavioural suite for PyraTreasury: distribution + supply lock,
///         team vesting, capped withdrawals, cap setters, pool rebalance and
///         inflows, plus the spec-gap cases and the proxy-level cases
///         (initializer, UUPS upgrade auth, per-function unauthorized reverts).
contract PyraTreasuryTest is Test {
    // 1 PYRA = 1e9 base units (token has 9 decimals).
    uint256 private constant PYRA = 1e9;
    uint256 private constant TOTAL_SUPPLY = 10_000_000_000 * PYRA; // 1e19

    // Vesting durations, in seconds.
    uint256 private constant ONE_YEAR = 31_536_000;
    uint256 private constant FOUR_YEARS = 126_230_400;

    bytes32 private constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    PyraAdmin internal pyraAdmin;
    PyraTreasury internal treasury;
    MockPYRA internal token;

    address internal superAdmin = makeAddr("superAdmin");
    address internal opsAdmin = makeAddr("opsAdmin");
    address internal orchestrator = makeAddr("orchestrator");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal attacker = makeAddr("attacker");

    function setUp() public {
        pyraAdmin = new PyraAdmin(0, superAdmin);
        vm.startPrank(superAdmin);
        pyraAdmin.grantRole(ADMIN_ROLE, opsAdmin);
        pyraAdmin.grantRole(ORCHESTRATOR_ROLE, orchestrator);
        vm.stopPrank();

        // Every test starts from a deployed, distribution-initialized treasury.
        (treasury, token) = _deployTreasury();
        vm.prank(opsAdmin);
        treasury.initializeDistribution();
    }

    /// @dev Deploys a fresh (treasury proxy, token) pair. The token mints the full
    ///      supply to the treasury proxy in its constructor, so the proxy must be
    ///      initialized with the token's precomputed address.
    function _deployTreasury() internal returns (PyraTreasury t, MockPYRA tok) {
        PyraTreasury impl = new PyraTreasury();
        uint256 nonce = vm.getNonce(address(this));
        address predictedToken = vm.computeCreateAddress(address(this), nonce + 1);
        t = PyraTreasury(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(PyraTreasury.initialize, (address(pyraAdmin), predictedToken))
                )
            )
        );
        tok = new MockPYRA(address(t));
        assertEq(address(tok), predictedToken, "token address prediction mismatch");
    }

    /// @dev Raises all five withdrawal caps to the full supply (10B) so that tests
    ///      which are not about caps are never throttled by them.
    function _raiseAllCaps() internal {
        vm.startPrank(superAdmin);
        treasury.setPresaleCap(TOTAL_SUPPLY, 0);
        treasury.setCommunityCap(TOTAL_SUPPLY, 0);
        treasury.setLiquidityCap(TOTAL_SUPPLY, 0);
        treasury.setReserveCap(TOTAL_SUPPLY, 0);
        treasury.setFeeCap(TOTAL_SUPPLY, 0);
        vm.stopPrank();
    }

    /// @dev Invariant: the treasury's real token balance backs all internal accounting.
    function _assertSolvent() internal {
        uint256 poolsSum = treasury.presalePoolBalance() + treasury.teamPoolBalance()
            + treasury.liquidityPoolBalance() + treasury.communityPoolBalance() + treasury.reservePoolBalance()
            + treasury.feePoolBalance();
        assertEq(token.balanceOf(address(treasury)), poolsSum + treasury.vestingEscrow(), "treasury solvency");
    }

    // =====================================================================
    // Distribution + supply lock
    // =====================================================================

    function test_InitializeDistribution_PoolAmounts() public view {
        assertTrue(treasury.initialized());
        assertEq(treasury.presalePoolBalance(), 2_500_000_000 * PYRA);
        assertEq(treasury.teamPoolBalance(), 2_500_000_000 * PYRA);
        assertEq(treasury.liquidityPoolBalance(), 3_000_000_000 * PYRA);
        assertEq(treasury.communityPoolBalance(), 1_000_000_000 * PYRA);
        assertEq(treasury.reservePoolBalance(), 1_000_000_000 * PYRA);
        assertEq(treasury.feePoolBalance(), 0);
        uint256 sum = treasury.presalePoolBalance() + treasury.teamPoolBalance() + treasury.liquidityPoolBalance()
            + treasury.communityPoolBalance() + treasury.reservePoolBalance();
        assertEq(sum, 10_000_000_000_000_000_000);
        assertEq(token.balanceOf(address(treasury)), TOTAL_SUPPLY);
    }

    function test_InitializeDistribution_EmitsEvent() public {
        (PyraTreasury t2,) = _deployTreasury();
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.TreasuryInitialized(TOTAL_SUPPLY, block.timestamp);
        vm.prank(opsAdmin);
        t2.initializeDistribution();
    }

    /// Deliberate quirk kept: a second initializeDistribution reverts InvalidAmount
    /// rather than a dedicated already-initialized error.
    function test_RevertWhen_InitializeTwice() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(opsAdmin);
        treasury.initializeDistribution();
    }

    function test_RevertWhen_NonAdminInitializes() public {
        (PyraTreasury t2,) = _deployTreasury();
        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, ADMIN_ROLE, alice));
        vm.prank(alice);
        t2.initializeDistribution();
    }

    /// The super admin satisfies the admin gates too, not only ADMIN_ROLE holders.
    function test_SuperAdminPassesAdminGates() public {
        (PyraTreasury t2,) = _deployTreasury();
        vm.prank(superAdmin);
        t2.initializeDistribution();
        assertTrue(t2.initialized());

        // Admin-or-orchestrator gate as well.
        vm.prank(superAdmin);
        treasury.withdrawCommunityRewards(1 * PYRA);
        assertEq(token.balanceOf(superAdmin), 1 * PYRA);
    }

    function test_LockSupply_FreezesCap() public {
        assertFalse(treasury.isSupplyLocked());
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.SupplyLocked(block.timestamp);
        vm.prank(opsAdmin);
        treasury.lockSupply();
        assertTrue(treasury.isSupplyLocked());
    }

    function test_RevertWhen_LockSupplyTwice() public {
        vm.startPrank(opsAdmin);
        treasury.lockSupply();
        vm.expectRevert(PyraTreasury.SupplyAlreadyLocked.selector);
        treasury.lockSupply();
        vm.stopPrank();
    }

    /// Deliberate quirk kept: locking before distribution reverts InvalidAmount.
    function test_RevertWhen_LockSupplyBeforeInitialization() public {
        (PyraTreasury t2,) = _deployTreasury();
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(opsAdmin);
        t2.lockSupply();
    }

    // =====================================================================
    // Team vesting (+ spec gaps)
    // =====================================================================

    function test_CreateTeamVesting_LocksTokens() public {
        uint256 amount = 1_000_000_000 * PYRA; // 1B
        uint256 teamBefore = treasury.teamPoolBalance();

        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.VestingScheduleCreated(alice, amount, block.timestamp, FOUR_YEARS, ONE_YEAR);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        assertEq(treasury.teamPoolBalance(), teamBefore - amount);
        assertEq(treasury.vestingEscrow(), amount);
        _assertSolvent();
    }

    function test_RevertWhen_ReleaseBeforeCliff() public {
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1_000_000_000 * PYRA, ONE_YEAR, FOUR_YEARS);

        vm.warp(start + ONE_YEAR / 2);
        vm.expectRevert(PyraTreasury.VestingNotStarted.selector);
        treasury.releaseVestedTokens(alice);
    }

    function test_ReleaseAfterFullVesting_ReleasesAll() public {
        uint256 amount = 1_000_000_000 * PYRA;
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        vm.warp(start + FOUR_YEARS + 1);
        // Permissionless: bob triggers the release; tokens go to alice.
        vm.prank(bob);
        treasury.releaseVestedTokens(alice);

        assertEq(treasury.vestingScheduleFor(alice).releasedAmount, amount);
        assertEq(token.balanceOf(alice), amount);
        assertEq(treasury.vestingEscrow(), 0);
        _assertSolvent();
    }

    /// One schedule per beneficiary, enforced on create.
    function test_RevertWhen_SecondScheduleForSameBeneficiary() public {
        vm.startPrank(superAdmin);
        treasury.createTeamVesting(alice, 1_000_000_000 * PYRA, ONE_YEAR, FOUR_YEARS);
        vm.expectRevert(PyraTreasury.VestingAlreadyExists.selector);
        treasury.createTeamVesting(alice, 1 * PYRA, 0, FOUR_YEARS);
        vm.stopPrank();
    }

    /// Schedules are never deleted: even a fully-released beneficiary can never
    /// receive a second grant.
    function test_RevertWhen_SecondScheduleAfterFullRelease() public {
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1_000_000 * PYRA, 0, ONE_YEAR);
        vm.warp(start + ONE_YEAR);
        treasury.releaseVestedTokens(alice);
        assertEq(treasury.vestingScheduleFor(alice).releasedAmount, 1_000_000 * PYRA);

        vm.expectRevert(PyraTreasury.VestingAlreadyExists.selector);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1 * PYRA, 0, ONE_YEAR);
    }

    function test_RevertWhen_CliffExceedsDuration() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1_000_000_000 * PYRA, FOUR_YEARS, ONE_YEAR);
    }

    /// Creating a vesting schedule requires the super admin — a regular admin fails.
    function test_RevertWhen_RegularAdminCreatesVesting() public {
        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        vm.prank(opsAdmin);
        treasury.createTeamVesting(alice, 1_000_000_000 * PYRA, ONE_YEAR, FOUR_YEARS);
    }

    function test_RevertWhen_CreateVestingZeroAmount() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 0, ONE_YEAR, FOUR_YEARS);
    }

    function test_RevertWhen_CreateVestingZeroDuration() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1 * PYRA, 0, 0);
    }

    function test_RevertWhen_CreateVestingExceedsTeamPool() public {
        vm.expectRevert(PyraTreasury.InsufficientBalance.selector);
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 2_500_000_001 * PYRA, ONE_YEAR, FOUR_YEARS);
    }

    /// Spec gap: linear-from-start floor math at mid-schedule (spec §4.6 —
    /// vesting accrues from startTime, NOT from cliff end).
    function test_PartialVestMidSchedule_LinearFloorMath() public {
        uint256 amount = 1_000_000_000 * PYRA;
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        vm.warp(start + FOUR_YEARS / 2); // exactly half the duration, past the cliff
        treasury.releaseVestedTokens(alice);
        assertEq(token.balanceOf(alice), amount / 2);
        assertEq(treasury.vestingScheduleFor(alice).releasedAmount, amount / 2);
    }

    /// Spec gap: release at the exact cliff moment (>= passes) pays the full
    /// pro-rata amount accrued during the cliff (1y cliff / 4y vest -> ~25%).
    function test_ReleaseAtExactCliff_PaysProRata() public {
        uint256 amount = 1_000_000_000 * PYRA;
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        vm.warp(start + ONE_YEAR);
        uint256 expected = (amount * ONE_YEAR) / FOUR_YEARS; // floor
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.VestingReleased(alice, expected, expected, block.timestamp);
        treasury.releaseVestedTokens(alice);
        assertEq(token.balanceOf(alice), expected);
    }

    /// Spec gap: multiple releases accumulate; each pays only the newly-vested delta.
    function test_MultipleReleasesAccumulate() public {
        uint256 amount = 1_000_000_000 * PYRA;
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        vm.warp(start + FOUR_YEARS / 2);
        treasury.releaseVestedTokens(alice);
        assertEq(token.balanceOf(alice), amount / 2);

        vm.warp(start + (3 * FOUR_YEARS) / 4);
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.VestingReleased(alice, amount / 4, (3 * amount) / 4, block.timestamp);
        treasury.releaseVestedTokens(alice);
        assertEq(token.balanceOf(alice), (3 * amount) / 4);
        assertEq(treasury.vestingScheduleFor(alice).releasedAmount, (3 * amount) / 4);
        _assertSolvent();
    }

    /// Spec §4.6 edge: cliff = 0 and elapsed = 0 -> vested 0 -> NoTokensToRelease.
    function test_RevertWhen_ReleaseWithNothingNewlyVested() public {
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, 1_000_000 * PYRA, 0, FOUR_YEARS);
        vm.expectRevert(PyraTreasury.NoTokensToRelease.selector);
        treasury.releaseVestedTokens(alice);
    }

    /// Releasing for an address that has no schedule at all.
    function test_RevertWhen_ReleaseWithNoSchedule() public {
        vm.expectRevert(PyraTreasury.NoVestingSchedule.selector);
        treasury.releaseVestedTokens(alice);
    }

    /// Spec gap: the vesting views — hasVestingSchedule plus every field returned
    /// by vestingScheduleFor (total, released, beneficiary, timing).
    function test_VestingViews() public {
        assertFalse(treasury.hasVestingSchedule(alice));
        PyraTreasury.VestingSchedule memory empty = treasury.vestingScheduleFor(alice);
        assertEq(empty.totalAmount, 0);

        uint256 amount = 42_000 * PYRA;
        uint256 start = block.timestamp;
        vm.prank(superAdmin);
        treasury.createTeamVesting(alice, amount, ONE_YEAR, FOUR_YEARS);

        assertTrue(treasury.hasVestingSchedule(alice));
        PyraTreasury.VestingSchedule memory s = treasury.vestingScheduleFor(alice);
        assertEq(s.beneficiary, alice);
        assertEq(s.totalAmount, amount);
        assertEq(s.releasedAmount, 0);
        assertEq(s.startTime, start);
        assertEq(s.duration, FOUR_YEARS);
        assertEq(s.cliffDuration, ONE_YEAR);
    }

    // =====================================================================
    // Capped withdrawals (+ spec gaps)
    // =====================================================================

    function test_WithdrawWithinCap_Succeeds() public {
        uint256 amount = 50_000 * PYRA; // default community cap is 100k

        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.PoolWithdrawn("community", amount, opsAdmin, block.timestamp, amount);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(amount);

        assertEq(token.balanceOf(opsAdmin), amount);
        (, , uint256 used) = treasury.capStatus("community");
        assertEq(used, amount);
        _assertSolvent();
    }

    function test_OrchestratorCanWithdrawCommunityRewards() public {
        uint256 amount = 50_000 * PYRA;
        vm.prank(orchestrator);
        treasury.withdrawCommunityRewards(amount);
        assertEq(token.balanceOf(orchestrator), amount);
    }

    /// Least privilege: community is the only orchestrator-accessible pool.
    function test_RevertWhen_OrchestratorWithdrawsOtherPools() public {
        bytes memory err = abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, ADMIN_ROLE, orchestrator);
        vm.startPrank(orchestrator);
        vm.expectRevert(err);
        treasury.withdrawLiquidity(1 * PYRA);
        vm.expectRevert(err);
        treasury.withdrawPresale(1 * PYRA);
        vm.expectRevert(err);
        treasury.withdrawReserve(1 * PYRA);
        vm.expectRevert(err);
        treasury.withdrawFees(1 * PYRA);
        vm.stopPrank();
    }

    function test_RevertWhen_WithdrawExceedsCap() public {
        vm.expectRevert(PyraTreasury.AdminWithdrawalCapExceeded.selector);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(200_000 * PYRA); // 2x the 100k default cap
    }

    /// Withdrawals accumulate against one shared per-window cap counter.
    function test_MultipleWithdrawalsAccumulate() public {
        vm.startPrank(opsAdmin);
        treasury.withdrawCommunityRewards(40_000 * PYRA);
        treasury.withdrawCommunityRewards(40_000 * PYRA);
        vm.stopPrank();
        (, , uint256 used) = treasury.capStatus("community");
        assertEq(used, 80_000 * PYRA);
    }

    function test_RevertWhen_SecondWithdrawalCrossesCap() public {
        vm.startPrank(opsAdmin);
        treasury.withdrawCommunityRewards(60_000 * PYRA);
        vm.expectRevert(PyraTreasury.AdminWithdrawalCapExceeded.selector);
        treasury.withdrawCommunityRewards(60_000 * PYRA); // 120k > 100k cap
        vm.stopPrank();
    }

    function test_WindowRollsAfterExpiry() public {
        uint256 t0 = block.timestamp;
        vm.startPrank(opsAdmin);
        treasury.withdrawCommunityRewards(80_000 * PYRA);
        vm.warp(t0 + 25 hours); // past the 24h window
        treasury.withdrawCommunityRewards(80_000 * PYRA);
        vm.stopPrank();
        (, uint256 windowStart, uint256 used) = treasury.capStatus("community");
        assertEq(used, 80_000 * PYRA); // only the latest — counter reset on roll
        assertEq(windowStart, t0 + 25 hours);
    }

    /// A cap of zero is the pause switch: every withdrawal from that pool reverts.
    function test_CapZeroPausesWithdrawals() public {
        vm.prank(superAdmin);
        treasury.setCommunityCap(0, 0);
        vm.expectRevert(PyraTreasury.AdminWithdrawalsPaused.selector);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(1); // 1 base unit
    }

    function test_RevertWhen_WithdrawZeroAmount() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(0);
    }

    function test_RevertWhen_NonAdminWithdrawsCommunity() public {
        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, ADMIN_ROLE, bob));
        vm.prank(bob);
        treasury.withdrawCommunityRewards(1);
    }

    /// Check ordering is guaranteed: the pool-balance check fires BEFORE the cap check.
    function test_BalanceCheckPrecedesCapCheck() public {
        // 2B > the 1B community pool AND > the 100k cap; must revert InsufficientBalance.
        vm.expectRevert(PyraTreasury.InsufficientBalance.selector);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(2_000_000_000 * PYRA);
    }

    /// Spec gap: withdrawReserve (same shape as the other tested pools).
    function test_WithdrawReserve() public {
        uint256 amount = 500 * PYRA; // default reserve cap is 1k
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.PoolWithdrawn("reserve", amount, opsAdmin, block.timestamp, amount);
        vm.prank(opsAdmin);
        treasury.withdrawReserve(amount);
        assertEq(token.balanceOf(opsAdmin), amount);
        (, , uint256 used) = treasury.capStatus("reserve");
        assertEq(used, amount);
    }

    /// Spec gap: withdrawFees (the fee pool must first be fed via depositFees).
    function test_WithdrawFees() public {
        _raiseAllCaps();
        vm.startPrank(opsAdmin);
        treasury.withdrawPresale(10_000_000 * PYRA);
        token.approve(address(treasury), 10_000_000 * PYRA);
        treasury.depositFees(10_000_000 * PYRA);

        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.PoolWithdrawn("fee", 4_000_000 * PYRA, opsAdmin, block.timestamp, 4_000_000 * PYRA);
        treasury.withdrawFees(4_000_000 * PYRA);
        vm.stopPrank();

        assertEq(treasury.feePoolBalance(), 6_000_000 * PYRA);
        _assertSolvent();
    }

    /// Spec gap: the AN-07 backwards-clock guard resets the window instead of
    /// stalling. Reachable in tests via vm.warp backwards.
    function test_BackwardsClockGuardResetsWindow() public {
        vm.warp(100_000);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(40_000 * PYRA); // window rolls to start=100000

        vm.warp(50_000); // clock goes backwards
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(80_000 * PYRA); // guard resets used to 0 first

        (, uint256 windowStart, uint256 used) = treasury.capStatus("community");
        assertEq(windowStart, 50_000);
        assertEq(used, 80_000 * PYRA);
    }

    // =====================================================================
    // Cap setters + admin window (+ spec gaps)
    // =====================================================================

    function test_SuperAdminCanRaiseCap() public {
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.AdminCapUpdated("presale", 500_000_000 * PYRA, 86_400, block.timestamp);
        vm.prank(superAdmin);
        treasury.setPresaleCap(500_000_000 * PYRA, 0);

        (uint256 cap, uint256 windowStart, uint256 used) = treasury.capStatus("presale");
        assertEq(cap, 500_000_000 * PYRA);
        assertEq(windowStart, block.timestamp); // window reset on cap change
        assertEq(used, 0);

        // Would revert at the default 1k cap; succeeds at 500M.
        vm.prank(opsAdmin);
        treasury.withdrawPresale(100_000_000 * PYRA);
        assertEq(token.balanceOf(opsAdmin), 100_000_000 * PYRA);
    }

    /// Cap changes are super-admin only — a regular admin cannot raise its own limit.
    function test_RevertWhen_RegularAdminChangesCap() public {
        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        vm.prank(opsAdmin);
        treasury.setCommunityCap(1, 0);
    }

    /// The shipped defaults: a 24h admin window and the five per-pool caps.
    function test_DefaultCapConstantsMatchModule() public view {
        assertEq(treasury.adminWindow(), 86_400); // 24h in seconds

        (uint256 cap,,) = treasury.capStatus("presale");
        assertEq(cap, 1_000 * PYRA);
        (cap,,) = treasury.capStatus("community");
        assertEq(cap, 100_000 * PYRA);
        (cap,,) = treasury.capStatus("liquidity");
        assertEq(cap, 10_000 * PYRA);
        (cap,,) = treasury.capStatus("reserve");
        assertEq(cap, 1_000 * PYRA);
        (cap,,) = treasury.capStatus("fee");
        assertEq(cap, 50_000 * PYRA);
    }

    /// Spec gap: a nonzero window param on a cap setter changes the GLOBAL
    /// window for ALL pools (documented side effect), and the event reports the
    /// effective global window.
    function test_CapSetterNonzeroWindowChangesGlobalWindow() public {
        uint256 t0 = block.timestamp;
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.AdminCapUpdated("community", 100_000 * PYRA, 3_600, t0);
        vm.prank(superAdmin);
        treasury.setCommunityCap(100_000 * PYRA, 3_600);
        assertEq(treasury.adminWindow(), 3_600);

        // Another pool now rolls on the 1h window: 800 + 800 would exceed the 1k
        // presale cap inside one window, but succeeds across a roll.
        vm.prank(opsAdmin);
        treasury.withdrawPresale(800 * PYRA);
        vm.warp(t0 + 3_601);
        vm.prank(opsAdmin);
        treasury.withdrawPresale(800 * PYRA);
        (, , uint256 used) = treasury.capStatus("presale");
        assertEq(used, 800 * PYRA);
    }

    /// Spec gap: setAdminWindow updates the global length WITHOUT resetting
    /// any per-pool window.
    function test_SetAdminWindow_DoesNotResetPoolWindows() public {
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(40_000 * PYRA);

        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.AdminCapUpdated("admin_window", 7_200, 7_200, block.timestamp);
        vm.prank(superAdmin);
        treasury.setAdminWindow(7_200);
        assertEq(treasury.adminWindow(), 7_200);

        // Window state survived the change.
        (, uint256 windowStart, uint256 used) = treasury.capStatus("community");
        assertEq(used, 40_000 * PYRA);
        assertEq(windowStart, 0); // first-ever withdrawal at t=1 never rolled

        // Still inside the (now 2h) window: crossing the cap reverts.
        vm.expectRevert(PyraTreasury.AdminWithdrawalCapExceeded.selector);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(70_000 * PYRA);

        // After the NEW window elapses, the counter rolls.
        vm.warp(7_201);
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(70_000 * PYRA);
        (, , used) = treasury.capStatus("community");
        assertEq(used, 70_000 * PYRA);
    }

    function test_RevertWhen_SetAdminWindowZero() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(superAdmin);
        treasury.setAdminWindow(0);
    }

    /// Spec gap: capStatus returns (0,0,0) for an unknown tag — deliberately no revert.
    function test_CapStatusUnknownKeyReturnsZeros() public view {
        (uint256 cap, uint256 windowStart, uint256 used) = treasury.capStatus("bogus");
        assertEq(cap, 0);
        assertEq(windowStart, 0);
        assertEq(used, 0);
    }

    // =====================================================================
    // Pool rebalance + inflows (+ spec gaps)
    // =====================================================================

    /// Spec gap: moveBetweenPools success path — bypasses withdrawal caps.
    function test_MoveBetweenPools_Success() public {
        uint256 amount = 1_000_000_000 * PYRA; // far above every cap: caps do not apply
        uint256 teamBefore = treasury.teamPoolBalance();
        uint256 feeBefore = treasury.feePoolBalance();

        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.PoolsRebalanced(superAdmin, 2, 6, amount, block.timestamp);
        vm.prank(superAdmin);
        treasury.moveBetweenPools(2, 6, amount); // team -> fee

        assertEq(treasury.teamPoolBalance(), teamBefore - amount);
        assertEq(treasury.feePoolBalance(), feeBefore + amount);
        _assertSolvent();
    }

    function test_RevertWhen_MoveBetweenPools_SamePool() public {
        vm.expectRevert(PyraTreasury.InvalidPool.selector);
        vm.prank(superAdmin);
        treasury.moveBetweenPools(3, 3, 1 * PYRA);
    }

    function test_RevertWhen_MoveBetweenPools_InvalidIds() public {
        vm.startPrank(superAdmin);
        vm.expectRevert(PyraTreasury.InvalidPool.selector);
        treasury.moveBetweenPools(0, 3, 1 * PYRA);
        vm.expectRevert(PyraTreasury.InvalidPool.selector);
        treasury.moveBetweenPools(7, 3, 1 * PYRA);
        vm.expectRevert(PyraTreasury.InvalidPool.selector);
        treasury.moveBetweenPools(3, 0, 1 * PYRA);
        vm.expectRevert(PyraTreasury.InvalidPool.selector);
        treasury.moveBetweenPools(3, 7, 1 * PYRA);
        vm.stopPrank();
    }

    function test_RevertWhen_MoveBetweenPools_ZeroAmount() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(superAdmin);
        treasury.moveBetweenPools(2, 6, 0);
    }

    /// Documented behaviour: draining more than a pool holds reverts with an
    /// explicit InsufficientBalance, not a bare arithmetic-underflow panic.
    function test_RevertWhen_MoveBetweenPools_InsufficientBalance() public {
        // Fee pool starts empty.
        vm.expectRevert(PyraTreasury.InsufficientBalance.selector);
        vm.prank(superAdmin);
        treasury.moveBetweenPools(6, 4, 1 * PYRA);
    }

    /// Inflows are uncapped: adding to a pool is never subject to withdrawal caps.
    function test_AddToCommunityPool_Inflow() public {
        _raiseAllCaps();
        uint256 amount = 100_000_000 * PYRA;
        uint256 communityBefore = treasury.communityPoolBalance();

        vm.startPrank(opsAdmin);
        treasury.withdrawPresale(amount);
        token.approve(address(treasury), amount);
        treasury.addToCommunityPool(amount);
        vm.stopPrank();

        assertEq(treasury.communityPoolBalance(), communityBefore + amount);
        _assertSolvent();
    }

    /// Spec gap: addToLiquidityPool (identical shape).
    function test_AddToLiquidityPool_Inflow() public {
        _raiseAllCaps();
        uint256 amount = 5_000_000 * PYRA;
        uint256 liquidityBefore = treasury.liquidityPoolBalance();

        vm.startPrank(opsAdmin);
        treasury.withdrawPresale(amount);
        token.approve(address(treasury), amount);
        treasury.addToLiquidityPool(amount);
        vm.stopPrank();

        assertEq(treasury.liquidityPoolBalance(), liquidityBefore + amount);
        _assertSolvent();
    }

    function test_DepositFees() public {
        _raiseAllCaps();
        uint256 amount = 10_000_000 * PYRA;

        vm.startPrank(opsAdmin);
        treasury.withdrawPresale(amount);
        token.approve(address(treasury), amount);
        vm.expectEmit(true, true, true, true);
        emit PyraTreasury.FeesDeposited(amount, opsAdmin, block.timestamp);
        treasury.depositFees(amount);
        vm.stopPrank();

        assertEq(treasury.feePoolBalance(), amount);
        _assertSolvent();
    }

    /// depositFees is PERMISSIONLESS — any holder may deposit.
    function test_DepositFees_PermissionlessDepositor() public {
        _raiseAllCaps();
        vm.startPrank(opsAdmin);
        treasury.withdrawPresale(1_000 * PYRA);
        token.transfer(alice, 1_000 * PYRA);
        vm.stopPrank();

        vm.startPrank(alice);
        token.approve(address(treasury), 1_000 * PYRA);
        treasury.depositFees(1_000 * PYRA);
        vm.stopPrank();

        assertEq(treasury.feePoolBalance(), 1_000 * PYRA);
    }

    /// Spec gap: depositFees with a zero amount reverts InvalidAmount.
    function test_RevertWhen_DepositFeesZero() public {
        vm.expectRevert(PyraTreasury.InvalidAmount.selector);
        vm.prank(alice);
        treasury.depositFees(0);
    }

    // =====================================================================
    // Pure helpers
    // =====================================================================

    /// Includes a wide-intermediate sanity value (1e18) to catch overflow in the
    /// bps math.
    function test_CalculatePlatformFee() public view {
        assertEq(treasury.calculatePlatformFee(10_000), 250);
        assertEq(treasury.calculatePlatformFee(1_000_000_000_000_000_000), 25_000_000_000_000_000);
        assertEq(treasury.PLATFORM_FEE_BPS(), 250);
    }

    // =====================================================================
    // Proxy plumbing: initializer, UUPS upgrade auth
    // =====================================================================

    function test_RevertWhen_InitializerRunsTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        treasury.initialize(address(pyraAdmin), address(token));
    }

    /// Audit L4: zero admin/token addresses must be rejected at initialize.
    function test_RevertWhen_InitializeZeroAddress() public {
        PyraTreasury impl = new PyraTreasury();
        vm.expectRevert(PyraTreasury.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(PyraTreasury.initialize, (address(0), address(token))));
        vm.expectRevert(PyraTreasury.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(PyraTreasury.initialize, (address(pyraAdmin), address(0))));
    }

    function test_RevertWhen_ImplementationInitializedDirectly() public {
        PyraTreasury impl = new PyraTreasury(); // constructor disables initializers
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(pyraAdmin), address(token));
    }

    function test_RevertWhen_NonSuperAdminUpgrades() public {
        PyraTreasury newImpl = new PyraTreasury();

        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, attacker));
        vm.prank(attacker);
        treasury.upgradeToAndCall(address(newImpl), "");

        // A regular ops admin must not be able to upgrade either.
        vm.expectRevert(abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, opsAdmin));
        vm.prank(opsAdmin);
        treasury.upgradeToAndCall(address(newImpl), "");
    }

    function test_SuperAdminCanUpgrade_StatePreserved() public {
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(10_000 * PYRA);

        PyraTreasury newImpl = new PyraTreasury();
        vm.prank(superAdmin);
        treasury.upgradeToAndCall(address(newImpl), "");

        // Storage (pools, window accounting) survives the upgrade.
        assertEq(treasury.communityPoolBalance(), 1_000_000_000 * PYRA - 10_000 * PYRA);
        (, , uint256 used) = treasury.capStatus("community");
        assertEq(used, 10_000 * PYRA);
        assertTrue(treasury.initialized());

        // And the contract remains functional.
        vm.prank(opsAdmin);
        treasury.withdrawCommunityRewards(1 * PYRA);
        _assertSolvent();
    }

    // =====================================================================
    // Unauthorized-role revert for EVERY gated function
    // =====================================================================

    function test_RevertWhen_UnauthorizedCallsAdminGatedFunctions() public {
        bytes memory err = abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, ADMIN_ROLE, attacker);
        vm.startPrank(attacker);
        vm.expectRevert(err);
        treasury.initializeDistribution();
        vm.expectRevert(err);
        treasury.lockSupply();
        vm.expectRevert(err);
        treasury.withdrawPresale(1);
        vm.expectRevert(err);
        treasury.withdrawCommunityRewards(1); // not admin, not orchestrator
        vm.expectRevert(err);
        treasury.withdrawLiquidity(1);
        vm.expectRevert(err);
        treasury.withdrawReserve(1);
        vm.expectRevert(err);
        treasury.withdrawFees(1);
        vm.expectRevert(err);
        treasury.addToCommunityPool(1);
        vm.expectRevert(err);
        treasury.addToLiquidityPool(1);
        vm.stopPrank();
    }

    function test_RevertWhen_UnauthorizedCallsSuperAdminGatedFunctions() public {
        bytes memory err = abi.encodeWithSelector(PyraTreasury.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, attacker);
        vm.startPrank(attacker);
        vm.expectRevert(err);
        treasury.createTeamVesting(alice, 1 * PYRA, 0, ONE_YEAR);
        vm.expectRevert(err);
        treasury.setPresaleCap(1, 0);
        vm.expectRevert(err);
        treasury.setCommunityCap(1, 0);
        vm.expectRevert(err);
        treasury.setLiquidityCap(1, 0);
        vm.expectRevert(err);
        treasury.setReserveCap(1, 0);
        vm.expectRevert(err);
        treasury.setFeeCap(1, 0);
        vm.expectRevert(err);
        treasury.setAdminWindow(3_600);
        vm.expectRevert(err);
        treasury.moveBetweenPools(2, 6, 1);
        vm.stopPrank();
    }
}
