// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {EscrowPool} from "../src/EscrowPool.sol";
import {MockPYRA} from "./mocks/MockPYRA.sol";
import {PyraAdmin} from "../src/PyraAdmin.sol";

/// @dev Minimal ERC20 test double whose `transfer` can re-enter the escrow
///      pool, used to prove the ReentrancyGuard on every outbound-token path.
///      Benign (mode 0) unless armed. SafeERC20-compatible (returns true).
contract ReentrantToken {
    uint8 internal constant MODE_NONE = 0;
    uint8 internal constant MODE_WITHDRAW = 1;
    uint8 internal constant MODE_SETTLE = 2;
    uint8 internal constant MODE_WITHDRAW_FEES = 3;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    EscrowPool internal target;
    uint8 internal mode;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setAttack(EscrowPool target_, uint8 mode_) external {
        target = target_;
        mode = mode_;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (mode == MODE_WITHDRAW) {
            target.withdraw(1);
        } else if (mode == MODE_SETTLE) {
            target.settleBatch(999, new address[](0), new uint256[](0));
        } else if (mode == MODE_WITHDRAW_FEES) {
            target.withdrawFees(1, address(this));
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev Full escrow-pool suite: the client deposit/withdraw ledger, batch
///      settlement and its fee split, the payout cap, the platform fee, the
///      fee-withdrawal cap, initializer locking, UUPS upgrade auth,
///      unauthorized-role reverts for every gated function, cycle dedup,
///      length mismatch, deposit `ref` attribution, window rolling, and
///      reentrancy on all outbound paths.
///      Three properties hold by construction rather than by an explicit
///      check, and are asserted as such: withdraw is never blocked by an
///      in-flight settlement (settlement is atomic), a cycle id can never
///      settle twice, and deposits are always allowed.
contract EscrowPoolTest is Test {
    PyraAdmin internal pyraAdmin;
    MockPYRA internal token;
    EscrowPool internal escrow;

    address internal superAdmin = makeAddr("superAdmin");
    address internal opsAdmin = makeAddr("opsAdmin");
    address internal orchestrator = makeAddr("orchestrator");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal worker1 = makeAddr("worker1");
    address internal worker2 = makeAddr("worker2");
    address internal attacker = makeAddr("attacker");
    address internal feeRecipient = makeAddr("feeRecipient");

    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 internal constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 internal constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    bytes32 internal constant REF = keccak256("deposit-ref");
    uint256 internal constant START_TS = 1_000_000;
    uint256 internal constant DAY = 86_400;

    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public {
        vm.warp(START_TS);

        pyraAdmin = new PyraAdmin(0, superAdmin);
        vm.startPrank(superAdmin);
        pyraAdmin.grantRole(ADMIN_ROLE, opsAdmin);
        pyraAdmin.grantRole(ORCHESTRATOR_ROLE, orchestrator);
        vm.stopPrank();

        token = new MockPYRA(address(this));

        EscrowPool impl = new EscrowPool();
        escrow = EscrowPool(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(EscrowPool.initialize, (address(pyraAdmin), address(token)))
                )
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    function _deposit(address client, uint256 amount) internal {
        token.transfer(client, amount);
        vm.startPrank(client);
        token.approve(address(escrow), amount);
        escrow.deposit(amount, REF);
        vm.stopPrank();
    }

    function _single(address worker, uint256 gross)
        internal
        pure
        returns (address[] memory ws, uint256[] memory gs)
    {
        ws = new address[](1);
        gs = new uint256[](1);
        ws[0] = worker;
        gs[0] = gross;
    }

    /// @dev Settles a one-payment batch as the orchestrator.
    function _settle(uint64 cycleId, address worker, uint256 gross) internal {
        (address[] memory ws, uint256[] memory gs) = _single(worker, gross);
        vm.prank(orchestrator);
        escrow.settleBatch(cycleId, ws, gs);
    }

    /// @dev Deploys a second escrow wired to the reentrant token double, with
    ///      alice pre-deposited (benign mode).
    function _deployEvilPool() internal returns (ReentrantToken evil, EscrowPool pool2) {
        evil = new ReentrantToken();
        EscrowPool impl = new EscrowPool();
        pool2 = EscrowPool(
            address(
                new ERC1967Proxy(
                    address(impl), abi.encodeCall(EscrowPool.initialize, (address(pyraAdmin), address(evil)))
                )
            )
        );
        evil.mint(alice, 1_000_000);
        vm.startPrank(alice);
        evil.approve(address(pool2), type(uint256).max);
        pool2.deposit(10_000, REF);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Client escrow
    // ─────────────────────────────────────────────────────────────────────

    /// Deposits are additive to an existing ledger entry.
    function testDepositIncreasesBalances() public {
        _deposit(alice, 1000);
        assertEq(escrow.clientBalance(alice), 1000);
        assertEq(escrow.pool(), 1000);
        assertEq(escrow.totalDeposited(), 1000);

        _deposit(alice, 500);
        assertEq(escrow.clientBalance(alice), 1500);
        assertEq(escrow.pool(), 1500);
        assertEq(escrow.totalDeposited(), 1500);
    }

    /// Withdraw debits the ledger and pays the client.
    function testWithdrawDecreasesBalance() public {
        _deposit(alice, 1000);

        vm.expectEmit(address(escrow));
        emit EscrowPool.ClientWithdraw(alice, 400, 600);
        vm.prank(alice);
        escrow.withdraw(400);

        assertEq(escrow.clientBalance(alice), 600);
        assertEq(escrow.pool(), 600);
        assertEq(escrow.totalWithdrawn(), 400);
        assertEq(token.balanceOf(alice), 400);
    }

    /// Settlement is atomic, so a withdrawal is NEVER blocked by one — there
    /// is no mid-settlement window to guard against. Prove withdraw works
    /// immediately after a settlement in the same block.
    function testWithdrawNotBlockedBySettlement() public {
        _deposit(alice, 1000);
        _settle(1, worker1, 100);

        vm.prank(alice);
        escrow.withdraw(400);
        assertEq(escrow.clientBalance(alice), 600);
        assertEq(token.balanceOf(alice), 400);
    }

    /// Over-withdrawal of an existing entry.
    function testWithdrawExceedsAvailable() public {
        _deposit(alice, 500);
        vm.prank(alice);
        vm.expectRevert(EscrowPool.WithdrawExceedsAvailable.selector);
        escrow.withdraw(501);
    }

    /// Deposits are allowed at any time — nothing, settlement included, ever
    /// gates deposit.
    function testDepositAllowedAnytime() public {
        _deposit(alice, 1000);
        _settle(1, worker1, 500);
        _deposit(bob, 2000);
        assertEq(escrow.clientBalance(bob), 2000);
    }

    /// An address that never deposited gets a distinct error from
    /// over-withdrawal — even for amount 0.
    function testWithdrawNoDepositReverts() public {
        vm.prank(alice);
        vm.expectRevert(EscrowPool.InsufficientBalance.selector);
        escrow.withdraw(1);

        vm.prank(alice);
        vm.expectRevert(EscrowPool.InsufficientBalance.selector);
        escrow.withdraw(0);
    }

    /// Deliberate quirk: a zero withdraw by a depositor succeeds and emits.
    function testWithdrawZeroAllowedForDepositor() public {
        _deposit(alice, 100);
        vm.expectEmit(address(escrow));
        emit EscrowPool.ClientWithdraw(alice, 0, 100);
        vm.prank(alice);
        escrow.withdraw(0);
        assertEq(escrow.clientBalance(alice), 100);
    }

    /// Deposit rejects zero — deliberately asymmetric with withdraw.
    function testDepositZeroReverts() public {
        vm.prank(alice);
        vm.expectRevert(EscrowPool.InvalidAmount.selector);
        escrow.deposit(0, REF);
    }

    /// The caller-supplied attribution ref is echoed verbatim in the event,
    /// so the orchestrator can attribute a deposit from the log alone instead
    /// of watching bare token transfers.
    function testDepositEmitsRef() public {
        bytes32 ref = keccak256("customer-42-invoice-7");
        token.transfer(alice, 1000);
        vm.startPrank(alice);
        token.approve(address(escrow), 1000);
        vm.expectEmit(address(escrow));
        emit EscrowPool.ClientDeposit(alice, 1000, 1000, ref);
        escrow.deposit(1000, ref);
        vm.stopPrank();
    }

    /// Settlements can drain the aggregate pool below a client's ledger
    /// promise; the withdrawal then reverts with an explicit
    /// InsufficientPoolBalance instead of a bare underflow panic.
    function testWithdrawPoolDrainedReverts() public {
        _deposit(alice, 1000);
        _settle(1, worker1, 800); // pool 200, alice's ledger still 1000

        vm.prank(alice);
        vm.expectRevert(EscrowPool.InsufficientPoolBalance.selector);
        escrow.withdraw(500);

        vm.prank(alice);
        escrow.withdraw(200); // exactly the remaining pool works
        assertEq(escrow.clientBalance(alice), 800);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Settlement
    // ─────────────────────────────────────────────────────────────────────

    /// Full settlement cycle with the fee split at the 250 bps default
    /// (4000 gross → 100 fee / 3900 net).
    function testFullSettlementCycle() public {
        _deposit(alice, 10_000);
        (address[] memory ws, uint256[] memory gs) = _single(worker1, 4000);

        vm.expectEmit(address(escrow));
        emit EscrowPool.WorkerPaid(1, worker1, 3900);
        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(1, 3900, 100, 1);
        vm.prank(opsAdmin);
        escrow.settleBatch(1, ws, gs);

        assertEq(escrow.totalPaidWorkers(), 3900);
        assertEq(escrow.totalFeesCollected(), 100);
        assertEq(escrow.feePool(), 100);
        assertEq(escrow.pool(), 6000);
        assertEq(token.balanceOf(worker1), 3900);
        assertTrue(escrow.settledCycles(1));
        assertEq(escrow.currentCycle(), 1);
        assertEq(escrow.lastSettlement(), START_TS);
    }

    /// HIGH-A regression: the least-privilege orchestrator key — NOT an
    /// admin — can drive a complete settlement cycle.
    function testOrchestratorCanRunFullSettlement() public {
        assertFalse(pyraAdmin.hasRole(ADMIN_ROLE, orchestrator));
        assertFalse(pyraAdmin.hasRole(DEFAULT_ADMIN_ROLE, orchestrator));

        _deposit(alice, 10_000);
        _settle(1, worker1, 4000); // helper settles as the orchestrator
        assertEq(escrow.totalPaidWorkers(), 3900);
        assertEq(token.balanceOf(worker1), 3900);
    }

    /// The settlement gate is not orchestrator-only: an ops admin and the
    /// super admin can each settle too.
    function testAdminAndSuperAdminCanSettle() public {
        _deposit(alice, 10_000);

        (address[] memory ws, uint256[] memory gs) = _single(worker1, 1000);
        vm.prank(opsAdmin);
        escrow.settleBatch(1, ws, gs);

        vm.prank(superAdmin);
        escrow.settleBatch(2, ws, gs);

        assertEq(escrow.currentCycle(), 2);
        assertEq(token.balanceOf(worker1), 975 * 2);
    }

    /// The per-payment fee split accumulates across a batch
    /// (10_000 → 250/9750, 1_000 → 25/975; totals 275 fee / 10_725 net).
    function testSettleBatchFeeSplit() public {
        _deposit(alice, 100_000);

        address[] memory ws = new address[](2);
        uint256[] memory gs = new uint256[](2);
        ws[0] = worker1;
        gs[0] = 10_000;
        ws[1] = worker2;
        gs[1] = 1_000;

        vm.expectEmit(address(escrow));
        emit EscrowPool.WorkerPaid(1, worker1, 9750);
        vm.expectEmit(address(escrow));
        emit EscrowPool.WorkerPaid(1, worker2, 975);
        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(1, 10_725, 275, 2);
        vm.prank(orchestrator);
        escrow.settleBatch(1, ws, gs);

        assertEq(escrow.feePool(), 275);
        assertEq(escrow.pool(), 89_000); // gross leaves the pool
        assertEq(token.balanceOf(worker1), 9750);
        assertEq(token.balanceOf(worker2), 975);
    }

    /// A settlement leaves no open state behind — the next cycle can settle
    /// immediately.
    function testSettlementLeavesNoOpenState() public {
        _deposit(alice, 10_000);
        _settle(1, worker1, 1000);
        _settle(2, worker1, 1000);
        assertTrue(escrow.settledCycles(1));
        assertTrue(escrow.settledCycles(2));
        assertEq(escrow.currentCycle(), 2);
    }

    /// A REVERTED settlement leaves no trace — the cycle counter does not
    /// advance and the same cycle id can be retried.
    function testRevertedSettlementLeavesCycleUnsettled() public {
        _deposit(alice, 500);

        vm.expectRevert(EscrowPool.InsufficientPoolBalance.selector);
        _settle(1, worker1, 4000);

        assertFalse(escrow.settledCycles(1));
        assertEq(escrow.currentCycle(), 0);
        assertEq(escrow.lastSettlement(), 0);

        _deposit(alice, 9500);
        _settle(1, worker1, 4000); // cycle id reused after the failed attempt
        assertTrue(escrow.settledCycles(1));
        assertEq(escrow.currentCycle(), 1);
    }

    /// A caller with no role cannot settle.
    function testNonAdminCannotSettle() public {
        _deposit(alice, 10_000);
        (address[] memory ws, uint256[] memory gs) = _single(worker1, 1000);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, ORCHESTRATOR_ROLE, attacker));
        escrow.settleBatch(1, ws, gs);
    }

    /// Cycle dedup: a cycle id can never settle twice, even when the second
    /// attempt carries a different payload.
    function testSettleBatchReplayReverts() public {
        _deposit(alice, 10_000);
        _settle(1, worker1, 1000);
        assertEq(token.balanceOf(worker1), 975);

        vm.expectRevert(abi.encodeWithSelector(EscrowPool.CycleAlreadySettled.selector, uint64(1)));
        _settle(1, worker1, 1000);

        (address[] memory ws, uint256[] memory gs) = _single(worker2, 42);
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(EscrowPool.CycleAlreadySettled.selector, uint64(1)));
        escrow.settleBatch(1, ws, gs);
    }

    /// Payouts draw from the aggregate pool — per-client ledgers are NEVER
    /// debited by settlement.
    function testMultiClientMultiWorkerSettlement() public {
        _deposit(alice, 5000);
        _deposit(bob, 3000);

        address[] memory ws = new address[](2);
        uint256[] memory gs = new uint256[](2);
        ws[0] = worker1;
        gs[0] = 1500; // fee 37 (floor), net 1463
        ws[1] = worker2;
        gs[1] = 1000; // fee 25, net 975

        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(1, 2438, 62, 2);
        vm.prank(orchestrator);
        escrow.settleBatch(1, ws, gs);

        assertEq(escrow.clientBalance(alice), 5000); // ledger untouched
        assertEq(escrow.clientBalance(bob), 3000);
        assertEq(escrow.pool(), 5500);
        assertEq(token.balanceOf(worker1), 1463);
        assertEq(token.balanceOf(worker2), 975);
    }

    /// Lifetime counters accumulate across settled cycles.
    function testLifetimeStatsAccumulate() public {
        _deposit(alice, 20_000);
        _settle(1, worker1, 4000); // net 3900 / fee 100
        _settle(2, worker1, 2000); // net 1950 / fee 50

        assertEq(escrow.currentCycle(), 2);
        assertEq(escrow.totalPaidWorkers(), 5850);
        assertEq(escrow.totalFeesCollected(), 150);
        assertEq(escrow.totalDeposited(), 20_000);
    }

    /// Zero-gross entries are silent no-ops by design (no event, not counted
    /// in workersPaid); an all-empty batch still settles.
    function testZeroGrossEntriesSkipped() public {
        _deposit(alice, 10_000);

        address[] memory ws = new address[](2);
        uint256[] memory gs = new uint256[](2);
        ws[0] = worker1;
        gs[0] = 0;
        ws[1] = worker2;
        gs[1] = 1000;

        vm.expectEmit(address(escrow));
        emit EscrowPool.WorkerPaid(1, worker2, 975);
        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(1, 975, 25, 1); // workersPaid == 1
        vm.prank(orchestrator);
        escrow.settleBatch(1, ws, gs);
        assertEq(token.balanceOf(worker1), 0);

        // An empty batch still consumes its cycle id.
        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(2, 0, 0, 0);
        vm.prank(orchestrator);
        escrow.settleBatch(2, new address[](0), new uint256[](0));
        assertTrue(escrow.settledCycles(2));
    }

    /// Mismatched array lengths revert.
    function testLengthMismatchReverts() public {
        address[] memory ws = new address[](2);
        uint256[] memory gs = new uint256[](1);
        ws[0] = worker1;
        ws[1] = worker2;
        gs[0] = 1000;

        vm.prank(orchestrator);
        vm.expectRevert(EscrowPool.LengthMismatch.selector);
        escrow.settleBatch(1, ws, gs);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Payout cap
    // ─────────────────────────────────────────────────────────────────────

    /// A gross payout over the cap reverts.
    function testPayoutCapBlocksExcessivePayout() public {
        _deposit(alice, 10_000);
        vm.prank(superAdmin);
        escrow.setPayoutCap(3000, 0);

        vm.expectRevert(EscrowPool.PayoutCapExceeded.selector);
        _settle(1, worker1, 4000);
    }

    /// The window records GROSS (4000), not net (3900).
    function testPayoutCapAllowsWithinAndRecordsGross() public {
        _deposit(alice, 10_000);
        vm.prank(superAdmin);
        escrow.setPayoutCap(5000, 0);

        _settle(1, worker1, 4000);

        (uint256 cap, uint256 window, uint256 windowStart, uint256 used) = escrow.payoutCapStatus();
        assertEq(cap, 5000);
        assertEq(window, DAY);
        assertEq(windowStart, START_TS);
        assertEq(used, 4000);
    }

    /// Role matrix: only the super admin can set the payout cap.
    function testSetPayoutCapNonSuperAdminReverts() public {
        address[3] memory callers = [attacker, opsAdmin, orchestrator];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, callers[i]));
            escrow.setPayoutCap(1000, 0);
        }
    }

    /// Payout cap 0 = DISABLED (unlimited), not paused — and a disabled cap
    /// deliberately leaves the window state entirely untouched.
    function testPayoutCapZeroDisables() public {
        vm.startPrank(superAdmin);
        escrow.setPayoutCap(3000, 0);
        escrow.setPayoutCap(0, 0);
        vm.stopPrank();

        _deposit(alice, 50_000);
        _settle(1, worker1, 40_000); // far above the old cap — no revert

        (,,, uint256 used) = escrow.payoutCapStatus();
        assertEq(used, 0); // window not tracked while disabled
    }

    /// The payout window rolls after its length elapses.
    function testPayoutWindowRolls() public {
        _deposit(alice, 20_000);
        vm.prank(superAdmin);
        escrow.setPayoutCap(5000, 0);

        _settle(1, worker1, 4000);

        vm.expectRevert(EscrowPool.PayoutCapExceeded.selector);
        _settle(2, worker1, 4000);
        assertFalse(escrow.settledCycles(2));

        vm.warp(START_TS + DAY);
        _settle(2, worker1, 4000); // fresh window

        (,, uint256 windowStart, uint256 used) = escrow.payoutCapStatus();
        assertEq(windowStart, START_TS + DAY);
        assertEq(used, 4000);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Platform fee
    // ─────────────────────────────────────────────────────────────────────

    /// 501 bps is above the 500 hard cap.
    function testSetPlatformFeeBpsRejectsAboveMax() public {
        vm.prank(superAdmin);
        vm.expectRevert(EscrowPool.FeeTooHigh.selector);
        escrow.setPlatformFeeBps(501);
    }

    /// Retuning to 500 bps changes live math (1000 → 50/950 instead of
    /// 25/975 at the 250 default).
    function testSetPlatformFeeBpsRetuneChangesNet() public {
        vm.expectEmit(address(escrow));
        emit EscrowPool.PlatformFeeUpdated(250, 500);
        vm.prank(superAdmin);
        escrow.setPlatformFeeBps(500);
        assertEq(escrow.platformFeeBps(), 500);

        _deposit(alice, 10_000);
        vm.expectEmit(address(escrow));
        emit EscrowPool.SettlementFinalized(1, 950, 50, 1);
        _settle(1, worker1, 1000);

        assertEq(token.balanceOf(worker1), 950);
        assertEq(escrow.feePool(), 50);
    }

    /// A non-super-admin cannot retune the fee.
    function testSetPlatformFeeBpsNonSuperAdminReverts() public {
        address[3] memory callers = [attacker, opsAdmin, orchestrator];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, callers[i]));
            escrow.setPlatformFeeBps(100);
        }
    }

    /// Fee 0 is allowed (fee-free settlement).
    function testPlatformFeeZeroAllowed() public {
        vm.prank(superAdmin);
        escrow.setPlatformFeeBps(0);

        _deposit(alice, 10_000);
        _settle(1, worker1, 1000);
        assertEq(token.balanceOf(worker1), 1000);
        assertEq(escrow.feePool(), 0);
        assertEq(escrow.totalFeesCollected(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fee withdrawal + cap
    // ─────────────────────────────────────────────────────────────────────

    /// Partial fee sweep.
    function testWithdrawFeesPartialSweep() public {
        _deposit(alice, 10_000);
        _settle(1, worker1, 8000); // fee 200
        assertEq(escrow.feePool(), 200);

        vm.expectEmit(address(escrow));
        emit EscrowPool.FeesWithdrawn(150, feeRecipient);
        vm.prank(opsAdmin);
        escrow.withdrawFees(150, feeRecipient);

        assertEq(escrow.feePool(), 50);
        assertEq(token.balanceOf(feeRecipient), 150);
    }

    /// No role → cannot sweep fees.
    function testNonAdminCannotWithdrawFees() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, ADMIN_ROLE, attacker));
        escrow.withdrawFees(1, attacker);
    }

    /// Deliberate asymmetry: sweeping fees is admin-only, so the
    /// orchestrator (settlement) key cannot do it even though it can settle.
    function testOrchestratorCannotWithdrawFees() public {
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, ADMIN_ROLE, orchestrator));
        escrow.withdrawFees(1, orchestrator);
    }

    /// The super admin counts as an admin for the fee-sweep gate.
    function testSuperAdminCanWithdrawFees() public {
        _deposit(alice, 10_000);
        _settle(1, worker1, 8000); // fee 200

        vm.prank(superAdmin);
        escrow.withdrawFees(50, feeRecipient);
        assertEq(token.balanceOf(feeRecipient), 50);
    }

    /// The cap boundary is inclusive (used + amount <= cap).
    function testWithdrawFeesAtCapSucceeds() public {
        _deposit(alice, 50_000);
        _settle(1, worker1, 40_000); // fee 1000

        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 0);

        vm.prank(opsAdmin);
        escrow.withdrawFees(1000, feeRecipient); // exactly == cap

        assertEq(token.balanceOf(feeRecipient), 1000);
        (uint256 cap,,, uint256 used) = escrow.feeCapStatus();
        assertEq(cap, 1000);
        assertEq(used, 1000);
    }

    /// With enough BALANCE, an over-cap request hits the cap error — proves
    /// the balance check runs before the cap check.
    function testWithdrawFeesExceedsCapReverts() public {
        _deposit(alice, 100_000);
        _settle(1, worker1, 80_000); // fee 2000 — balance check passes

        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 0);

        vm.prank(opsAdmin);
        vm.expectRevert(EscrowPool.AdminWithdrawalCapExceeded.selector);
        escrow.withdrawFees(1001, feeRecipient);
    }

    /// feeCap == 0 pauses all fee withdrawals.
    function testWithdrawFeesWhenPausedReverts() public {
        _deposit(alice, 10_000);
        _settle(1, worker1, 8000); // fee 200 — so the balance check passes

        vm.prank(superAdmin);
        escrow.setFeeCap(0, 0);

        vm.prank(opsAdmin);
        vm.expectRevert(EscrowPool.AdminWithdrawalsPaused.selector);
        escrow.withdrawFees(1, feeRecipient);
    }

    /// The super admin can retune the cap; usage records.
    function testSuperAdminCanRaiseFeeCap() public {
        _deposit(alice, 50_000);
        _settle(1, worker1, 40_000); // fee 1000

        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 0);
        vm.prank(opsAdmin);
        escrow.withdrawFees(500, feeRecipient);

        (uint256 cap,,, uint256 used) = escrow.feeCapStatus();
        assertEq(cap, 1000);
        assertEq(used, 500);
    }

    /// The amount check runs BEFORE the balance/pause/cap logic —
    /// withdrawFees(0) reverts InvalidAmount even while paused with an empty
    /// fee pool.
    function testWithdrawFeesZeroAmountReverts() public {
        vm.prank(superAdmin);
        escrow.setFeeCap(0, 0); // paused, feePool empty

        vm.prank(opsAdmin);
        vm.expectRevert(EscrowPool.InvalidAmount.selector);
        escrow.withdrawFees(0, feeRecipient);
    }

    /// The fee window rolls after its length elapses.
    function testFeeWindowRolls() public {
        _deposit(alice, 100_000);
        _settle(1, worker1, 80_000); // fee 2000

        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 0);

        vm.prank(opsAdmin);
        escrow.withdrawFees(1000, feeRecipient); // window exhausted

        vm.prank(opsAdmin);
        vm.expectRevert(EscrowPool.AdminWithdrawalCapExceeded.selector);
        escrow.withdrawFees(1, feeRecipient);

        vm.warp(START_TS + DAY);
        vm.prank(opsAdmin);
        escrow.withdrawFees(1000, feeRecipient); // fresh window

        (,, uint256 windowStart, uint256 used) = escrow.feeCapStatus();
        assertEq(windowStart, START_TS + DAY);
        assertEq(used, 1000);
    }

    /// Every cap update resets the window (start = now, used = 0); a
    /// window arg of 0 keeps the current length, > 0 replaces it; the event
    /// carries the post-update effective window.
    function testSetFeeCapResetsWindowAndUpdatesLength() public {
        _deposit(alice, 100_000);
        _settle(1, worker1, 80_000); // fee 2000

        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 0);
        vm.prank(opsAdmin);
        escrow.withdrawFees(400, feeRecipient); // used 400

        vm.expectEmit(address(escrow));
        emit EscrowPool.FeeCapUpdated(1000, 3600);
        vm.prank(superAdmin);
        escrow.setFeeCap(1000, 3600);

        (uint256 cap, uint256 window, uint256 windowStart, uint256 used) = escrow.feeCapStatus();
        assertEq(cap, 1000);
        assertEq(window, 3600);
        assertEq(windowStart, block.timestamp);
        assertEq(used, 0); // reset on every cap update

        // window arg 0 keeps the current (3600) length.
        vm.expectEmit(address(escrow));
        emit EscrowPool.FeeCapUpdated(700, 3600);
        vm.prank(superAdmin);
        escrow.setFeeCap(700, 0);
        (, window,,) = escrow.feeCapStatus();
        assertEq(window, 3600);
    }

    /// Only the super admin can set the fee cap.
    function testSetFeeCapNonSuperAdminReverts() public {
        address[3] memory callers = [attacker, opsAdmin, orchestrator];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, callers[i]));
            escrow.setFeeCap(1000, 0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initial state
    // ─────────────────────────────────────────────────────────────────────

    /// Genesis seeds — 250 bps fee, 100k-PYRA/24h fee cap, payout cap
    /// disabled, everything else zero.
    function testInitialPoolState() public view {
        assertEq(address(escrow.admin()), address(pyraAdmin));
        assertEq(address(escrow.token()), address(token));
        assertEq(escrow.pool(), 0);
        assertEq(escrow.feePool(), 0);
        assertEq(escrow.currentCycle(), 0);
        assertEq(escrow.lastSettlement(), 0);
        assertEq(escrow.totalDeposited(), 0);
        assertEq(escrow.totalWithdrawn(), 0);
        assertEq(escrow.totalPaidWorkers(), 0);
        assertEq(escrow.totalFeesCollected(), 0);
        assertEq(escrow.platformFeeBps(), 250);
        assertEq(escrow.clientBalance(address(0xBEEF)), 0); // stranger reads 0, no revert
        assertFalse(escrow.settledCycles(1));

        (uint256 feeCap, uint256 feeWindow, uint256 feeStart, uint256 feeUsed) = escrow.feeCapStatus();
        assertEq(feeCap, 100_000_000_000_000); // 100k PYRA in base units
        assertEq(feeWindow, DAY);
        assertEq(feeStart, 0);
        assertEq(feeUsed, 0);

        (uint256 pCap, uint256 pWindow, uint256 pStart, uint256 pUsed) = escrow.payoutCapStatus();
        assertEq(pCap, 0); // 0 = disabled (NOT paused)
        assertEq(pWindow, DAY);
        assertEq(pStart, 0);
        assertEq(pUsed, 0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Initializer / UUPS upgrade
    // ─────────────────────────────────────────────────────────────────────

    function testInitializeCannotRunTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        escrow.initialize(address(pyraAdmin), address(token));
    }

    function testImplementationInitializersDisabled() public {
        EscrowPool impl = new EscrowPool();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(pyraAdmin), address(token));
    }

    /// Audit L4: zero admin/token addresses must be rejected at initialize.
    function testInitializeZeroAddressReverts() public {
        EscrowPool impl = new EscrowPool();
        vm.expectRevert(EscrowPool.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(EscrowPool.initialize, (address(0), address(token))));
        vm.expectRevert(EscrowPool.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(EscrowPool.initialize, (address(pyraAdmin), address(0))));
    }

    function testUpgradeNonSuperAdminReverts() public {
        EscrowPool newImpl = new EscrowPool();
        address[3] memory callers = [attacker, opsAdmin, orchestrator];
        for (uint256 i = 0; i < callers.length; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(EscrowPool.NotAuthorized.selector, DEFAULT_ADMIN_ROLE, callers[i]));
            escrow.upgradeToAndCall(address(newImpl), "");
        }
    }

    function testSuperAdminCanUpgradeAndStatePersists() public {
        _deposit(alice, 1234);

        EscrowPool newImpl = new EscrowPool();
        vm.prank(superAdmin);
        escrow.upgradeToAndCall(address(newImpl), "");

        address impl = address(uint160(uint256(vm.load(address(escrow), IMPLEMENTATION_SLOT))));
        assertEq(impl, address(newImpl));

        // Storage survives the implementation swap.
        assertEq(escrow.clientBalance(alice), 1234);
        assertEq(escrow.platformFeeBps(), 250);
        _deposit(alice, 1);
        assertEq(escrow.clientBalance(alice), 1235);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Reentrancy (guard on every outbound-token path)
    // ─────────────────────────────────────────────────────────────────────

    function testWithdrawReentrancyBlocked() public {
        (ReentrantToken evil, EscrowPool pool2) = _deployEvilPool();
        evil.setAttack(pool2, 1); // re-enter withdraw() from the outbound transfer

        vm.prank(alice);
        vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
        pool2.withdraw(400);
    }

    function testSettleBatchReentrancyBlocked() public {
        (ReentrantToken evil, EscrowPool pool2) = _deployEvilPool();
        evil.setAttack(pool2, 2); // re-enter settleBatch() from the worker payout

        (address[] memory ws, uint256[] memory gs) = _single(worker1, 1000);
        vm.prank(orchestrator);
        vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
        pool2.settleBatch(1, ws, gs);
    }

    function testWithdrawFeesReentrancyBlocked() public {
        (ReentrantToken evil, EscrowPool pool2) = _deployEvilPool();

        // Seed the fee pool with a benign settlement first.
        (address[] memory ws, uint256[] memory gs) = _single(worker1, 8000);
        vm.prank(orchestrator);
        pool2.settleBatch(1, ws, gs); // fee 200

        evil.setAttack(pool2, 3); // re-enter withdrawFees() from the sweep
        vm.prank(opsAdmin);
        vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
        pool2.withdrawFees(100, feeRecipient);
    }
}
