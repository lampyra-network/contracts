// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {MockPYRA} from "../mocks/MockPYRA.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";
import {PyraTreasury} from "../../src/PyraTreasury.sol";
import {EscrowPool} from "../../src/EscrowPool.sol";
import {PyraPresale} from "../../src/PyraPresale.sol";

/// @title LampyraHandler — bounded random actions for the invariant suite
/// @notice Every action pranks a legitimate actor and uses bound() so the fuzzer
/// spends its depth on REACHABLE states, not reverts. Ghost counters mirror what
/// the contracts should be doing; invariants cross-check them against contract
/// accounting and real token balances.
contract LampyraHandler is Test {
    MockPYRA public immutable pyra;
    MockUSDC public immutable usdc;
    PyraTreasury public immutable treasury;
    EscrowPool public immutable escrow;
    PyraPresale public immutable presale;

    address public immutable opsAdmin;
    address public immutable orchestrator;
    address[3] public actors; // clients, presale buyers, and settlement workers

    // Ghost accounting
    uint256 public gEscrowDeposited;
    uint256 public gEscrowClientWithdrawn;
    uint256 public gEscrowFeesWithdrawn;
    uint256 public gPresaleUsdcWithdrawn;
    uint64 public nextCycleId = 1;
    uint64[] public settledIds;
    uint256 public gReplayAttempts;
    uint256 public gReplaysPaid; // MUST stay 0 — a paid replay is a double-settlement

    constructor(
        MockPYRA pyra_,
        MockUSDC usdc_,
        PyraTreasury treasury_,
        EscrowPool escrow_,
        PyraPresale presale_,
        address opsAdmin_,
        address orchestrator_,
        address[3] memory actors_
    ) {
        pyra = pyra_;
        usdc = usdc_;
        treasury = treasury_;
        escrow = escrow_;
        presale = presale_;
        opsAdmin = opsAdmin_;
        orchestrator = orchestrator_;
        actors = actors_;
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    // ───────────────────────── EscrowPool ─────────────────────────

    function escrowDeposit(uint256 actorSeed, uint256 amount) external {
        address a = _actor(actorSeed);
        uint256 bal = pyra.balanceOf(a);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);
        vm.startPrank(a);
        pyra.approve(address(escrow), amount);
        escrow.deposit(amount, bytes32("fuzz"));
        vm.stopPrank();
        gEscrowDeposited += amount;
    }

    function escrowWithdraw(uint256 actorSeed, uint256 amount) external {
        address a = _actor(actorSeed);
        uint256 ledger = escrow.clientBalance(a);
        if (ledger == 0) return;
        amount = bound(amount, 1, ledger);
        vm.prank(a);
        try escrow.withdraw(amount) {
            gEscrowClientWithdrawn += amount;
        } catch {} // pool may be legitimately drained below the ledger promise
    }

    function escrowSettle(uint256 workerSeed, uint256 amount1, uint256 amount2) external {
        uint256 pool = escrow.pool();
        if (pool < 4) return;
        address[] memory workers = new address[](2);
        workers[0] = _actor(workerSeed);
        workers[1] = _actor(workerSeed + 1);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = bound(amount1, 1, pool / 4);
        amounts[1] = bound(amount2, 1, pool / 4);
        uint64 id = nextCycleId++;
        vm.prank(orchestrator);
        try escrow.settleBatch(id, workers, amounts) {
            settledIds.push(id);
        } catch {} // payout cap can legitimately reject a cycle
    }

    /// @dev The core dedup property: re-settling a used cycleId must NEVER pay.
    function escrowSettleReplay(uint256 idSeed, uint256 amount) external {
        if (settledIds.length == 0) return;
        uint64 id = settledIds[idSeed % settledIds.length];
        uint256 paidBefore = escrow.totalPaidWorkers();
        address[] memory workers = new address[](1);
        workers[0] = _actor(idSeed);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = bound(amount, 1, 1_000_000 * 1e9);
        gReplayAttempts++;
        vm.prank(orchestrator);
        try escrow.settleBatch(id, workers, amounts) {
            gReplaysPaid++; // FINDING if this ever happens
        } catch {}
        if (escrow.totalPaidWorkers() != paidBefore) gReplaysPaid++;
    }

    function escrowWithdrawFees(uint256 amount) external {
        uint256 feePool = escrow.feePool();
        if (feePool == 0) return;
        amount = bound(amount, 1, feePool);
        vm.prank(opsAdmin);
        try escrow.withdrawFees(amount, opsAdmin) {
            gEscrowFeesWithdrawn += amount;
        } catch {} // fee cap window can reject
    }

    // ───────────────────────── PyraPresale ─────────────────────────

    function presalePurchase(uint256 actorSeed, uint256 maxPayment) external {
        address a = _actor(actorSeed);
        uint256 bal = usdc.balanceOf(a);
        if (bal == 0 || !presale.isActive()) return;
        maxPayment = bound(maxPayment, 1, bal > 20_000 * 1e6 ? 20_000 * 1e6 : bal);
        vm.startPrank(a);
        usdc.approve(address(presale), maxPayment);
        try presale.purchase(maxPayment) {} catch {} // caps/stage edges may reject
        vm.stopPrank();
    }

    function presaleClaim(uint256 actorSeed) external {
        vm.prank(_actor(actorSeed));
        try presale.claimVested() {} catch {} // nothing vested yet is fine
    }

    function presaleWithdrawUsdc(uint256 amount) external {
        uint256 bal = usdc.balanceOf(address(presale));
        if (bal == 0) return;
        amount = bound(amount, 1, bal);
        vm.prank(opsAdmin);
        try presale.withdrawRaisedUsdc(amount) {
            gPresaleUsdcWithdrawn += amount;
        } catch {} // rolling USDC cap can reject
    }

    // ───────────────────────── PyraTreasury ─────────────────────────

    function treasuryWithdraw(uint256 which, uint256 amount) external {
        amount = bound(amount, 1, 10_000 * 1e9);
        vm.startPrank(opsAdmin);
        which = which % 4;
        if (which == 0) try treasury.withdrawCommunityRewards(amount) {} catch {}
        else if (which == 1) try treasury.withdrawLiquidity(amount) {} catch {}
        else if (which == 2) try treasury.withdrawReserve(amount) {} catch {}
        else try treasury.withdrawFees(amount) {} catch {}
        vm.stopPrank();
    }

    function treasuryDepositFees(uint256 actorSeed, uint256 amount) external {
        address a = _actor(actorSeed);
        uint256 bal = pyra.balanceOf(a);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);
        vm.startPrank(a);
        pyra.approve(address(treasury), amount);
        treasury.depositFees(amount);
        vm.stopPrank();
    }

    // ───────────────────────── Time ─────────────────────────

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1 hours, 7 days));
    }
}
