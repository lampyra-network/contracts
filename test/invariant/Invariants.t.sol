// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {PyraAdmin} from "../../src/PyraAdmin.sol";
import {PyraTreasury} from "../../src/PyraTreasury.sol";
import {WorkerRegistry} from "../../src/WorkerRegistry.sol";
import {EscrowPool} from "../../src/EscrowPool.sol";
import {PyraPresale} from "../../src/PyraPresale.sol";
import {MockPYRA} from "../mocks/MockPYRA.sol";
import {MockUSDC} from "../mocks/MockUSDC.sol";
import {LampyraHandler} from "./Handlers.sol";

/// @title LampyraInvariants — stateful fuzz over the full deployed system
/// @notice Deploys the REAL genesis (mirroring script/Deploy.s.sol: admin → proxies →
/// supply to treasury → initializeDistribution → capped presale pull → presale proxy
/// funded via predicted-address approval → payout cap on) and then lets the handler
/// hammer it with bounded random actions. The invariants are the accounting laws the
/// audit reasoned about — here they are enforced mechanically.
contract LampyraInvariants is StdInvariant, Test {
    uint256 internal constant TOTAL_SUPPLY = 10_000_000_000 * 1e9;

    PyraAdmin internal pyraAdmin;
    MockPYRA internal pyra;
    MockUSDC internal usdc;
    PyraTreasury internal treasury;
    WorkerRegistry internal registry;
    EscrowPool internal escrow;
    PyraPresale internal presale;
    LampyraHandler internal handler;

    address internal opsAdmin = makeAddr("opsAdmin");
    address internal orchestrator = makeAddr("orchestrator");
    address[3] internal actors = [makeAddr("actor0"), makeAddr("actor1"), makeAddr("actor2")];

    function setUp() public {
        // Genesis, exactly as Deploy.s.sol performs it (this = deployer + super admin).
        pyraAdmin = new PyraAdmin(0, address(this));
        pyraAdmin.grantRole(pyraAdmin.ADMIN_ROLE(), opsAdmin);
        pyraAdmin.grantRole(pyraAdmin.ORCHESTRATOR_ROLE(), orchestrator);

        pyra = new MockPYRA(address(this));
        usdc = new MockUSDC();

        treasury = PyraTreasury(
            address(
                new ERC1967Proxy(
                    address(new PyraTreasury()),
                    abi.encodeCall(PyraTreasury.initialize, (address(pyraAdmin), address(pyra)))
                )
            )
        );
        registry = WorkerRegistry(
            address(
                new ERC1967Proxy(
                    address(new WorkerRegistry()),
                    abi.encodeCall(WorkerRegistry.initialize, (address(pyraAdmin), address(pyra)))
                )
            )
        );
        escrow = EscrowPool(
            address(
                new ERC1967Proxy(
                    address(new EscrowPool()),
                    abi.encodeCall(EscrowPool.initialize, (address(pyraAdmin), address(pyra)))
                )
            )
        );

        pyra.transfer(address(treasury), TOTAL_SUPPLY);
        treasury.initializeDistribution();

        uint256 presaleAllocation = treasury.PRESALE_ALLOCATION();
        treasury.setPresaleCap(presaleAllocation, 1 hours);
        treasury.withdrawPresale(presaleAllocation);

        PyraPresale presaleImpl = new PyraPresale();
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        pyra.approve(predicted, presaleAllocation);
        presale = PyraPresale(
            address(
                new ERC1967Proxy(
                    address(presaleImpl),
                    abi.encodeCall(PyraPresale.initialize, (address(pyraAdmin), address(pyra), address(usdc)))
                )
            )
        );
        require(address(presale) == predicted, "prediction failed");

        escrow.setPayoutCap(100_000 * 1e9, 4 hours);

        // Circulating PYRA for the actors (community-pool withdrawal, the
        // legitimate route tokens reach users) + USDC for presale buys.
        treasury.setCommunityCap(600_000_000 * 1e9, 1 hours);
        treasury.withdrawCommunityRewards(600_000_000 * 1e9);
        for (uint256 i = 0; i < actors.length; i++) {
            pyra.transfer(actors[i], 200_000_000 * 1e9);
            usdc.mint(actors[i], 1_000_000 * 1e6);
        }

        handler = new LampyraHandler(pyra, usdc, treasury, escrow, presale, opsAdmin, orchestrator, actors);
        targetContract(address(handler));
    }

    /// Treasury solvency: real balance always equals its internal pool accounting
    /// (the handler creates no vesting schedules, so pools are the whole story).
    function invariant_treasurySolvency() public view {
        uint256 pools = treasury.presalePoolBalance() + treasury.teamPoolBalance()
            + treasury.liquidityPoolBalance() + treasury.communityPoolBalance()
            + treasury.reservePoolBalance() + treasury.feePoolBalance();
        assertEq(pyra.balanceOf(address(treasury)), pools, "treasury balance != pool accounting");
    }

    /// Escrow solvency: real balance always equals client pool + fee pool.
    function invariant_escrowSolvency() public view {
        assertEq(
            pyra.balanceOf(address(escrow)),
            escrow.pool() + escrow.feePool(),
            "escrow balance != pool + feePool"
        );
    }

    /// Escrow ledger conservation: every base unit in is accounted out.
    function invariant_escrowAccounting() public view {
        assertEq(
            escrow.pool(),
            escrow.totalDeposited() - escrow.totalWithdrawn() - escrow.totalPaidWorkers()
                - escrow.totalFeesCollected(),
            "escrow pool != deposits - withdrawals - payouts - fees"
        );
        assertEq(
            escrow.feePool(),
            escrow.totalFeesCollected() - handler.gEscrowFeesWithdrawn(),
            "feePool != collected - withdrawn"
        );
    }

    /// No double settlement, ever: a replayed cycleId never pays a base unit.
    function invariant_noDoubleSettlement() public view {
        assertEq(handler.gReplaysPaid(), 0, "a replayed cycleId paid out");
    }

    /// Presale solvency: it can always cover every unclaimed vesting obligation,
    /// and its USDC balance is exactly what was raised minus what admins withdrew.
    function invariant_presaleSolvency() public view {
        assertGe(
            pyra.balanceOf(address(presale)),
            presale.outstandingObligations(),
            "presale cannot cover vesting obligations"
        );
        // usdcRaised is SELF-DECREMENTING on withdrawal by design: it tracks
        // raised-and-still-held, not cumulative-raised — so the law is exact
        // equality with the real balance at all times.
        assertEq(usdc.balanceOf(address(presale)), presale.usdcRaised(), "presale USDC != usdcRaised");
    }

    /// Global conservation: the fixed 10B supply is fully accounted for across
    /// every holder the system can reach. Nothing minted, nothing lost.
    function invariant_globalConservation() public view {
        uint256 sum = pyra.balanceOf(address(treasury)) + pyra.balanceOf(address(escrow))
            + pyra.balanceOf(address(presale)) + pyra.balanceOf(address(this))
            + pyra.balanceOf(opsAdmin) + pyra.balanceOf(orchestrator) + pyra.balanceOf(address(handler));
        for (uint256 i = 0; i < actors.length; i++) {
            sum += pyra.balanceOf(actors[i]);
        }
        assertEq(sum, TOTAL_SUPPLY, "10B supply not conserved");
        assertEq(pyra.totalSupply(), TOTAL_SUPPLY, "total supply changed");
    }
}
