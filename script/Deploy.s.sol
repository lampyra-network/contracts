// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PyraAdmin} from "../src/PyraAdmin.sol";
import {PyraTreasury} from "../src/PyraTreasury.sol";
import {WorkerRegistry} from "../src/WorkerRegistry.sol";
import {EscrowPool} from "../src/EscrowPool.sol";
import {PyraPresale} from "../src/PyraPresale.sol";
import {MockPYRA} from "../test/mocks/MockPYRA.sol";
import {MockUSDC} from "../test/mocks/MockUSDC.sol";

/// @title Lampyra genesis — one script for the whole EVM-side ceremony
/// @notice Precondition in "b20" mode: the PYRA B20 already exists (created by
/// script/genesis-b20.sh — vanilla forge cannot execute the factory precompile
/// locally) and the DEPLOYER holds the full 10B supply with the token admin
/// already renounced. In "mock" mode (default on chain 31337) a MockPYRA fills
/// that role and the rehearsal is fully self-contained.
///
/// Ceremony (identical in both modes from here):
///   1. PyraAdmin (deployer = interim super admin)
///   2. Treasury / WorkerRegistry / EscrowPool proxies
///   3. full supply -> treasury, initializeDistribution()
///   4. raise presale pool cap, withdrawPresale(2.5B) -> deployer
///   5. approve the PREDICTED presale proxy address, deploy PyraPresale proxy
///      (its initializer pulls the 2.5B allocation atomically)
///   6. EscrowPool payout cap (blast-radius limiter — audit M1)
///   7. optional ORCHESTRATOR_ROLE grant; begin two-step super-admin transfer
///      if SUPER_ADMIN != deployer (accepted later from the Safe/Ledger)
///
/// Env: PRIVATE_KEY (required) · PYRA_MODE ("mock"/"b20") · PYRA_TOKEN (b20 mode) ·
/// USDC (defaults: chain 8453/84532 canonical USDC, else MockUSDC) · SUPER_ADMIN ·
/// ORCHESTRATOR · ADMIN_DELAY (s) · PAYOUT_CAP / PAYOUT_WINDOW.
/// Writes deployments/<chainid>.env.
contract Deploy is Script {
    uint256 internal constant TOTAL_SUPPLY = 10_000_000_000 * 1e9; // 10B PYRA @ 9 decimals

    address internal constant USDC_BASE_MAINNET = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address internal constant USDC_BASE_SEPOLIA = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    struct Deployed {
        address deployer;
        PyraAdmin admin;
        address token;
        address usdc;
        PyraTreasury treasury;
        WorkerRegistry registry;
        EscrowPool escrow;
        PyraPresale presale;
    }

    Deployed internal d;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        d.deployer = vm.addr(pk);

        vm.startBroadcast(pk);
        _deployCore();
        _fundAndOpen();
        _rolesAndHandoff();
        vm.stopBroadcast();

        _writeOut();
    }

    /// @dev Steps 1–2: access-control root, token, USDC, the three unfunded proxies.
    function _deployCore() internal {
        d.admin = new PyraAdmin(uint48(vm.envOr("ADMIN_DELAY", uint256(0))), d.deployer);

        d.token = _isMock() ? address(new MockPYRA(d.deployer)) : vm.envAddress("PYRA_TOKEN");
        require(IERC20(d.token).balanceOf(d.deployer) == TOTAL_SUPPLY, "deployer must hold the full 10B supply");

        d.usdc = vm.envOr("USDC", address(0));
        if (d.usdc == address(0)) {
            if (block.chainid == 8453) d.usdc = USDC_BASE_MAINNET;
            else if (block.chainid == 84532) d.usdc = USDC_BASE_SEPOLIA;
            else d.usdc = address(new MockUSDC());
        }

        d.treasury = PyraTreasury(
            address(
                new ERC1967Proxy(
                    address(new PyraTreasury()), abi.encodeCall(PyraTreasury.initialize, (address(d.admin), d.token))
                )
            )
        );
        d.registry = WorkerRegistry(
            address(
                new ERC1967Proxy(
                    address(new WorkerRegistry()), abi.encodeCall(WorkerRegistry.initialize, (address(d.admin), d.token))
                )
            )
        );
        d.escrow = EscrowPool(
            address(
                new ERC1967Proxy(
                    address(new EscrowPool()), abi.encodeCall(EscrowPool.initialize, (address(d.admin), d.token))
                )
            )
        );
    }

    /// @dev Steps 3–6: treasury funding, presale pull via predicted proxy address,
    /// settlement payout cap (audit M1: defaults to disabled).
    function _fundAndOpen() internal {
        IERC20(d.token).transfer(address(d.treasury), TOTAL_SUPPLY);
        d.treasury.initializeDistribution();

        uint256 presaleAllocation = d.treasury.PRESALE_ALLOCATION();
        d.treasury.setPresaleCap(presaleAllocation, 1 hours);
        d.treasury.withdrawPresale(presaleAllocation);

        // Approve the PREDICTED presale proxy address so the initializer's atomic
        // transferFrom pull succeeds at construction.
        PyraPresale presaleImpl = new PyraPresale();
        address predicted = vm.computeCreateAddress(d.deployer, vm.getNonce(d.deployer) + 1);
        IERC20(d.token).approve(predicted, presaleAllocation);
        d.presale = PyraPresale(
            address(
                new ERC1967Proxy(
                    address(presaleImpl), abi.encodeCall(PyraPresale.initialize, (address(d.admin), d.token, d.usdc))
                )
            )
        );
        require(address(d.presale) == predicted, "presale proxy address prediction failed");

        d.escrow.setPayoutCap(
            vm.envOr("PAYOUT_CAP", uint256(100_000 * 1e9)), vm.envOr("PAYOUT_WINDOW", uint256(4 hours))
        );
    }

    /// @dev Step 7: optional orchestrator grant; begin two-step super-admin handoff.
    function _rolesAndHandoff() internal {
        address orchestrator = vm.envOr("ORCHESTRATOR", address(0));
        if (orchestrator != address(0)) {
            d.admin.grantRole(d.admin.ORCHESTRATOR_ROLE(), orchestrator);
        }
        address superAdmin = vm.envOr("SUPER_ADMIN", d.deployer);
        if (superAdmin != d.deployer) {
            // Grant the incoming super admin ADMIN_ROLE too, so it can reach
            // the admin console (which gates on current-admin status) to
            // accept the two-step transfer. PyraAdmin._acceptDefaultAdminTransfer
            // auto-revokes this ADMIN_ROLE on accept, leaving the Ledger as the
            // sole super admin with no leftover role. Without this, the pending
            // admin is locked out of the console and must accept via cast.
            d.admin.grantRole(d.admin.ADMIN_ROLE(), superAdmin);
            d.admin.beginDefaultAdminTransfer(superAdmin);
        }
    }

    function _writeOut() internal {
        string memory out = string.concat(
            "PYRA_ADMIN=", vm.toString(address(d.admin)), "\n",
            "PYRA_TOKEN=", vm.toString(d.token), "\n",
            "TREASURY=", vm.toString(address(d.treasury)), "\n",
            "WORKER_REGISTRY=", vm.toString(address(d.registry)), "\n",
            "ESCROW=", vm.toString(address(d.escrow)), "\n",
            "PRESALE=", vm.toString(address(d.presale)), "\n",
            "USDC=", vm.toString(d.usdc), "\n"
        );
        vm.createDir("deployments", true);
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".env");
        vm.writeFile(path, out);
        console.log("wrote", path);
        console.log(out);
    }

    function _isMock() internal view returns (bool) {
        string memory def = block.chainid == 31337 ? "mock" : "b20";
        return keccak256(bytes(vm.envOr("PYRA_MODE", def))) == keccak256("mock");
    }
}
