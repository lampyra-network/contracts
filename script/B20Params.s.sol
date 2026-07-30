// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IB20Factory} from "base-std/interfaces/IB20Factory.sol";
import {B20FactoryLib} from "base-std/lib/B20FactoryLib.sol";
import {B20Constants} from "base-std/lib/B20Constants.sol";

/// @notice Prints the exact `createB20` calldata for the $PYRA genesis. Pure local
/// computation (official base-std encoders) — the actual call is sent with `cast`
/// by script/genesis-b20.sh, because vanilla forge cannot execute the factory
/// precompile locally. The LAST hex line of output is the calldata.
/// Env: PRIVATE_KEY (defines the initial admin = deployer) · B20_SALT (bytes32,
/// default keccak256("lampyra-genesis-v1")).
contract B20Params is Script {
    uint256 internal constant TOTAL_SUPPLY = 10_000_000_000 * 1e9;

    function run() external view {
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        bytes32 salt = vm.envOr("B20_SALT", keccak256("lampyra-genesis-v1"));

        bytes memory params = B20FactoryLib.encodeAssetCreateParams("Lampyra", "PYRA", deployer, 9);
        bytes[] memory initCalls = new bytes[](2);
        initCalls[0] = B20FactoryLib.encodeGrantRole(B20Constants.MINT_ROLE, deployer);
        initCalls[1] = B20FactoryLib.encodeUpdateSupplyCap(TOTAL_SUPPLY);

        console.log("deployer/initial admin:", deployer);
        console.log("salt:");
        console.logBytes32(salt);
        console.log("createB20 calldata (last hex line):");
        console.logBytes(abi.encodeCall(IB20Factory.createB20, (IB20Factory.B20Variant.ASSET, salt, params, initCalls)));
    }
}
