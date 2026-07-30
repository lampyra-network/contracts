// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @title MockPYRA — test stand-in for the PYRA B20
/// @notice The real $PYRA is a B20: a native precompile token on Base with no
/// EVM bytecode to instantiate under vanilla forge (created at deploy time via
/// the B20 factory — see ../../B20.md). This mock mirrors the exact surface our
/// contracts rely on: ERC-20 + EIP-2612 permit, 9 decimals, fixed 10B supply
/// minted once to `recipient`, no mint afterwards.
contract MockPYRA is ERC20, ERC20Permit {
    /// @notice 10,000,000,000 PYRA at 9 decimals (1e19 base units).
    uint256 public constant TOTAL_SUPPLY = 10_000_000_000 * 1e9;

    constructor(address recipient) ERC20("Lampyra", "PYRA") ERC20Permit("Lampyra") {
        _mint(recipient, TOTAL_SUPPLY);
    }

    /// @notice PYRA uses 9 decimals — 1 PYRA = 1e9 base units, matching the
    /// off-chain ledger's unit math exactly.
    function decimals() public pure override returns (uint8) {
        return 9;
    }
}
