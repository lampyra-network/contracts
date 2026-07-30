// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockUSDC — minimal 6-decimal ERC-20 stand-in for USDC in tests
/// @notice The presale quotes prices in USDC base units (6 decimals) per whole
/// PYRA; this mock exists purely so tests can mint payment funds at will.
contract MockUSDC is ERC20 {
    constructor() ERC20("USD Coin", "USDC") {}

    /// @notice USDC uses 6 decimals — 1 USDC = 1e6 base units.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice Open mint for test funding.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
