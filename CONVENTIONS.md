# Lampyra ($PYRA) Solidity conventions

These rules are binding for every contract in `src/` and every test in `test/`.
This file is the *structural* truth — contract shapes, naming, storage, and
patterns; per-contract behavior is specified alongside each contract.
Brand: the network is **Lampyra**, the token is **$PYRA**. These are the only
names permitted in Solidity source, comments, errors, or test names — no other
project or network name may appear anywhere.

## Toolchain
- `pragma solidity ^0.8.26;` (foundry.toml pins solc 0.8.26, evm cancun).
- OpenZeppelin v5.1.0 vendored at `lib/openzeppelin-contracts` and
  `lib/openzeppelin-contracts-upgradeable` (remappings in `remappings.txt`).
- Tests: forge-std `Test`.

## The six contracts (fixed names + deployment shape)

| File | Contract | Proxy? | Constructor / initializer (EXACT signatures) |
|---|---|---|---|
| — (no token contract) | **$PYRA is a B20** — Base-native precompile token, created via the B20 factory at deploy time (see `B20.md`) | n/a — no bytecode at all | Tests use `test/mocks/MockPYRA.sol`: `constructor(address recipient)` mints `TOTAL_SUPPLY` to `recipient`, 9 decimals, ERC-20 + Permit |
| `src/PyraAdmin.sol` | `PyraAdmin` | No proxy | `constructor(uint48 initialDelay, address initialSuperAdmin)` → OZ `AccessControlDefaultAdminRules` |
| `src/PyraTreasury.sol` | `PyraTreasury` | UUPS | `initialize(address admin_, address token_)` |
| `src/WorkerRegistry.sol` | `WorkerRegistry` | UUPS | `initialize(address admin_, address token_)` |
| `src/EscrowPool.sol` | `EscrowPool` | UUPS | `initialize(address admin_, address token_)` |
| `src/PyraPresale.sol` | `PyraPresale` | UUPS | `initialize(address admin_, address token_, address usdc_)` |

`admin_` is always the deployed `PyraAdmin` address; `token_` is `PyraToken`.

## Token facts
- $PYRA is a **B20** (Base-native precompile, ERC-20 superset) — created via
  the factory precompile, never deployed from this repo. Full config +
  genesis ceremony: `B20.md`. Contracts here only ever see `IERC20`.
- `name() = "Lampyra"`, `symbol() = "PYRA"`, **`decimals() = 9`**
  (NOT 18; the off-chain ledger assumes 1 PYRA = 1e9 base units).
- `TOTAL_SUPPLY = 10_000_000_000 * 1e9` (1e19 base units), fixed: minted once
  to the treasury, then `renounceLastAdmin()` — no mint/pause/policy forever.
- EIP-2612 permit is built into B20 (ECDSA-only — smart wallets fall back to
  batched `approve`).
- USDC has 6 decimals. Presale prices are quoted in **USDC base units per one
  whole PYRA (1e9 base units)**: cost = `pyraAmount * price / 1e9`. Use
  `uint256` everywhere; at this width the products can't overflow, so no
  widening casts or intermediate-precision gymnastics are needed.

## Access control (one central registry, satellites read from it)
- `PyraAdmin is AccessControlDefaultAdminRules` — gives two-step,
  delayed super-admin transfer natively (`DEFAULT_ADMIN_ROLE` = super admin,
  will live on a Safe with the founder's Ledger as signer).
- Role constants (declare in `PyraAdmin`, reference everywhere):
  ```solidity
  bytes32 public constant ADMIN_ROLE        = keccak256("ADMIN_ROLE");        // ops admins
  bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE"); // hot key(s), multi-wallet
  ```
  `DEFAULT_ADMIN_ROLE` is the admin of both (OZ default).
- Satellite contracts store `IAccessControl public admin;` (the PyraAdmin
  address) and gate with:
  ```solidity
  error NotAuthorized(bytes32 role, address account);
  modifier onlyRole(bytes32 role) {
      if (!admin.hasRole(role, msg.sender)) revert NotAuthorized(role, msg.sender);
      _;
  }
  ```
  (Import `IAccessControl` from `@openzeppelin/contracts/access/IAccessControl.sol`;
  copy the two role constants locally as `bytes32 private constant`.)

## UUPS pattern (the four proxied contracts)
- Inherit `Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable` (the
  reentrancy guard only where PYRA/USDC leaves the contract).
- `constructor() { _disableInitializers(); }`
- `_authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE)`
  — i.e. only the super admin (Safe) can upgrade.
- End every upgradeable contract's storage with `uint256[50] private __gap;`
  (shrink by the number of storage slots you add in future upgrades). The gap
  IS the forward-compatibility mechanism: new state consumes it, so no existing
  variable ever has to shift slots or change type.
- No in-contract version counter and no version-mismatch guard — the proxy
  makes them obsolete; there is only ever one live implementation to gate.

## Style
- **Custom errors only** (no revert strings). Error names are the ABI — once
  shipped, never rename or re-parameterize a custom error: off-chain monitors
  match on selectors, so a changed signature silently breaks them. Retire an
  error rather than repurposing its name.
- Every state mutation emits an event; events carry enough to reconstruct the
  change off-chain (the orchestrator's watcher consumes them).
- Checks-effects-interactions strictly; `SafeERC20` for USDC transfers.
- Every economic knob (fee bps, caps, tier thresholds, stage params pre-freeze,
  and the vesting durations that are meant to be tunable) is a storage variable
  with an `ADMIN_ROLE` setter, each setter enforcing its hard cap (e.g. fee
  ≤ 500 bps) and emitting an event. The knob set is deliberate and closed:
  anything not on it stays a constant — no ad-hoc tunables.
- NatSpec `@notice` on every external function; brief, factual.

## Tests (`test/<Contract>.t.sol`)
- One test contract per source contract, named `<Contract>Test`.
- Deploy proxied contracts THE REAL WAY:
  ```solidity
  import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
  X impl = new X();
  X x = X(address(new ERC1967Proxy(address(impl), abi.encodeCall(X.initialize, (...)))));
  ```
- Standard actors: `superAdmin` (deploys PyraAdmin), `opsAdmin` (granted
  ADMIN_ROLE), `orchestrator` (granted ORCHESTRATOR_ROLE), `alice`/`bob`
  (users), `attacker`.
- Cover EVERY numbered case in the contract's behavioral spec; where a case's
  mechanics map onto the implementation only loosely, state the intent being
  tested in a comment.
- Use `vm.expectRevert(abi.encodeWithSelector(X.SomeError.selector, ...))` for
  error assertions and `vm.expectEmit` for event assertions on the money paths.
