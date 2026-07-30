// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";

/// @title PyraAdmin — Lampyra access-control registry
/// @notice Single source of truth for access control across the Lampyra protocol.
/// Three tiers:
///  - Super admin: the sole `DEFAULT_ADMIN_ROLE` holder (lives on a Safe). Transfers
///    only via OZ's two-step, optionally delayed `beginDefaultAdminTransfer` /
///    `acceptDefaultAdminTransfer` flow. Implicitly an admin in every read path and
///    therefore never a member of `ADMIN_ROLE`.
///  - Ops admins: `ADMIN_ROLE`. Granted/revoked by the super admin only;
///    self-renounceable via `renounceRole`.
///  - Orchestrators: `ORCHESTRATOR_ROLE`, least-privilege hot keys (multi-wallet by
///    design). Orchestrators are NOT admins — they only pass `isAdminOrOrchestrator`.
///    Role membership is independent: an admin or the super admin may also hold it.
/// Satellite contracts store this contract's address and gate with `hasRole`.
/// Not upgradeable; deployed once with a plain constructor.
/// @dev Deliberate behaviours, all load-bearing:
///  - Duplicate grants and missing revokes REVERT (strict) rather than no-op — the
///    off-chain admin console relies on those reverts, so OZ's default idempotent
///    no-ops are overridden away for `ADMIN_ROLE` / `ORCHESTRATOR_ROLE`.
///  - Timestamps are `block.timestamp` SECONDS, never milliseconds; indexers must
///    not assume ms.
///  - Orchestrators may self-renounce — privilege-reducing, so it is allowed.
///  - Enumeration order of role members is not insertion order (swap-and-pop).
contract PyraAdmin is AccessControlEnumerable, AccessControlDefaultAdminRules {
    /// @notice Ops-admin role. Administered by `DEFAULT_ADMIN_ROLE`.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice Orchestrator hot-key role (multi-wallet). Administered by `DEFAULT_ADMIN_ROLE`.
    bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    /// @dev Grant metadata, recorded solely to back `getAdminInfo`.
    struct AdminInfo {
        uint64 addedAt; // block.timestamp (seconds) at grant
        address addedBy; // the super admin that granted the role
    }

    mapping(address account => AdminInfo) private _adminInfo;

    /// @dev Target of `grantRole(ADMIN_ROLE, …)` already holds the role, or is the
    /// super admin (implicitly admin — must never be double-registered).
    error AlreadyAdmin(address account);
    /// @dev Target of `revokeRole`/`renounceRole` on `ADMIN_ROLE` does not hold it.
    error NotAdmin(address account);
    /// @dev `revokeRole`/`renounceRole` on `ADMIN_ROLE` aimed at the super admin —
    /// the super admin exits only via the two-step transfer flow.
    error CannotRemoveSuperAdmin();
    /// @dev Target of `grantRole(ORCHESTRATOR_ROLE, …)` already holds the role.
    error AlreadyOrchestrator(address account);
    /// @dev Target of `revokeRole`/`renounceRole` on `ORCHESTRATOR_ROLE` does not hold it.
    error NotOrchestrator(address account);

    /// @param initialDelay Seconds a proposed super-admin transfer must wait before
    /// `acceptDefaultAdminTransfer` succeeds (0 = accept in the next block).
    /// @param initialSuperAdmin Initial `DEFAULT_ADMIN_ROLE` holder; must be nonzero.
    constructor(uint48 initialDelay, address initialSuperAdmin)
        AccessControlDefaultAdminRules(initialDelay, initialSuperAdmin)
    {}

    // ─────────────────────────── Views ───────────────────────────

    /// @notice True for the super admin and any `ADMIN_ROLE` holder. Orchestrators do NOT pass.
    function isAdmin(address account) public view returns (bool) {
        return account == defaultAdmin() || hasRole(ADMIN_ROLE, account);
    }

    /// @notice True only for the current super admin (`DEFAULT_ADMIN_ROLE` holder).
    function isSuperAdmin(address account) external view returns (bool) {
        return account == defaultAdmin();
    }

    /// @notice Pure `ORCHESTRATOR_ROLE` membership; admins and the super admin do NOT implicitly pass.
    function isOrchestrator(address account) external view returns (bool) {
        return hasRole(ORCHESTRATOR_ROLE, account);
    }

    /// @notice Gate for the orchestrator's narrow operational entry points; admins and
    /// the super admin also pass.
    function isAdminOrOrchestrator(address account) external view returns (bool) {
        return isAdmin(account) || hasRole(ORCHESTRATOR_ROLE, account);
    }

    /// @notice The current super admin (alias of `defaultAdmin()`).
    function superAdmin() external view returns (address) {
        return defaultAdmin();
    }

    /// @notice Number of ops admins. Excludes the super admin.
    function adminCount() external view returns (uint256) {
        return getRoleMemberCount(ADMIN_ROLE);
    }

    /// @notice Number of orchestrator hot keys.
    function orchestratorCount() external view returns (uint256) {
        return getRoleMemberCount(ORCHESTRATOR_ROLE);
    }

    /// @notice All orchestrator addresses (off-chain listing; order not guaranteed).
    function orchestrators() external view returns (address[] memory) {
        return getRoleMembers(ORCHESTRATOR_ROLE);
    }

    /// @notice Admin status plus grant metadata. Super admin returns
    /// `(true, 0, address(0))` sentinels; an ops admin returns
    /// `(true, addedAt, addedBy)` with `addedAt` in seconds; anyone else
    /// returns `(false, 0, address(0))`.
    function getAdminInfo(address account)
        external
        view
        returns (bool isAdmin_, uint256 addedAt, address addedBy)
    {
        if (account == defaultAdmin()) {
            return (true, 0, address(0));
        }
        if (hasRole(ADMIN_ROLE, account)) {
            AdminInfo storage info = _adminInfo[account];
            return (true, info.addedAt, info.addedBy);
        }
        return (false, 0, address(0));
    }

    // ─────────────────────────── Overrides ───────────────────────────

    /// @dev Diamond resolution between the two OZ extensions. Defers to
    /// `AccessControlDefaultAdminRules` (last in C3 order), which enforces its
    /// `DEFAULT_ADMIN_ROLE` restrictions before reaching plain `AccessControl`.
    function grantRole(bytes32 role, address account)
        public
        override(AccessControl, AccessControlDefaultAdminRules, IAccessControl)
    {
        super.grantRole(role, account);
    }

    /// @dev See {grantRole} — diamond resolution only.
    function revokeRole(bytes32 role, address account)
        public
        override(AccessControl, AccessControlDefaultAdminRules, IAccessControl)
    {
        super.revokeRole(role, account);
    }

    /// @dev See {grantRole} — diamond resolution only.
    function renounceRole(bytes32 role, address account)
        public
        override(AccessControl, AccessControlDefaultAdminRules, IAccessControl)
    {
        super.renounceRole(role, account);
    }

    /// @dev See {grantRole} — diamond resolution only.
    function _setRoleAdmin(bytes32 role, bytes32 adminRole)
        internal
        override(AccessControl, AccessControlDefaultAdminRules)
    {
        super._setRoleAdmin(role, adminRole);
    }

    /// @dev Strict grants: a duplicate `ADMIN_ROLE`/`ORCHESTRATOR_ROLE` grant reverts,
    /// and the super admin can never be registered as an ops admin (implicitly admin
    /// already). Records `AdminInfo` grant metadata for ops admins.
    function _grantRole(bytes32 role, address account)
        internal
        override(AccessControlEnumerable, AccessControlDefaultAdminRules)
        returns (bool)
    {
        if (role == ADMIN_ROLE) {
            if (account == defaultAdmin() || hasRole(ADMIN_ROLE, account)) {
                revert AlreadyAdmin(account);
            }
            _adminInfo[account] = AdminInfo({addedAt: uint64(block.timestamp), addedBy: _msgSender()});
        } else if (role == ORCHESTRATOR_ROLE) {
            if (hasRole(ORCHESTRATOR_ROLE, account)) {
                revert AlreadyOrchestrator(account);
            }
        }
        return super._grantRole(role, account);
    }

    /// @dev Strict revokes: revoking a role the account does not hold reverts, and
    /// `ADMIN_ROLE` can never be revoked "from" the super admin (they are not a member;
    /// the check ordering — CannotRemoveSuperAdmin before NotAdmin — is deliberate, and
    /// callers depend on it). Clears `AdminInfo` on ops-admin revocation.
    function _revokeRole(bytes32 role, address account)
        internal
        override(AccessControlEnumerable, AccessControlDefaultAdminRules)
        returns (bool)
    {
        if (role == ADMIN_ROLE) {
            if (account == defaultAdmin()) {
                revert CannotRemoveSuperAdmin();
            }
            if (!hasRole(ADMIN_ROLE, account)) {
                revert NotAdmin(account);
            }
            delete _adminInfo[account];
        } else if (role == ORCHESTRATOR_ROLE) {
            if (!hasRole(ORCHESTRATOR_ROLE, account)) {
                revert NotOrchestrator(account);
            }
        }
        return super._revokeRole(role, account);
    }

    /// @dev An acceptor who already holds `ADMIN_ROLE` must leave the ops-admin table
    /// when they become super admin (implicitly admin from then on): revoke
    /// `ADMIN_ROLE` before the hand-off, which also clears their `AdminInfo` (the
    /// sentinels apply afterwards) and keeps `getRoleMemberCount(ADMIN_ROLE)` honest.
    /// Runs before `super` so the strict-revoke super-admin check sees the OLD admin;
    /// if the schedule has not passed, `super` reverts and the revoke rolls back.
    function _acceptDefaultAdminTransfer() internal override {
        (address newAdmin,) = pendingDefaultAdmin();
        if (hasRole(ADMIN_ROLE, newAdmin)) {
            _revokeRole(ADMIN_ROLE, newAdmin);
        }
        super._acceptDefaultAdminTransfer();
    }

    /// @notice ERC165 support across both inherited extensions.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControlEnumerable, AccessControlDefaultAdminRules)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
