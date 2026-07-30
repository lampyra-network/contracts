// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IAccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {PyraAdmin} from "../src/PyraAdmin.sol";

/// @notice Full behavioural suite for the admin registry: deployment / super admin,
/// ops-admin management, the two-step super-admin transfer and orchestrator roles,
/// plus the spec checklist extras (re-propose overwrite, cancel-with-no-pending,
/// self-transfer no-op, accept-clears-ADMIN_ROLE member count) and the deployment /
/// access-control edge cases (constructor zero-address guard, direct
/// DEFAULT_ADMIN_ROLE grant/revoke blocked, unauthorized-caller revert for every
/// gated function, nonzero-delay enforcement).
/// PyraAdmin is NOT a proxy: there is no initializer to re-run and no upgrade path
/// to gate — the constructor + absent UUPS surface stand in for the usual re-init
/// and upgrade-authorization cases.
/// Note on delay-0: OZ's schedule check is strictly `schedule < block.timestamp`,
/// so even with `initialDelay = 0` acceptance needs the NEXT second — tests warp +1s.
contract PyraAdminTest is Test {
    PyraAdmin internal registry;

    address internal superAdmin;
    address internal opsAdmin;
    address internal orchestrator;
    address internal alice;
    address internal bob;
    address internal attacker;

    bytes32 internal DEFAULT_ADMIN_ROLE;
    bytes32 internal ADMIN_ROLE;
    bytes32 internal ORCHESTRATOR_ROLE;

    function setUp() public {
        superAdmin = makeAddr("superAdmin");
        opsAdmin = makeAddr("opsAdmin");
        orchestrator = makeAddr("orchestrator");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attacker = makeAddr("attacker");

        registry = new PyraAdmin(0, superAdmin);
        DEFAULT_ADMIN_ROLE = registry.DEFAULT_ADMIN_ROLE();
        ADMIN_ROLE = registry.ADMIN_ROLE();
        ORCHESTRATOR_ROLE = registry.ORCHESTRATOR_ROLE();
    }

    // ─────────────────────────── Helpers ───────────────────────────

    function _grantAdmin(address account) internal {
        vm.prank(superAdmin);
        registry.grantRole(ADMIN_ROLE, account);
    }

    function _grantOrchestrator(address account) internal {
        vm.prank(superAdmin);
        registry.grantRole(ORCHESTRATOR_ROLE, account);
    }

    /// @dev Full two-step transfer with the delay-0 registry (+1s warp — see header).
    function _transferSuperAdminTo(address to) internal {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(to);
        vm.warp(block.timestamp + 1);
        vm.prank(to);
        registry.acceptDefaultAdminTransfer();
    }

    function _unauthorized(address account) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            IAccessControl.AccessControlUnauthorizedAccount.selector, account, DEFAULT_ADMIN_ROLE
        );
    }

    // ─────────────── Deployment / super admin ───────────────

    /// Deployment seats the constructor-supplied address as super admin.
    function test_DeploySetsInitialSuperAdmin() public view {
        assertTrue(registry.isSuperAdmin(superAdmin));
        assertTrue(registry.isAdmin(superAdmin)); // implicitly admin
        assertEq(registry.adminCount(), 0); // super admin not in the ops-admin set
        assertFalse(registry.isAdmin(alice));
        assertFalse(registry.isSuperAdmin(alice));
        assertEq(registry.superAdmin(), superAdmin);
        assertEq(registry.defaultAdmin(), superAdmin);
        assertEq(registry.owner(), superAdmin); // ERC5313
    }

    /// getAdminInfo for the super admin returns sentinels.
    function test_GetAdminInfoForSuperAdminReturnsSentinels() public view {
        (bool isAdmin_, uint256 addedAt, address addedBy) = registry.getAdminInfo(superAdmin);
        assertTrue(isAdmin_);
        assertEq(addedAt, 0);
        assertEq(addedBy, address(0));
    }

    // ─────────────── Ops-admin management ───────────────

    /// Super admin can add an admin. (Grants deliberately carry no human-readable
    /// label — it would be write-only state, never readable on-chain.)
    function test_SuperAdminCanAddAdmin() public {
        vm.warp(1000); // addedAt is a unix timestamp in seconds
        _grantAdmin(opsAdmin);

        assertTrue(registry.isAdmin(opsAdmin));
        assertFalse(registry.isSuperAdmin(opsAdmin));
        assertEq(registry.adminCount(), 1);

        (bool isAdmin_, uint256 addedAt, address addedBy) = registry.getAdminInfo(opsAdmin);
        assertTrue(isAdmin_);
        assertEq(addedAt, 1000);
        assertEq(addedBy, superAdmin);
    }

    /// Cannot add a duplicate admin.
    function test_RevertWhen_AddingDuplicateAdmin() public {
        _grantAdmin(opsAdmin);
        vm.prank(superAdmin);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.AlreadyAdmin.selector, opsAdmin));
        registry.grantRole(ADMIN_ROLE, opsAdmin);
    }

    /// Cannot add the super admin as a regular admin (implicitly admin already).
    function test_RevertWhen_AddingSuperAdminAsRegularAdmin() public {
        vm.prank(superAdmin);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.AlreadyAdmin.selector, superAdmin));
        registry.grantRole(ADMIN_ROLE, superAdmin);
    }

    /// Super admin can remove an admin; info is cleared.
    function test_SuperAdminCanRemoveAdmin() public {
        _grantAdmin(opsAdmin);
        vm.prank(superAdmin);
        registry.revokeRole(ADMIN_ROLE, opsAdmin);

        assertFalse(registry.isAdmin(opsAdmin));
        assertEq(registry.adminCount(), 0);
        (bool isAdmin_, uint256 addedAt, address addedBy) = registry.getAdminInfo(opsAdmin);
        assertFalse(isAdmin_);
        assertEq(addedAt, 0);
        assertEq(addedBy, address(0));
    }

    /// Cannot remove a non-existent admin.
    function test_RevertWhen_RemovingNonExistentAdmin() public {
        vm.prank(superAdmin);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.NotAdmin.selector, alice));
        registry.revokeRole(ADMIN_ROLE, alice);
    }

    /// The super admin cannot remove itself (must use the transfer flow).
    function test_RevertWhen_SuperAdminRemovesSelf() public {
        vm.prank(superAdmin);
        vm.expectRevert(PyraAdmin.CannotRemoveSuperAdmin.selector);
        registry.revokeRole(ADMIN_ROLE, superAdmin);
    }

    /// A regular admin can renounce their own role.
    function test_RegularAdminCanRenounce() public {
        _grantAdmin(opsAdmin);
        vm.prank(opsAdmin);
        registry.renounceRole(ADMIN_ROLE, opsAdmin);
        assertFalse(registry.isAdmin(opsAdmin));
        assertEq(registry.adminCount(), 0);
    }

    /// The super admin cannot renounce — must transfer first.
    function test_RevertWhen_SuperAdminRenounces() public {
        // ADMIN_ROLE renounce: blocked with the dedicated CannotRemoveSuperAdmin error.
        vm.prank(superAdmin);
        vm.expectRevert(PyraAdmin.CannotRemoveSuperAdmin.selector);
        registry.renounceRole(ADMIN_ROLE, superAdmin);

        // DEFAULT_ADMIN_ROLE renounce outside a scheduled two-step-to-zero: blocked by OZ.
        vm.prank(superAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, uint48(0)
            )
        );
        registry.renounceRole(DEFAULT_ADMIN_ROLE, superAdmin);
    }

    /// A nobody cannot add an admin.
    function test_RevertWhen_NonAdminAddsAdmin() public {
        vm.prank(alice);
        vm.expectRevert(_unauthorized(alice));
        registry.grantRole(ADMIN_ROLE, bob);
    }

    /// A nobody cannot remove an admin.
    function test_RevertWhen_NonAdminRemovesAdmin() public {
        _grantAdmin(opsAdmin);
        vm.prank(bob);
        vm.expectRevert(_unauthorized(bob));
        registry.revokeRole(ADMIN_ROLE, opsAdmin);
    }

    /// A regular admin cannot add another admin (super-admin only).
    function test_RevertWhen_RegularAdminAddsAdmin() public {
        _grantAdmin(opsAdmin);
        vm.prank(opsAdmin);
        vm.expectRevert(_unauthorized(opsAdmin));
        registry.grantRole(ADMIN_ROLE, bob);
    }

    /// A regular admin cannot remove a fellow admin.
    function test_RevertWhen_RegularAdminRemovesAdmin() public {
        _grantAdmin(opsAdmin);
        _grantAdmin(alice);
        vm.prank(opsAdmin);
        vm.expectRevert(_unauthorized(opsAdmin));
        registry.revokeRole(ADMIN_ROLE, alice);
    }

    /// isAdmin is true for both tiers, isSuperAdmin only for the top.
    function test_IsAdminTrueForBothTiers() public {
        _grantAdmin(opsAdmin);
        assertTrue(registry.isAdmin(superAdmin));
        assertTrue(registry.isAdmin(opsAdmin));
        assertFalse(registry.isAdmin(bob));
        assertTrue(registry.isSuperAdmin(superAdmin));
        assertFalse(registry.isSuperAdmin(opsAdmin));
    }

    /// A nobody cannot renounce the admin role.
    function test_RevertWhen_NonAdminRenounces() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.NotAdmin.selector, alice));
        registry.renounceRole(ADMIN_ROLE, alice);
    }

    /// getAdminInfo for a non-admin.
    function test_GetAdminInfoForNonAdmin() public view {
        (bool isAdmin_, uint256 addedAt, address addedBy) = registry.getAdminInfo(alice);
        assertFalse(isAdmin_);
        assertEq(addedAt, 0);
        assertEq(addedBy, address(0));
    }

    /// Add and remove multiple admins; counts track.
    function test_AddAndRemoveMultipleAdmins() public {
        _grantAdmin(opsAdmin);
        _grantAdmin(alice);
        assertEq(registry.adminCount(), 2);

        vm.prank(superAdmin);
        registry.revokeRole(ADMIN_ROLE, opsAdmin);
        assertEq(registry.adminCount(), 1);
        assertTrue(registry.isAdmin(alice));
        assertFalse(registry.isAdmin(opsAdmin));
    }

    // ─────────────── Two-step super-admin transfer ───────────────

    /// Two-step transfer; old super admin ends with no role at all.
    function test_TwoStepSuperAdminTransfer() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);

        // Proposal alone changes nothing.
        assertTrue(registry.isSuperAdmin(superAdmin));
        assertFalse(registry.isSuperAdmin(alice));
        (address pending,) = registry.pendingDefaultAdmin();
        assertEq(pending, alice);

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        registry.acceptDefaultAdminTransfer();

        assertTrue(registry.isSuperAdmin(alice));
        assertTrue(registry.isAdmin(alice));
        assertFalse(registry.isSuperAdmin(superAdmin));
        assertFalse(registry.isAdmin(superAdmin)); // old super admin holds nothing
        (bool wasAdmin,,) = registry.getAdminInfo(superAdmin);
        assertFalse(wasAdmin);
    }

    /// Cancel clears the pending transfer.
    function test_CancelSuperAdminTransfer() public {
        vm.startPrank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);
        registry.cancelDefaultAdminTransfer();
        vm.stopPrank();

        assertTrue(registry.isSuperAdmin(superAdmin));
        assertFalse(registry.isSuperAdmin(alice));
        assertFalse(registry.isAdmin(alice));
        (address pending,) = registry.pendingDefaultAdmin();
        assertEq(pending, address(0));
    }

    /// Accept fails after cancel.
    function test_RevertWhen_AcceptingAfterCancel() public {
        vm.startPrank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);
        registry.cancelDefaultAdminTransfer();
        vm.stopPrank();

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, alice
            )
        );
        registry.acceptDefaultAdminTransfer();
    }

    /// Accepting the super-admin transfer strips the acceptor's ADMIN_ROLE (implicitly
    /// admin from then on) and drops their info.
    function test_AcceptSuperAdminClearsAdminRole() public {
        _grantAdmin(opsAdmin);
        assertEq(registry.adminCount(), 1);

        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(opsAdmin);
        vm.warp(block.timestamp + 1);
        vm.prank(opsAdmin);
        registry.acceptDefaultAdminTransfer();

        assertTrue(registry.isSuperAdmin(opsAdmin));
        assertEq(registry.adminCount(), 0);
        assertEq(registry.getRoleMemberCount(ADMIN_ROLE), 0);
        assertFalse(registry.hasRole(ADMIN_ROLE, opsAdmin));
        assertTrue(registry.isAdmin(opsAdmin)); // implicitly, as super admin

        (bool isAdmin_, uint256 addedAt, address addedBy) = registry.getAdminInfo(opsAdmin);
        assertTrue(isAdmin_); // sentinels — old grant metadata dropped
        assertEq(addedAt, 0);
        assertEq(addedBy, address(0));
    }

    /// A nobody cannot propose a super-admin transfer.
    function test_RevertWhen_NonAdminProposesSuperAdmin() public {
        vm.prank(alice);
        vm.expectRevert(_unauthorized(alice));
        registry.beginDefaultAdminTransfer(bob);
    }

    /// Only the proposed address can accept.
    function test_RevertWhen_WrongAddressAccepts() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);
        vm.warp(block.timestamp + 1);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, bob
            )
        );
        registry.acceptDefaultAdminTransfer();
    }

    /// Accept without any proposal fails.
    function test_RevertWhen_AcceptingWithoutProposal() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, alice
            )
        );
        registry.acceptDefaultAdminTransfer();
    }

    /// A nobody cannot cancel a pending transfer.
    function test_RevertWhen_NonAdminCancelsTransfer() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);

        vm.prank(bob);
        vm.expectRevert(_unauthorized(bob));
        registry.cancelDefaultAdminTransfer();
    }

    /// The new super admin can manage admins.
    function test_NewSuperAdminCanManageAdmins() public {
        _transferSuperAdminTo(alice);

        vm.prank(alice);
        registry.grantRole(ADMIN_ROLE, bob);
        assertTrue(registry.isAdmin(bob));
        assertEq(registry.adminCount(), 1);
    }

    /// The old super admin loses all powers after transfer.
    function test_RevertWhen_OldSuperAdminAddsAfterTransfer() public {
        _transferSuperAdminTo(alice);

        vm.prank(superAdmin);
        vm.expectRevert(_unauthorized(superAdmin));
        registry.grantRole(ADMIN_ROLE, bob);
    }

    // ─────────────── Orchestrators ───────────────

    /// Super admin can add an orchestrator; role is NOT admin.
    function test_SuperAdminCanAddOrchestrator() public {
        _grantOrchestrator(orchestrator);

        assertTrue(registry.isOrchestrator(orchestrator));
        assertTrue(registry.isAdminOrOrchestrator(orchestrator));
        assertFalse(registry.isAdmin(orchestrator));
        assertFalse(registry.isSuperAdmin(orchestrator));
        assertEq(registry.orchestratorCount(), 1);
    }

    /// Super admin can remove an orchestrator.
    function test_SuperAdminCanRemoveOrchestrator() public {
        _grantOrchestrator(orchestrator);
        vm.prank(superAdmin);
        registry.revokeRole(ORCHESTRATOR_ROLE, orchestrator);

        assertFalse(registry.isOrchestrator(orchestrator));
        assertFalse(registry.isAdminOrOrchestrator(orchestrator));
        assertEq(registry.orchestratorCount(), 0);
    }

    /// Cannot add a duplicate orchestrator.
    function test_RevertWhen_AddingDuplicateOrchestrator() public {
        _grantOrchestrator(orchestrator);
        vm.prank(superAdmin);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.AlreadyOrchestrator.selector, orchestrator));
        registry.grantRole(ORCHESTRATOR_ROLE, orchestrator);
    }

    /// Cannot remove a non-existent orchestrator.
    function test_RevertWhen_RemovingNonexistentOrchestrator() public {
        vm.prank(superAdmin);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.NotOrchestrator.selector, orchestrator));
        registry.revokeRole(ORCHESTRATOR_ROLE, orchestrator);
    }

    /// A regular admin cannot add an orchestrator (super-admin only).
    function test_RevertWhen_RegularAdminAddsOrchestrator() public {
        _grantAdmin(opsAdmin);
        vm.prank(opsAdmin);
        vm.expectRevert(_unauthorized(opsAdmin));
        registry.grantRole(ORCHESTRATOR_ROLE, bob);
    }

    /// A nobody cannot add an orchestrator.
    function test_RevertWhen_NonAdminAddsOrchestrator() public {
        vm.prank(alice);
        vm.expectRevert(_unauthorized(alice));
        registry.grantRole(ORCHESTRATOR_ROLE, bob);
    }

    /// Admins pass isAdminOrOrchestrator without being orchestrators.
    function test_AdminsPassAdminOrOrchestratorWithoutBeingOrchestrators() public {
        _grantAdmin(opsAdmin);

        assertTrue(registry.isAdminOrOrchestrator(superAdmin));
        assertTrue(registry.isAdminOrOrchestrator(opsAdmin));
        assertFalse(registry.isOrchestrator(superAdmin));
        assertFalse(registry.isOrchestrator(opsAdmin));
        assertFalse(registry.isAdminOrOrchestrator(bob));
        assertFalse(registry.isOrchestrator(bob));
    }

    /// Orchestrator list + count. (Enumeration order is not guaranteed — assert
    /// membership, not order.)
    function test_OrchestratorsListAndCount() public {
        _grantOrchestrator(alice);
        _grantOrchestrator(bob);

        assertEq(registry.orchestratorCount(), 2);
        address[] memory list = registry.orchestrators();
        assertEq(list.length, 2);
        assertTrue(list[0] == alice || list[1] == alice);
        assertTrue(list[0] == bob || list[1] == bob);
    }

    /// Roles are independent — the super admin may also be an orchestrator.
    function test_OrchestratorCanAlsoBeSuperAdmin() public {
        _grantOrchestrator(superAdmin);

        assertTrue(registry.isOrchestrator(superAdmin));
        assertTrue(registry.isSuperAdmin(superAdmin));
        assertTrue(registry.isAdminOrOrchestrator(superAdmin));
    }

    // ─────────────── Spec checklist (code-defined behaviours) ───────────────

    /// Re-proposing overwrites the pending transfer (no error).
    function test_ReproposeOverwritesPending() public {
        vm.startPrank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);
        registry.beginDefaultAdminTransfer(bob);
        vm.stopPrank();

        (address pending,) = registry.pendingDefaultAdmin();
        assertEq(pending, bob);

        vm.warp(block.timestamp + 1);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, alice
            )
        );
        registry.acceptDefaultAdminTransfer();

        vm.prank(bob);
        registry.acceptDefaultAdminTransfer();
        assertTrue(registry.isSuperAdmin(bob));
    }

    /// Cancel with no pending transfer succeeds silently (idempotent — OZ v5's cancel
    /// does not revert when nothing is pending).
    function test_CancelWithNoPendingTransferSucceeds() public {
        vm.prank(superAdmin);
        registry.cancelDefaultAdminTransfer();
        assertTrue(registry.isSuperAdmin(superAdmin));
    }

    /// Self-transfer is a valid no-op: propose self, accept self.
    function test_SelfTransferIsNoOp() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(superAdmin);
        vm.warp(block.timestamp + 1);
        vm.prank(superAdmin);
        registry.acceptDefaultAdminTransfer();

        assertTrue(registry.isSuperAdmin(superAdmin));
        assertEq(registry.adminCount(), 0);
        (address pending,) = registry.pendingDefaultAdmin();
        assertEq(pending, address(0));
    }

    // ─────────────── Deployment / access-control edge cases ───────────────

    /// Constructor guard: the initial super admin must be nonzero (OZ-native).
    function test_RevertWhen_ConstructorZeroSuperAdmin() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlInvalidDefaultAdmin.selector, address(0)
            )
        );
        new PyraAdmin(0, address(0));
    }

    /// DEFAULT_ADMIN_ROLE can never be granted or revoked directly — two-step flow only.
    function test_RevertWhen_DirectDefaultAdminRoleGrantOrRevoke() public {
        vm.prank(superAdmin);
        vm.expectRevert(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector);
        registry.grantRole(DEFAULT_ADMIN_ROLE, alice);

        vm.prank(superAdmin);
        vm.expectRevert(IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminRules.selector);
        registry.revokeRole(DEFAULT_ADMIN_ROLE, superAdmin);
    }

    /// Both managed roles are administered by DEFAULT_ADMIN_ROLE (OZ default wiring).
    function test_RoleAdminIsDefaultAdminRole() public view {
        assertEq(registry.getRoleAdmin(ADMIN_ROLE), DEFAULT_ADMIN_ROLE);
        assertEq(registry.getRoleAdmin(ORCHESTRATOR_ROLE), DEFAULT_ADMIN_ROLE);
    }

    /// Unauthorized-caller revert for EVERY gated function.
    function test_RevertWhen_AttackerCallsAnyGatedFunction() public {
        _grantAdmin(opsAdmin);
        _grantOrchestrator(orchestrator);

        vm.startPrank(attacker);

        vm.expectRevert(_unauthorized(attacker));
        registry.grantRole(ADMIN_ROLE, attacker);

        vm.expectRevert(_unauthorized(attacker));
        registry.revokeRole(ADMIN_ROLE, opsAdmin);

        vm.expectRevert(_unauthorized(attacker));
        registry.grantRole(ORCHESTRATOR_ROLE, attacker);

        vm.expectRevert(_unauthorized(attacker));
        registry.revokeRole(ORCHESTRATOR_ROLE, orchestrator);

        vm.expectRevert(_unauthorized(attacker));
        registry.beginDefaultAdminTransfer(attacker);

        vm.expectRevert(_unauthorized(attacker));
        registry.cancelDefaultAdminTransfer();

        vm.expectRevert(_unauthorized(attacker));
        registry.changeDefaultAdminDelay(1 days);

        vm.expectRevert(_unauthorized(attacker));
        registry.rollbackDefaultAdminDelay();

        vm.stopPrank();
    }

    /// Orchestrators are least-privilege: they cannot manage any role.
    function test_RevertWhen_OrchestratorManagesRoles() public {
        _grantOrchestrator(orchestrator);

        vm.startPrank(orchestrator);
        vm.expectRevert(_unauthorized(orchestrator));
        registry.grantRole(ADMIN_ROLE, alice);

        vm.expectRevert(_unauthorized(orchestrator));
        registry.grantRole(ORCHESTRATOR_ROLE, alice);
        vm.stopPrank();
    }

    /// A nonzero deploy delay is enforced between propose and accept.
    function test_NonzeroDelayEnforcesWait() public {
        PyraAdmin delayed = new PyraAdmin(1 days, superAdmin);
        uint48 schedule = uint48(block.timestamp + 1 days);

        vm.prank(superAdmin);
        delayed.beginDefaultAdminTransfer(alice);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector, schedule
            )
        );
        delayed.acceptDefaultAdminTransfer();

        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(alice);
        delayed.acceptDefaultAdminTransfer();
        assertTrue(delayed.isSuperAdmin(alice));
    }

    /// Even with delay 0 the schedule is strict — a same-second accept reverts, so
    /// propose and accept can never land on the same timestamp.
    function test_RevertWhen_AcceptingInSameSecondWithZeroDelay() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(alice);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlDefaultAdminRules.AccessControlEnforcedDefaultAdminDelay.selector,
                uint48(block.timestamp)
            )
        );
        registry.acceptDefaultAdminTransfer();
    }

    /// Orchestrator self-renounce is permitted — deliberate, as it only ever reduces
    /// privilege; a non-holder renouncing still reverts.
    function test_OrchestratorCanSelfRenounce() public {
        _grantOrchestrator(orchestrator);
        vm.prank(orchestrator);
        registry.renounceRole(ORCHESTRATOR_ROLE, orchestrator);
        assertFalse(registry.isOrchestrator(orchestrator));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(PyraAdmin.NotOrchestrator.selector, alice));
        registry.renounceRole(ORCHESTRATOR_ROLE, alice);
    }

    /// The super admin can exit entirely via the two-step renounce-to-zero flow,
    /// deliberately leaving the seat permanently empty (OZ-native).
    function test_TwoStepRenounceToZero() public {
        vm.prank(superAdmin);
        registry.beginDefaultAdminTransfer(address(0));
        vm.warp(block.timestamp + 1);
        vm.prank(superAdmin);
        registry.renounceRole(DEFAULT_ADMIN_ROLE, superAdmin);

        assertEq(registry.defaultAdmin(), address(0));
        assertFalse(registry.isSuperAdmin(superAdmin));
    }

    /// The OZ events are the whole observable surface for role changes: RoleGranted on
    /// every admin/orchestrator add, RoleRevoked on every removal, with the sender field
    /// identifying who made the change.
    function test_EventsOnGrantAndRevoke() public {
        vm.prank(superAdmin);
        vm.expectEmit(true, true, true, true, address(registry));
        emit IAccessControl.RoleGranted(ADMIN_ROLE, opsAdmin, superAdmin);
        registry.grantRole(ADMIN_ROLE, opsAdmin);

        vm.prank(superAdmin);
        vm.expectEmit(true, true, true, true, address(registry));
        emit IAccessControl.RoleRevoked(ADMIN_ROLE, opsAdmin, superAdmin);
        registry.revokeRole(ADMIN_ROLE, opsAdmin);

        vm.prank(superAdmin);
        vm.expectEmit(true, true, true, true, address(registry));
        emit IAccessControl.RoleGranted(ORCHESTRATOR_ROLE, orchestrator, superAdmin);
        registry.grantRole(ORCHESTRATOR_ROLE, orchestrator);

        vm.prank(superAdmin);
        vm.expectEmit(true, true, true, true, address(registry));
        emit IAccessControl.RoleRevoked(ORCHESTRATOR_ROLE, orchestrator, superAdmin);
        registry.revokeRole(ORCHESTRATOR_ROLE, orchestrator);
    }
}
