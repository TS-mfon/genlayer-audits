# {"Depends": "py-genlayer:test"}
"""
ATTACK VECTOR 4: Access Control & Method Resolution Bypass
============================================================
Target: GenVM bootloader method resolution, access control patterns, dunder methods

Threat Model:
  Attacker exploits the method resolution logic in GenVM's bootloader
  to call restricted methods, bypass access controls, or trigger
  unintended behavior.

Scenarios:
  A) Calling private methods via edge cases in name resolution
  B) Exploiting __handle_undefined_method__ for unauthorized access
  C) Bypassing owner-only checks via cross-contract calls
  D) Re-initialization attacks (__init__ replay)
  E) Payable method exploitation (sending value to non-payable methods)
  F) Address spoofing via contract-to-contract calls
"""

from genlayer import *


# ============================================================================
# ATTACK A: __handle_undefined_method__ Exploitation
# ============================================================================
class UndefinedMethodVulnerable(gl.Contract):
    """
    If __handle_undefined_method__ is too permissive, attackers can
    invoke arbitrary behavior by calling non-existent methods.
    """
    admin_data: TreeMap[str, str]
    is_initialized: bool

    def __init__(self):
        self.is_initialized = True
        self.admin_data = TreeMap[str, str]()

    def __handle_undefined_method__(self, method_name: str, *args):
        # VULNERABILITY: Overly permissive catch-all
        # Attacker calls contract.admin_reset() which doesn't exist
        # but gets handled here and could trigger unintended logic
        if method_name.startswith("admin_"):
            # Intended for future admin methods, but exposes attack surface
            return f"Admin method {method_name} called"

        if method_name.startswith("get_"):
            # Unintentionally leaks storage data
            key = method_name[4:]  # Strip "get_"
            return self.admin_data.get(key, "not found")

    @gl.public.write
    def set_admin_data(self, key: str, value: str):
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("Owner only")
        self.admin_data[key] = value


class UndefinedMethodHardened(gl.Contract):
    """
    Defense: Never implement __handle_undefined_method__ unless absolutely
    necessary. If needed, use a strict allowlist.
    """
    admin_data: TreeMap[str, str]

    def __init__(self):
        self.admin_data = TreeMap[str, str]()

    # Defense: No __handle_undefined_method__ at all.
    # Unknown method calls will be rejected by the bootloader.

    @gl.public.view
    def get_admin_data(self, key: str) -> str:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("Owner only")
        return self.admin_data.get(key, "")

    @gl.public.write
    def set_admin_data(self, key: str, value: str):
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("Owner only")
        self.admin_data[key] = value


# ============================================================================
# ATTACK B: Cross-Contract Access Control Bypass
# ============================================================================
class VaultContract(gl.Contract):
    """
    A vault that checks msg.sender for access control.

    Vulnerability: If another contract calls this vault, msg.sender
    becomes the calling contract's address, not the original user.
    An attacker can deploy a proxy contract that passes the access check.
    """
    balances: TreeMap[Address, u256]
    authorized: TreeMap[Address, bool]

    def __init__(self):
        self.authorized[gl.message.sender_address] = True

    @gl.public.write
    def deposit(self):
        sender = gl.message.sender_address
        current = self.balances.get(sender, u256(0))
        self.balances[sender] = current + gl.message.value

    @gl.public.write
    def withdraw(self, amount: u256):
        sender = gl.message.sender_address
        # VULNERABILITY: Only checks msg.sender, not tx.origin
        # A malicious contract can be authorized and drain funds
        if not self.authorized.get(sender, False):
            raise gl.vm.UserError("Not authorized")

        balance = self.balances.get(sender, u256(0))
        if balance < amount:
            raise gl.vm.UserError("Insufficient balance")

        self.balances[sender] = balance - amount
        # Transfer amount to sender...


class AttackerProxy(gl.Contract):
    """
    Attacker deploys this contract to bypass VaultContract access controls.

    Step 1: Get AttackerProxy authorized on VaultContract
    Step 2: Users deposit into VaultContract through AttackerProxy
    Step 3: AttackerProxy can withdraw all funds (it's the msg.sender)
    """
    vault_address: Address

    def __init__(self, vault_addr: Address):
        self.vault_address = vault_addr

    @gl.public.write
    def deposit_to_vault(self):
        vault = gl.get_contract_at(self.vault_address)
        # Deposits as AttackerProxy, not as the original user
        vault.emit().deposit()

    @gl.public.write
    def steal_funds(self, amount: u256):
        vault = gl.get_contract_at(self.vault_address)
        vault.emit().withdraw(amount)


class HardenedVault(gl.Contract):
    """
    Defense: Role-based access control with explicit per-user authorization.
    Never rely solely on msg.sender for user-facing operations.
    """
    balances: TreeMap[Address, u256]
    owner: Address
    withdrawal_allowances: TreeMap[Address, TreeMap[Address, u256]]

    def __init__(self):
        self.owner = gl.message.sender_address

    @gl.public.write
    @gl.public.payable
    def deposit(self, beneficiary: Address):
        """Deposits are explicitly tagged with the beneficiary."""
        current = self.balances.get(beneficiary, u256(0))
        self.balances[beneficiary] = current + gl.message.value

    @gl.public.write
    def withdraw(self, amount: u256, beneficiary: Address):
        """
        Withdrawal requires the caller to be the beneficiary themselves,
        or have an explicit allowance from the beneficiary.
        """
        caller = gl.message.sender_address

        if caller != beneficiary:
            # Check allowance
            user_allowances = self.withdrawal_allowances.get(beneficiary, None)
            if user_allowances is None:
                raise gl.vm.UserError("No allowance set")
            allowance = user_allowances.get(caller, u256(0))
            if allowance < amount:
                raise gl.vm.UserError("Allowance exceeded")
            user_allowances[caller] = allowance - amount

        balance = self.balances.get(beneficiary, u256(0))
        if balance < amount:
            raise gl.vm.UserError("Insufficient balance")

        self.balances[beneficiary] = balance - amount


# ============================================================================
# ATTACK C: Re-initialization Attack
# ============================================================================
class ReinitVulnerable(gl.Contract):
    """
    If __init__ can be called more than once (or if the bootloader doesn't
    prevent it), an attacker could re-initialize the contract to reset
    the owner or other critical state.

    NOTE: GenVM bootloader routes __init__ only during deployment, so this
    is protected at the VM level. This scenario tests that assumption.
    """
    owner: Address
    total_supply: u256

    def __init__(self):
        self.owner = gl.message.sender_address
        self.total_supply = u256(1000000)

    @gl.public.write
    def transfer_ownership(self, new_owner: Address):
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("Owner only")
        self.owner = new_owner

    # Test: Can an attacker somehow trigger __init__ again?
    # If the bootloader correctly prevents this, the attack fails.
    # This is a defensive verification test.


# ============================================================================
# ATTACK D: Integer Overflow in Access Control Mapping
# ============================================================================
class OverflowAccessControl(gl.Contract):
    """
    Tests whether GenLayer's integer types properly prevent overflow
    in access control scenarios.
    """
    role_levels: TreeMap[Address, u256]
    ADMIN_LEVEL: u256

    def __init__(self):
        self.ADMIN_LEVEL = u256(100)
        self.role_levels[gl.message.sender_address] = self.ADMIN_LEVEL

    @gl.public.write
    def set_role_level(self, user: Address, level: u256):
        caller_level = self.role_levels.get(gl.message.sender_address, u256(0))
        if caller_level < self.ADMIN_LEVEL:
            raise gl.vm.UserError("Admin only")
        # VULNERABILITY: No upper bound check on level
        # An admin could set level to u256.MAX, which might cause
        # comparison issues elsewhere
        self.role_levels[user] = level

    @gl.public.view
    def check_access(self, user: Address, required_level: u256) -> bool:
        user_level = self.role_levels.get(user, u256(0))
        return user_level >= required_level


class SafeAccessControl(gl.Contract):
    """Defense: Bounded role levels, explicit role enumeration."""
    ROLE_NONE: u256
    ROLE_USER: u256
    ROLE_MODERATOR: u256
    ROLE_ADMIN: u256
    ROLE_OWNER: u256

    roles: TreeMap[Address, u256]
    owner: Address

    def __init__(self):
        self.ROLE_NONE = u256(0)
        self.ROLE_USER = u256(1)
        self.ROLE_MODERATOR = u256(2)
        self.ROLE_ADMIN = u256(3)
        self.ROLE_OWNER = u256(4)

        self.owner = gl.message.sender_address
        self.roles[gl.message.sender_address] = self.ROLE_OWNER

    def _valid_role(self, level: u256) -> bool:
        return level <= self.ROLE_OWNER

    @gl.public.write
    def set_role(self, user: Address, level: u256):
        if not self._valid_role(level):
            raise gl.vm.UserError("Invalid role level")

        caller_role = self.roles.get(gl.message.sender_address, self.ROLE_NONE)
        if caller_role < self.ROLE_ADMIN:
            raise gl.vm.UserError("Admin+ required")
        if level >= caller_role:
            raise gl.vm.UserError("Cannot assign role >= your own")

        self.roles[user] = level
