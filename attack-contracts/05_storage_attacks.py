# {"Depends": "py-genlayer:test"}
"""
ATTACK VECTOR 5: Storage & State Manipulation
===============================================
Target: TreeMap, DynArray, storage slots, state consistency

Threat Model:
  Attacker exploits storage patterns to corrupt state, exhaust storage,
  or create inconsistencies that benefit them financially.

Scenarios:
  A) Storage exhaustion (unbounded growth)
  B) State inconsistency via partial updates (no atomicity)
  C) Storage slot collision
  D) Reentrancy via cross-contract state manipulation
  E) Front-running state-dependent operations
"""

from genlayer import *


# ============================================================================
# ATTACK A: Storage Exhaustion (Unbounded Growth)
# ============================================================================
class StorageExhaustionVulnerable(gl.Contract):
    """
    Contract allows unlimited storage growth, enabling a DoS attack
    where an attacker fills storage until the contract becomes unusable
    or too expensive to interact with.
    """
    messages: DynArray[str]
    user_data: TreeMap[Address, DynArray[str]]

    def __init__(self):
        pass

    @gl.public.write
    def post_message(self, message: str):
        # VULNERABILITY: No limit on message count or size
        self.messages.append(message)

    @gl.public.write
    def add_user_data(self, data: str):
        sender = gl.message.sender_address
        if sender not in self.user_data:
            self.user_data[sender] = DynArray[str]()
        # VULNERABILITY: Unbounded per-user storage
        self.user_data[sender].append(data)

    @gl.public.view
    def get_all_messages(self) -> str:
        # VULNERABILITY: Tries to read entire array - will fail/timeout with large data
        return str(list(self.messages))


class StorageBoundedContract(gl.Contract):
    """
    Defense: Strict bounds on all storage collections.
    """
    messages: DynArray[str]
    message_count: u256
    user_data: TreeMap[Address, DynArray[str]]
    user_data_counts: TreeMap[Address, u256]

    MAX_MESSAGES: u256
    MAX_MESSAGE_LENGTH: u256
    MAX_USER_DATA: u256

    def __init__(self):
        self.message_count = u256(0)
        self.MAX_MESSAGES = u256(10000)
        self.MAX_MESSAGE_LENGTH = u256(500)
        self.MAX_USER_DATA = u256(100)

    @gl.public.write
    def post_message(self, message: str):
        # Defense 1: Global message limit
        if self.message_count >= self.MAX_MESSAGES:
            raise gl.vm.UserError("Message storage full")

        # Defense 2: Individual message size limit
        if len(message) > int(self.MAX_MESSAGE_LENGTH):
            raise gl.vm.UserError("Message too long")

        self.messages.append(message)
        self.message_count += u256(1)

    @gl.public.write
    def add_user_data(self, data: str):
        sender = gl.message.sender_address
        count = self.user_data_counts.get(sender, u256(0))

        # Defense 3: Per-user storage limit
        if count >= self.MAX_USER_DATA:
            raise gl.vm.UserError("User storage limit reached")

        if sender not in self.user_data:
            self.user_data[sender] = DynArray[str]()
        self.user_data[sender].append(data)
        self.user_data_counts[sender] = count + u256(1)

    @gl.public.view
    def get_messages_paginated(self, offset: u256, limit: u256) -> str:
        """Defense 4: Pagination for reads."""
        if limit > u256(50):
            limit = u256(50)  # Cap page size

        results = []
        start = int(offset)
        end = min(start + int(limit), len(self.messages))
        for i in range(start, end):
            results.append(self.messages[i])
        return str(results)


# ============================================================================
# ATTACK B: State Inconsistency via Partial Updates
# ============================================================================
class InconsistentStateVulnerable(gl.Contract):
    """
    Contract performs multi-step state updates that can leave state
    inconsistent if an error occurs mid-update.

    Attack: Trigger an error after the first state change but before
    the second, leaving balances inconsistent.
    """
    balances: TreeMap[Address, u256]
    total_supply: u256

    def __init__(self, initial_supply: u256):
        self.total_supply = initial_supply
        self.balances[gl.message.sender_address] = initial_supply

    @gl.public.write
    def transfer(self, to: Address, amount: u256):
        sender = gl.message.sender_address
        sender_balance = self.balances.get(sender, u256(0))

        if sender_balance < amount:
            raise gl.vm.UserError("Insufficient balance")

        # Step 1: Deduct from sender
        self.balances[sender] = sender_balance - amount

        # VULNERABILITY: If an error occurs here (e.g., due to a malicious
        # `to` address triggering a callback that reverts), the sender's
        # balance is already reduced but the recipient hasn't received tokens.
        # NOTE: GenVM should handle this with transaction atomicity,
        # but this tests that assumption.

        # Step 2: Credit to recipient
        recipient_balance = self.balances.get(to, u256(0))
        self.balances[to] = recipient_balance + amount


class ConsistentStateContract(gl.Contract):
    """
    Defense: Checks-Effects-Interactions pattern adapted for GenLayer.
    All checks first, then all state changes, then any external calls.
    """
    balances: TreeMap[Address, u256]
    total_supply: u256

    def __init__(self, initial_supply: u256):
        self.total_supply = initial_supply
        self.balances[gl.message.sender_address] = initial_supply

    @gl.public.write
    def transfer(self, to: Address, amount: u256):
        sender = gl.message.sender_address

        # CHECKS (all validation first)
        if to == Address("0x0000000000000000000000000000000000000000"):
            raise gl.vm.UserError("Cannot transfer to zero address")
        if amount == u256(0):
            raise gl.vm.UserError("Amount must be > 0")

        sender_balance = self.balances.get(sender, u256(0))
        if sender_balance < amount:
            raise gl.vm.UserError("Insufficient balance")

        recipient_balance = self.balances.get(to, u256(0))
        new_recipient_balance = recipient_balance + amount
        if new_recipient_balance < recipient_balance:
            raise gl.vm.UserError("Overflow")

        # EFFECTS (all state changes together)
        self.balances[sender] = sender_balance - amount
        self.balances[to] = new_recipient_balance

        # INTERACTIONS (external calls last - none in this case)


# ============================================================================
# ATTACK C: Reentrancy via Cross-Contract Calls
# ============================================================================
class ReentrancyVulnerable(gl.Contract):
    """
    Classic reentrancy: external call before state update.

    Attack flow:
    1. Attacker deposits 1 token
    2. Attacker calls withdraw(1)
    3. Before balance is updated, the transfer triggers attacker's
       __receive__ which calls withdraw(1) again
    4. Attacker drains the contract
    """
    balances: TreeMap[Address, u256]

    def __init__(self):
        pass

    @gl.public.write
    @gl.public.payable
    def deposit(self):
        sender = gl.message.sender_address
        current = self.balances.get(sender, u256(0))
        self.balances[sender] = current + gl.message.value

    @gl.public.write
    def withdraw(self, amount: u256):
        sender = gl.message.sender_address
        balance = self.balances.get(sender, u256(0))

        if balance < amount:
            raise gl.vm.UserError("Insufficient balance")

        # VULNERABILITY: External call before state update
        # If sender is a contract with __receive__, it can re-enter
        # gl.transfer(sender, amount)  # hypothetical transfer call

        # State update happens AFTER external call
        self.balances[sender] = balance - amount


class ReentrancyGuarded(gl.Contract):
    """
    Defense: Reentrancy guard + checks-effects-interactions.
    """
    balances: TreeMap[Address, u256]
    _locked: bool

    def __init__(self):
        self._locked = False

    def _reentrancy_guard_enter(self):
        if self._locked:
            raise gl.vm.UserError("Reentrant call detected")
        self._locked = True

    def _reentrancy_guard_exit(self):
        self._locked = False

    @gl.public.write
    @gl.public.payable
    def deposit(self):
        self._reentrancy_guard_enter()

        sender = gl.message.sender_address
        current = self.balances.get(sender, u256(0))
        self.balances[sender] = current + gl.message.value

        self._reentrancy_guard_exit()

    @gl.public.write
    def withdraw(self, amount: u256):
        self._reentrancy_guard_enter()

        sender = gl.message.sender_address
        balance = self.balances.get(sender, u256(0))

        if balance < amount:
            self._reentrancy_guard_exit()
            raise gl.vm.UserError("Insufficient balance")

        # EFFECTS first (update state before external call)
        self.balances[sender] = balance - amount

        # INTERACTIONS last
        # gl.transfer(sender, amount)

        self._reentrancy_guard_exit()


# ============================================================================
# ATTACK D: Front-Running State-Dependent Operations
# ============================================================================
class FrontRunVulnerable(gl.Contract):
    """
    A DEX-like contract where swap price depends on current state.

    Attack: Attacker sees a large swap in the mempool, submits their
    own swap first (front-run) to move the price, then the victim's
    swap executes at a worse price, and the attacker sells (back-run).

    This is the classic "sandwich attack" applied to GenLayer.
    """
    reserve_a: u256
    reserve_b: u256

    def __init__(self, initial_a: u256, initial_b: u256):
        self.reserve_a = initial_a
        self.reserve_b = initial_b

    @gl.public.write
    def swap_a_for_b(self, amount_a: u256) -> u256:
        # Constant product AMM: x * y = k
        # VULNERABILITY: No slippage protection
        k = self.reserve_a * self.reserve_b
        new_reserve_a = self.reserve_a + amount_a
        new_reserve_b = k // new_reserve_a
        amount_b_out = self.reserve_b - new_reserve_b

        self.reserve_a = new_reserve_a
        self.reserve_b = new_reserve_b
        return amount_b_out


class FrontRunProtected(gl.Contract):
    """
    Defense: Slippage protection, commit-reveal scheme, or batch auctions.
    """
    reserve_a: u256
    reserve_b: u256

    def __init__(self, initial_a: u256, initial_b: u256):
        self.reserve_a = initial_a
        self.reserve_b = initial_b

    @gl.public.write
    def swap_a_for_b(self, amount_a: u256, min_amount_b_out: u256) -> u256:
        """Defense: User specifies minimum acceptable output (slippage protection)."""
        k = self.reserve_a * self.reserve_b
        new_reserve_a = self.reserve_a + amount_a
        new_reserve_b = k // new_reserve_a
        amount_b_out = self.reserve_b - new_reserve_b

        # Defense: Revert if output is worse than user's minimum
        if amount_b_out < min_amount_b_out:
            raise gl.vm.UserError(
                f"Slippage exceeded: got {amount_b_out}, minimum was {min_amount_b_out}"
            )

        self.reserve_a = new_reserve_a
        self.reserve_b = new_reserve_b
        return amount_b_out
