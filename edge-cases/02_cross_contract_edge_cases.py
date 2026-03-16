# {"Depends": "py-genlayer:test"}
"""
EDGE CASE SUITE 2: Cross-Contract Interaction Edge Cases
==========================================================
Tests boundary conditions in contract-to-contract calls,
contract deployment, and inter-contract state dependencies.
"""

from genlayer import *


# ============================================================================
# EDGE CASE 1: Circular Contract Dependencies
# ============================================================================
class ContractA(gl.Contract):
    """
    Contract A calls Contract B, which calls Contract A back.
    Tests: Does GenVM detect and prevent circular calls?
    Does it handle reentrancy across contracts?
    """
    partner: Address
    call_depth: u256

    def __init__(self, partner_address: Address):
        self.partner = partner_address
        self.call_depth = u256(0)

    @gl.public.write
    def ping(self, depth: u256) -> str:
        self.call_depth = depth

        if depth > u256(0):
            partner_contract = gl.get_contract_at(self.partner)
            result = partner_contract.view().pong(depth - u256(1))
            return f"A:ping({depth})->B:{result}"
        return f"A:ping({depth})->end"


class ContractB(gl.Contract):
    partner: Address
    call_depth: u256

    def __init__(self, partner_address: Address):
        self.partner = partner_address
        self.call_depth = u256(0)

    @gl.public.write
    def pong(self, depth: u256) -> str:
        self.call_depth = depth

        if depth > u256(0):
            partner_contract = gl.get_contract_at(self.partner)
            result = partner_contract.view().ping(depth - u256(1))
            return f"B:pong({depth})->A:{result}"
        return f"B:pong({depth})->end"


# ============================================================================
# EDGE CASE 2: Contract Calling Non-Existent Contract
# ============================================================================
class GhostCaller(gl.Contract):
    """
    Tests behavior when calling a contract address that:
    - Doesn't exist
    - Was destroyed/self-destructed
    - Is an EOA (externally owned account), not a contract
    """

    @gl.public.write
    def call_ghost(self, ghost_address: Address) -> str:
        try:
            ghost = gl.get_contract_at(ghost_address)
            result = ghost.view().some_method()
            return f"UNEXPECTED: Got result from ghost: {result}"
        except Exception as e:
            return f"EXPECTED: Error calling ghost: {type(e).__name__}: {str(e)[:100]}"

    @gl.public.write
    def call_wrong_method(self, target_address: Address) -> str:
        """Call an existing contract but with a method it doesn't have."""
        try:
            target = gl.get_contract_at(target_address)
            result = target.view().this_method_definitely_does_not_exist()
            return f"UNEXPECTED: Got result: {result}"
        except Exception as e:
            return f"EXPECTED: Error: {type(e).__name__}: {str(e)[:100]}"


# ============================================================================
# EDGE CASE 3: Contract Self-Reference
# ============================================================================
class SelfReferencer(gl.Contract):
    """
    Contract that calls itself. Tests:
    - Can a contract call its own public methods via get_contract_at?
    - Does this create reentrancy issues?
    - Are storage changes from self-calls visible?
    """
    counter: u256

    def __init__(self):
        self.counter = u256(0)

    @gl.public.write
    def increment(self) -> u256:
        self.counter += u256(1)
        return self.counter

    @gl.public.write
    def self_call_increment(self, times: u256) -> str:
        """Call our own increment method via contract proxy."""
        try:
            # Get a reference to ourselves
            self_contract = gl.get_contract_at(gl.contract.address)

            for _ in range(int(times)):
                self_contract.emit().increment()

            return f"Counter after {times} self-calls: {self.counter}"
        except Exception as e:
            return f"Self-call failed: {type(e).__name__}: {str(e)[:100]}"


# ============================================================================
# EDGE CASE 4: Value Transfer Edge Cases
# ============================================================================
class ValueTransferEdgeCases(gl.Contract):
    """Tests edge cases in value (native token) transfers between contracts."""
    received_total: u256

    def __init__(self):
        self.received_total = u256(0)

    @gl.public.write
    @gl.public.payable
    def __receive__(self):
        """Called when contract receives value without method call."""
        self.received_total += gl.message.value

    @gl.public.write
    def test_zero_value_transfer(self, target: Address):
        """Send 0 value to a contract. Should this succeed or fail?"""
        contract = gl.get_contract_at(target)
        # Attempt to call with 0 value
        contract.emit().__receive__()

    @gl.public.write
    @gl.public.payable
    def receive_and_forward(self, target: Address):
        """Receive value and immediately forward it."""
        if gl.message.value > u256(0):
            self.received_total += gl.message.value
            # Forward to target
            contract = gl.get_contract_at(target)
            contract.emit().__receive__()


# ============================================================================
# EDGE CASE 5: Error Handling in Cross-Contract Calls
# ============================================================================
class ErrorPropagation(gl.Contract):
    """
    Tests how errors in called contracts propagate to the caller.
    Questions:
    - Does a revert in the called contract revert the caller?
    - Can the caller catch the error and continue?
    - Is state in the caller preserved or rolled back?
    """
    state_before_call: u256
    state_after_call: u256

    def __init__(self):
        self.state_before_call = u256(0)
        self.state_after_call = u256(0)

    @gl.public.write
    def call_failing_contract(self, target: Address) -> str:
        # Modify state before the call
        self.state_before_call = u256(42)

        try:
            contract = gl.get_contract_at(target)
            contract.emit().always_reverts()  # This should fail
        except Exception as e:
            # State after the failed call
            self.state_after_call = u256(99)
            return (
                f"Caught error: {type(e).__name__}. "
                f"State before: {self.state_before_call}, "
                f"State after: {self.state_after_call}"
            )

        return "UNEXPECTED: No error raised"


class AlwaysReverts(gl.Contract):
    """Helper contract that always reverts."""

    @gl.public.write
    def always_reverts(self):
        raise gl.vm.UserError("I always revert")


# ============================================================================
# EDGE CASE 6: Contract Deploying Another Contract
# ============================================================================
class ContractFactory(gl.Contract):
    """
    Tests contract deployment from within another contract.
    Edge cases:
    - Can a contract deploy other contracts?
    - What happens with constructor arguments?
    - Address derivation (deterministic via salt?)
    """
    deployed_contracts: DynArray[Address]

    def __init__(self):
        pass

    @gl.public.write
    def deploy_child(self, salt: u256) -> str:
        """Attempt to deploy a child contract from within this contract."""
        try:
            # Using deploy_contract if available
            child_address = gl.deploy_contract(
                "child_contract.py",
                salt_nonce=int(salt),
                args=[]
            )
            self.deployed_contracts.append(child_address)
            return f"Deployed child at: {child_address}"
        except Exception as e:
            return f"Deploy failed: {type(e).__name__}: {str(e)[:100]}"


# ============================================================================
# EDGE CASE 7: __on_errored_message__ Behavior
# ============================================================================
class ErrorRecoveryContract(gl.Contract):
    """
    Tests the __on_errored_message__ handler.
    What happens when a message sent to this contract fails?
    Can the error handler introduce new vulnerabilities?
    """
    error_log: DynArray[str]
    recovery_attempts: u256

    def __init__(self):
        self.recovery_attempts = u256(0)

    def __on_errored_message__(self, error_info):
        """Called when a message to this contract errors."""
        self.error_log.append(f"Error #{self.recovery_attempts}: {str(error_info)[:200]}")
        self.recovery_attempts += u256(1)

        # EDGE CASE: What if the error handler itself fails?
        # Does this cause infinite recursion?
        if self.recovery_attempts > u256(100):
            raise gl.vm.UserError("Too many errors")

    @gl.public.write
    def risky_operation(self, should_fail: bool):
        if should_fail:
            raise gl.vm.UserError("Intentional failure")
        # Normal operation
        pass
