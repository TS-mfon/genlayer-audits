# {"Depends": "py-genlayer:test"}
"""
STRESS TEST SUITE 1: Consensus Layer Stress Testing
=====================================================
Tests the robustness of the Optimistic Democracy consensus under
adversarial conditions and high load.
"""

from genlayer import *
import json


class ConsensusStressTest(gl.Contract):
    """
    Comprehensive stress tests for the consensus layer.
    Each method targets a specific consensus edge case.
    """
    results: DynArray[str]
    test_counter: u256

    def __init__(self):
        self.test_counter = u256(0)

    # =========================================================================
    # STRESS 1: Rapid-fire consensus operations
    # =========================================================================
    @gl.public.write
    def rapid_consensus_calls(self, count: u256) -> str:
        """
        Submit many consecutive non-deterministic operations in a single
        transaction. Tests whether the consensus layer handles batched
        non-det operations without failure or state corruption.
        """
        results = []
        for i in range(min(int(count), 20)):  # Cap at 20 for safety
            def task(idx=i) -> str:
                return gl.nondet.exec_prompt(f"Return the number {idx}")

            result = gl.eq_principle.strict_eq(task)
            results.append(result)

        self.test_counter += count
        return json.dumps(results)

    # =========================================================================
    # STRESS 2: Nested equivalence principles
    # =========================================================================
    @gl.public.write
    def nested_consensus(self) -> str:
        """
        Tests nested non-deterministic operations.
        What happens when an eq_principle call is inside another?
        Does the inner consensus complete before the outer one validates?
        """
        def outer_task() -> str:
            # First non-det operation
            inner_result = gl.nondet.exec_prompt("Return exactly: ALPHA")

            # Second non-det operation that depends on the first
            combined = gl.nondet.exec_prompt(
                f"The previous result was '{inner_result}'. "
                "Now return exactly: BETA"
            )

            return f"{inner_result}|{combined}"

        result = gl.eq_principle.strict_eq(outer_task)
        self.results.append(result)
        return result

    # =========================================================================
    # STRESS 3: Maximum prompt length
    # =========================================================================
    @gl.public.write
    def max_prompt_length(self) -> str:
        """
        Test behavior when prompts approach or exceed LLM context limits.
        """
        def task() -> str:
            # Generate a very long prompt
            filler = "The quick brown fox jumps over the lazy dog. " * 1000
            prompt = (
                f"Context (please read all of it): {filler}\n\n"
                "After reading all the above context, return exactly: ACKNOWLEDGED"
            )
            return gl.nondet.exec_prompt(prompt)

        result = gl.eq_principle.strict_eq(task)
        return result

    # =========================================================================
    # STRESS 4: Concurrent web fetches
    # =========================================================================
    @gl.public.write
    def concurrent_web_stress(self) -> str:
        """
        Test multiple web fetches in a single non-det block.
        """
        def task() -> str:
            urls = [
                "https://httpbin.org/delay/1",
                "https://httpbin.org/delay/2",
                "https://httpbin.org/delay/3",
                "https://httpbin.org/status/200",
                "https://httpbin.org/status/404",
                "https://httpbin.org/status/500",
            ]

            results = []
            for url in urls:
                try:
                    data = gl.nondet.web.render(url, mode="text")
                    results.append(f"OK:{len(data)}")
                except Exception as e:
                    results.append(f"ERR:{str(e)[:50]}")

            return "|".join(results)

        result = gl.eq_principle.strict_eq(task)
        return result

    # =========================================================================
    # STRESS 5: Mixed equivalence principles
    # =========================================================================
    @gl.public.write
    def mixed_eq_principles(self) -> str:
        """
        Use all three equivalence principles in sequence within one transaction.
        Tests state consistency across different consensus modes.
        """
        # Step 1: Strict equality
        def strict_task() -> str:
            return gl.nondet.exec_prompt("Return exactly: 42")
        strict_result = gl.eq_principle.strict_eq(strict_task)

        # Step 2: Comparative
        def comparative_task() -> str:
            return gl.nondet.exec_prompt(
                "Estimate pi to 4 decimal places. Return only the number."
            )
        comparative_result = gl.eq_principle.prompt_comparative(
            comparative_task,
            principle="Value of pi should be within 0.1% tolerance"
        )

        # Step 3: Non-comparative
        def non_comparative_task() -> str:
            return gl.nondet.exec_prompt(
                f"Given that the answer was {strict_result} and pi is approximately "
                f"{comparative_result}, write a one-sentence conclusion."
            )
        non_comparative_result = gl.eq_principle.prompt_non_comparative(
            non_comparative_task,
            task="Write a conclusion combining two results",
            criteria="Must reference both the number 42 and pi"
        )

        combined = f"strict={strict_result}|comp={comparative_result}|noncomp={non_comparative_result}"
        self.results.append(combined)
        return combined

    # =========================================================================
    # STRESS 6: Error propagation in consensus
    # =========================================================================
    @gl.public.write
    def consensus_error_handling(self, scenario: str) -> str:
        """
        Test how errors propagate through the consensus layer.
        """
        def task() -> str:
            if scenario == "exception":
                raise Exception("Deliberate exception in non-det block")
            elif scenario == "empty":
                return ""
            elif scenario == "none":
                return None  # type: ignore
            elif scenario == "huge":
                return "x" * 10000000  # 10MB result
            elif scenario == "unicode":
                return "\x00\xff\xfe\ud800"  # Invalid Unicode
            elif scenario == "newlines":
                return "\n" * 10000
            else:
                return "normal"

        try:
            result = gl.eq_principle.strict_eq(task)
            return f"SUCCESS: {result[:100]}"
        except Exception as e:
            return f"ERROR: {str(e)[:200]}"

    # =========================================================================
    # STRESS 7: Validator timeout simulation
    # =========================================================================
    @gl.public.write
    def slow_consensus_task(self) -> str:
        """
        Test behavior when non-det operations are very slow.
        What happens when a leader takes much longer than expected?
        Does the consensus timeout? Does it retry with a new leader?
        """
        def task() -> str:
            # Simulate a slow external service
            url = "https://httpbin.org/delay/10"  # 10-second delay
            data = gl.nondet.web.render(url, mode="text")
            return data[:100]

        result = gl.eq_principle.strict_eq(task)
        return result
