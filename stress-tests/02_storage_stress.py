# {"Depends": "py-genlayer:test"}
"""
STRESS TEST SUITE 2: Storage & State Stress Testing
=====================================================
Tests the robustness of GenLayer's storage layer under extreme conditions.
"""

from genlayer import *


class StorageStressTest(gl.Contract):
    """
    Pushes storage subsystems to their limits to find breaking points.
    """
    # Various storage collections for testing
    flat_map: TreeMap[str, str]
    nested_map: TreeMap[str, TreeMap[str, u256]]
    large_array: DynArray[str]
    counter_map: TreeMap[u256, u256]
    address_map: TreeMap[Address, DynArray[u256]]

    stress_counter: u256

    def __init__(self):
        self.stress_counter = u256(0)

    # =========================================================================
    # STRESS 1: TreeMap with many keys
    # =========================================================================
    @gl.public.write
    def treemap_mass_insert(self, count: u256) -> str:
        """Insert many keys into a TreeMap. Test performance degradation."""
        for i in range(int(count)):
            key = f"key_{self.stress_counter}_{i}"
            self.flat_map[key] = f"value_{i}" * 10
        self.stress_counter += count
        return f"Inserted {count} keys. Total: {self.stress_counter}"

    @gl.public.write
    def treemap_mass_delete(self, count: u256) -> str:
        """Delete many keys from a TreeMap. Test cleanup performance."""
        deleted = u256(0)
        for i in range(int(count)):
            key = f"key_{i}"
            if key in self.flat_map:
                del self.flat_map[key]
                deleted += u256(1)
        return f"Deleted {deleted} keys"

    @gl.public.view
    def treemap_mass_read(self, count: u256) -> str:
        """Read many keys from TreeMap. Test read performance under load."""
        found = u256(0)
        for i in range(int(count)):
            key = f"key_{i}"
            if key in self.flat_map:
                _ = self.flat_map[key]
                found += u256(1)
        return f"Found {found} of {count} keys"

    # =========================================================================
    # STRESS 2: DynArray growth and access patterns
    # =========================================================================
    @gl.public.write
    def dynarray_append_stress(self, count: u256, item_size: u256) -> str:
        """Append many items to a DynArray. Test exponential growth behavior."""
        item = "x" * int(item_size)
        for _ in range(int(count)):
            self.large_array.append(item)
        return f"Array size: {len(self.large_array)}"

    @gl.public.write
    def dynarray_random_access(self, count: u256) -> str:
        """Random access pattern on a large DynArray."""
        array_len = len(self.large_array)
        if array_len == 0:
            return "Empty array"

        accessed = u256(0)
        for i in range(int(count)):
            # Access pattern: stride through array
            idx = (i * 7) % array_len  # Prime stride for pseudo-random access
            _ = self.large_array[idx]
            accessed += u256(1)
        return f"Accessed {accessed} elements from array of {array_len}"

    @gl.public.write
    def dynarray_insert_middle(self, count: u256) -> str:
        """Insert elements in the middle of a DynArray. Very expensive operation."""
        for i in range(int(count)):
            midpoint = len(self.large_array) // 2
            self.large_array.insert(midpoint, f"mid_insert_{i}")
        return f"Inserted {count} elements at midpoint. Size: {len(self.large_array)}"

    # =========================================================================
    # STRESS 3: Nested storage structures
    # =========================================================================
    @gl.public.write
    def nested_map_stress(self, outer_keys: u256, inner_keys: u256) -> str:
        """
        Create deeply nested storage structure.
        Tests storage serialization overhead.
        """
        for i in range(int(outer_keys)):
            outer_key = f"outer_{i}"
            if outer_key not in self.nested_map:
                self.nested_map[outer_key] = TreeMap[str, u256]()
            inner_map = self.nested_map[outer_key]
            for j in range(int(inner_keys)):
                inner_map[f"inner_{j}"] = u256(i * int(inner_keys) + j)

        return f"Created {outer_keys}x{inner_keys} nested entries"

    # =========================================================================
    # STRESS 4: Key collision and edge cases
    # =========================================================================
    @gl.public.write
    def key_edge_cases(self) -> str:
        """Test edge cases in TreeMap key handling."""
        test_keys = [
            "",                          # Empty string
            " ",                         # Space
            "\t",                        # Tab
            "\n",                        # Newline
            "\x00",                      # Null byte
            "a" * 10000,                 # Very long key
            "\u0000\u0001\u0002",        # Control characters
            "key with spaces",
            "key\twith\ttabs",
            "key\nwith\nnewlines",
            "duplicate",
            "duplicate",                 # Exact duplicate
            "DUPLICATE",                 # Case variation
        ]

        results = []
        for key in test_keys:
            try:
                self.flat_map[key] = f"value_for_{repr(key)[:20]}"
                results.append(f"OK:{repr(key)[:20]}")
            except Exception as e:
                results.append(f"ERR:{repr(key)[:20]}:{str(e)[:30]}")

        return "|".join(results)

    # =========================================================================
    # STRESS 5: Concurrent storage access patterns
    # =========================================================================
    @gl.public.write
    def read_write_interleave(self, count: u256) -> str:
        """
        Interleave reads and writes to test storage consistency.
        Verifies that writes are immediately visible to subsequent reads.
        """
        errors = []
        for i in range(int(count)):
            key = f"interleave_{i}"
            expected_value = f"value_{i}"

            # Write
            self.flat_map[key] = expected_value

            # Immediate read-back
            actual = self.flat_map.get(key, "MISSING")
            if actual != expected_value:
                errors.append(f"Mismatch at {key}: expected={expected_value}, got={actual}")

        if errors:
            return f"FAILURES: {len(errors)} - {errors[:5]}"
        return f"All {count} read-write cycles consistent"

    # =========================================================================
    # STRESS 6: Storage under transaction rollback
    # =========================================================================
    @gl.public.write
    def rollback_consistency(self, should_fail: bool) -> str:
        """
        Test: If a transaction fails after writing to storage,
        are all writes correctly rolled back?
        """
        # Write some data
        self.flat_map["rollback_test_1"] = "should_be_rolled_back"
        self.flat_map["rollback_test_2"] = "should_be_rolled_back"
        self.counter_map[u256(999)] = u256(12345)

        if should_fail:
            # This should cause a rollback, reverting all writes above
            raise gl.vm.UserError("Intentional rollback")

        return "Transaction completed (no rollback)"

    @gl.public.view
    def verify_rollback(self) -> str:
        """Check if the rollback actually cleaned up storage."""
        results = {
            "key1": self.flat_map.get("rollback_test_1", "NOT_FOUND"),
            "key2": self.flat_map.get("rollback_test_2", "NOT_FOUND"),
            "counter": str(self.counter_map.get(u256(999), u256(0))),
        }
        return str(results)
