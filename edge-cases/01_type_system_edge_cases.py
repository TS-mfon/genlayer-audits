# {"Depends": "py-genlayer:test"}
"""
EDGE CASE SUITE 1: Type System & Serialization Edge Cases
============================================================
Tests boundary conditions in GenLayer's type system, calldata encoding,
and storage serialization.
"""

from genlayer import *


class TypeEdgeCases(gl.Contract):
    """
    Comprehensive edge case testing for the GenLayer type system.
    """
    u256_store: TreeMap[str, u256]
    string_store: TreeMap[str, str]
    address_store: TreeMap[str, Address]
    bool_store: TreeMap[str, bool]

    # =========================================================================
    # INTEGER BOUNDARY TESTS
    # =========================================================================
    @gl.public.write
    def test_u256_boundaries(self) -> str:
        """Test u256 at its limits."""
        results = []

        # Max value
        max_u256 = u256(2**256 - 1)
        self.u256_store["max"] = max_u256
        readback = self.u256_store["max"]
        results.append(f"max_u256={readback == max_u256}")

        # Zero
        self.u256_store["zero"] = u256(0)
        results.append(f"zero={self.u256_store['zero'] == u256(0)}")

        # Overflow: max + 1
        try:
            overflow = max_u256 + u256(1)
            results.append(f"overflow=UNEXPECTED:{overflow}")
        except (OverflowError, Exception) as e:
            results.append(f"overflow=CAUGHT:{type(e).__name__}")

        # Underflow: 0 - 1
        try:
            underflow = u256(0) - u256(1)
            results.append(f"underflow=UNEXPECTED:{underflow}")
        except (OverflowError, Exception) as e:
            results.append(f"underflow=CAUGHT:{type(e).__name__}")

        return "|".join(results)

    @gl.public.write
    def test_u8_boundaries(self) -> str:
        """Test u8 at its limits (0-255)."""
        results = []

        results.append(f"u8_max={u8(255)}")
        results.append(f"u8_min={u8(0)}")

        try:
            too_big = u8(256)
            results.append(f"u8_256=UNEXPECTED:{too_big}")
        except Exception as e:
            results.append(f"u8_256=CAUGHT:{type(e).__name__}")

        try:
            negative = u8(-1)
            results.append(f"u8_neg=UNEXPECTED:{negative}")
        except Exception as e:
            results.append(f"u8_neg=CAUGHT:{type(e).__name__}")

        return "|".join(results)

    @gl.public.write
    def test_integer_arithmetic_edge_cases(self) -> str:
        """Test arithmetic operations at boundaries."""
        results = []

        # Division by zero
        try:
            result = u256(100) // u256(0)
            results.append(f"div_zero=UNEXPECTED:{result}")
        except Exception as e:
            results.append(f"div_zero=CAUGHT:{type(e).__name__}")

        # Modulo by zero
        try:
            result = u256(100) % u256(0)
            results.append(f"mod_zero=UNEXPECTED:{result}")
        except Exception as e:
            results.append(f"mod_zero=CAUGHT:{type(e).__name__}")

        # Large multiplication (potential overflow)
        try:
            a = u256(2**128)
            b = u256(2**128)
            result = a * b  # Should be 2^256 which overflows u256
            results.append(f"large_mul=UNEXPECTED:{result}")
        except Exception as e:
            results.append(f"large_mul=CAUGHT:{type(e).__name__}")

        # Multiplication just under overflow
        a = u256(2**128 - 1)
        b = u256(2**128 - 1)
        try:
            result = a * b  # (2^128-1)^2 = 2^256 - 2^129 + 1, fits in u256
            results.append(f"safe_mul=OK")
        except Exception as e:
            results.append(f"safe_mul=UNEXPECTED_ERR:{type(e).__name__}")

        return "|".join(results)

    # =========================================================================
    # ADDRESS EDGE CASES
    # =========================================================================
    @gl.public.write
    def test_address_edge_cases(self) -> str:
        """Test Address type at its limits."""
        results = []

        # Zero address
        zero_addr = Address("0x0000000000000000000000000000000000000000")
        self.address_store["zero"] = zero_addr
        results.append(f"zero_addr=OK")

        # Max address
        max_addr = Address("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        self.address_store["max"] = max_addr
        results.append(f"max_addr=OK")

        # Invalid address formats
        invalid_addresses = [
            "",                          # Empty
            "0x",                        # Just prefix
            "0x123",                     # Too short
            "0x" + "G" * 40,            # Invalid hex chars
            "not_an_address",            # Completely wrong
            "0x" + "0" * 41,            # One byte too long
        ]

        for addr_str in invalid_addresses:
            try:
                addr = Address(addr_str)
                results.append(f"invalid_addr({addr_str[:10]})=UNEXPECTED")
            except Exception as e:
                results.append(f"invalid_addr({addr_str[:10]})=CAUGHT")

        return "|".join(results)

    # =========================================================================
    # STRING EDGE CASES
    # =========================================================================
    @gl.public.write
    def test_string_edge_cases(self) -> str:
        """Test string handling at boundaries."""
        results = []

        test_strings = {
            "empty": "",
            "null_bytes": "hello\x00world",
            "unicode_emoji": "\U0001f600\U0001f680\U0001f4a9",
            "rtl_text": "\u202eThis is reversed\u202c",
            "zalgo": "H\u0335\u0321\u031b\u0320e\u0344\u034f\u032c\u0325",
            "max_char": "\U0010FFFF",
            "long_1mb": "A" * 1048576,
            "newlines_only": "\n" * 1000,
            "mixed_encoding": "ASCII \u00e9\u00e8 \u4e2d\u6587 \U0001f600",
        }

        for name, test_str in test_strings.items():
            try:
                self.string_store[name] = test_str
                readback = self.string_store[name]
                match = readback == test_str
                results.append(f"{name}={'OK' if match else 'MISMATCH'}")
            except Exception as e:
                results.append(f"{name}=ERR:{type(e).__name__}")

        return "|".join(results)

    # =========================================================================
    # CALLDATA ENCODING EDGE CASES
    # =========================================================================
    @gl.public.write
    def test_calldata_boundaries(
        self,
        uint_param: u256,
        string_param: str,
        bool_param: bool,
        address_param: Address
    ) -> str:
        """
        Test calldata encoding/decoding with various parameter types.
        The function itself just echoes back - the test is whether
        the calldata encoding handles edge cases correctly.
        """
        return (
            f"uint={uint_param}|"
            f"string_len={len(string_param)}|"
            f"bool={bool_param}|"
            f"addr={address_param}"
        )

    @gl.public.write
    def test_many_parameters(
        self,
        a: u256, b: u256, c: u256, d: u256, e: u256,
        f: str, g: str, h: str,
        i: bool, j: bool,
        k: Address,
    ) -> str:
        """Test calldata encoding with many parameters."""
        return f"params={a},{b},{c},{d},{e},{f},{g},{h},{i},{j},{k}"

    # =========================================================================
    # COLLECTION EDGE CASES
    # =========================================================================
    @gl.public.write
    def test_treemap_edge_cases(self) -> str:
        """Test TreeMap edge cases."""
        results = []
        test_map: TreeMap[str, u256] = TreeMap[str, u256]()

        # Access non-existent key
        try:
            _ = test_map["nonexistent"]
            results.append("missing_key=NO_ERROR")
        except (KeyError, Exception) as e:
            results.append(f"missing_key=CAUGHT:{type(e).__name__}")

        # Delete non-existent key
        try:
            del test_map["nonexistent"]
            results.append("del_missing=NO_ERROR")
        except (KeyError, Exception) as e:
            results.append(f"del_missing=CAUGHT:{type(e).__name__}")

        # Overwrite existing key
        test_map["key"] = u256(1)
        test_map["key"] = u256(2)
        results.append(f"overwrite={test_map['key'] == u256(2)}")

        # Check length after operations
        results.append(f"len_after_overwrite={len(test_map)}")

        # Clear and verify
        test_map.clear()
        results.append(f"len_after_clear={len(test_map)}")

        return "|".join(results)

    @gl.public.write
    def test_dynarray_edge_cases(self) -> str:
        """Test DynArray edge cases."""
        results = []
        test_array: DynArray[u256] = DynArray[u256]()

        # Pop from empty
        try:
            test_array.pop()
            results.append("pop_empty=NO_ERROR")
        except (IndexError, Exception) as e:
            results.append(f"pop_empty=CAUGHT:{type(e).__name__}")

        # Access out of bounds
        try:
            _ = test_array[0]
            results.append("oob_0=NO_ERROR")
        except (IndexError, Exception) as e:
            results.append(f"oob_0=CAUGHT:{type(e).__name__}")

        # Negative index
        test_array.append(u256(42))
        try:
            val = test_array[-1]
            results.append(f"neg_idx={val}")
        except Exception as e:
            results.append(f"neg_idx=CAUGHT:{type(e).__name__}")

        # Slice operations
        try:
            test_array.append(u256(43))
            test_array.append(u256(44))
            sliced = test_array[0:2]
            results.append(f"slice=OK:{len(sliced)}")
        except Exception as e:
            results.append(f"slice=CAUGHT:{type(e).__name__}")

        return "|".join(results)
