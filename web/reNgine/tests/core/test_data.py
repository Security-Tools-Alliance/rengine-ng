"""
Tests for core data utilities.
"""

from django.test import TestCase

from reNgine.core.data import (
    get_ip_info,
    get_ips_from_cidr_range,
    get_request_worker_id,
    is_iterable,
    replace_nulls,
    return_iterable,
    safe_bool_cast,
    safe_int_cast,
)


class TestDataUtils(TestCase):
    """Test data utility functions."""

    def test_return_iterable_with_string(self):
        """Test return_iterable with a string."""
        result = return_iterable("test")
        self.assertEqual(result, ["test"])

    def test_return_iterable_with_list(self):
        """Test return_iterable with a list."""
        result = return_iterable(["test1", "test2"])
        self.assertEqual(result, ["test1", "test2"])

    def test_replace_nulls_string(self):
        """Test replace_nulls with string containing null chars."""
        result = replace_nulls("test\x00value")
        self.assertEqual(result, "testvalue")

    def test_replace_nulls_list(self):
        """Test replace_nulls with list."""
        result = replace_nulls(["test\x00", "value"])
        self.assertEqual(result, ["test", "value"])

    def test_replace_nulls_dict(self):
        """Test replace_nulls with dictionary."""
        result = replace_nulls({"key\x00": "value\x00"})
        self.assertEqual(result, {"key": "value"})

    def test_replace_nulls_nested(self):
        """Test replace_nulls with nested dictionaries and lists."""
        nested = {
            "key\x00": [
                "val\x00ue",
                {"inner\x00key": "inn\x00ervalue"},
                ["li\x00st", {"deep\x00key": "deep\x00value"}],
            ],
            "plain": "no\x00null",
        }
        expected = {"key": ["value", {"innerkey": "innervalue"}, ["list", {"deepkey": "deepvalue"}]], "plain": "nonull"}
        result = replace_nulls(nested)
        self.assertEqual(result, expected)

    def test_replace_nulls_key_collision_raises_error(self):
        """Test that replace_nulls raises ValueError when key collision would occur."""
        collision_dict = {"key\x00": "value1", "key": "value2"}

        with self.assertRaises(ValueError) as context:
            replace_nulls(collision_dict)

        self.assertIn("Key collision detected", str(context.exception))
        self.assertIn("key", str(context.exception))

    def test_replace_nulls_multiple_collisions(self):
        """Test that replace_nulls reports all colliding keys."""
        collision_dict = {"key\x00": "value1", "key": "value2", "another\x00key": "value3", "anotherkey": "value4"}

        with self.assertRaises(ValueError) as context:
            replace_nulls(collision_dict)

        error_msg = str(context.exception)
        self.assertIn("Key collision detected", error_msg)
        self.assertIn("key", error_msg)
        self.assertIn("anotherkey", error_msg)

    def test_replace_nulls_no_collision_success(self):
        """Test that replace_nulls works when no key collisions occur."""
        safe_dict = {"key1": "value1", "key2\x00": "value2", "key3": "value3\x00"}

        result = replace_nulls(safe_dict)
        expected = {"key1": "value1", "key2": "value2", "key3": "value3"}
        self.assertEqual(result, expected)

    def test_replace_nulls_nested_collision_raises_error(self):
        """Test that replace_nulls raises ValueError for key collisions in nested dictionaries."""
        nested_collision = {
            "level1": {
                "key\x00": "value1",
                "key": "value2",  # This will collide with "key\x00"
            },
            "level2": "safe",
        }

        with self.assertRaises(ValueError) as context:
            replace_nulls(nested_collision)

        self.assertIn("Key collision detected", str(context.exception))
        self.assertIn("key", str(context.exception))

    def test_replace_nulls_deeply_nested_collision(self):
        """Test that replace_nulls detects collisions in deeply nested structures."""
        deeply_nested = {
            "level1": {
                "level2": {
                    "level3": {
                        "key\x00": "value1",
                        "key": "value2",  # Collision at level 3
                    }
                }
            }
        }

        with self.assertRaises(ValueError) as context:
            replace_nulls(deeply_nested)

        self.assertIn("Key collision detected", str(context.exception))
        self.assertIn("key", str(context.exception))

    def test_replace_nulls_nested_list_with_dict_collision(self):
        """Test that replace_nulls detects collisions in dictionaries within lists."""
        # Note: Each dict in the list is processed separately, so no collision occurs
        # This test verifies that the function works correctly with nested structures
        list_with_dicts = {
            "items": [
                {"name\x00": "item1"},
                {"name": "item2"},  # No collision - different dicts
                {"other": "item3"},
            ]
        }

        result = replace_nulls(list_with_dicts)

        # Verify structure is preserved and nulls are removed
        self.assertEqual(len(result["items"]), 3)
        self.assertEqual(result["items"][0]["name"], "item1")
        self.assertEqual(result["items"][1]["name"], "item2")
        self.assertEqual(result["items"][2]["other"], "item3")

    def test_replace_nulls_single_dict_in_list_with_collision(self):
        """Test that replace_nulls detects collisions within a single dictionary in a list."""
        list_with_single_dict_collision = {
            "items": [
                {
                    "name\x00": "item1",
                    "name": "item2",  # This WILL collide within the same dict
                }
            ]
        }

        with self.assertRaises(ValueError) as context:
            replace_nulls(list_with_single_dict_collision)

        self.assertIn("Key collision detected", str(context.exception))
        self.assertIn("name", str(context.exception))

    def test_replace_nulls_complex_nested_success(self):
        """Test that replace_nulls works with complex nested structures without collisions."""
        complex_nested = {
            "config": {
                "database": {
                    "host": "localhost",
                    "port": 5432,
                    "name\x00": "test_db",  # No collision
                },
                "cache": {"redis\x00": "redis://localhost:6379", "ttl": 3600},
            },
            "features": [
                {"name": "feature1", "enabled": True},
                {"name\x00": "feature2", "enabled": False},  # No collision
                {"description": "feature3", "enabled": True},
            ],
            "metadata": {"version": "1.0.0", "author\x00": "team", "tags": ["production", "stable"]},
        }

        result = replace_nulls(complex_nested)

        # Verify structure is preserved
        self.assertIn("config", result)
        self.assertIn("features", result)
        self.assertIn("metadata", result)

        # Verify nulls are removed
        self.assertEqual(result["config"]["database"]["name"], "test_db")
        self.assertEqual(result["config"]["cache"]["redis"], "redis://localhost:6379")
        self.assertEqual(result["features"][1]["name"], "feature2")
        self.assertEqual(result["metadata"]["author"], "team")

    def test_replace_nulls_mixed_types_nested(self):
        """Test that replace_nulls handles mixed types in nested structures."""
        mixed_nested = {
            "string": "test\x00value",
            "list": ["item1\x00", "item2", {"nested\x00key": "nested\x00value"}],
            "dict": {
                "key1": "value1\x00",
                "key2": ["list\x00item", {"deep\x00key": "deep\x00value"}],
                "key3": 123,  # Non-string value
            },
            "number": 42,
            "boolean": True,
            "none": None,
        }

        result = replace_nulls(mixed_nested)

        # Verify string nulls are removed
        self.assertEqual(result["string"], "testvalue")
        self.assertEqual(result["list"][0], "item1")
        self.assertEqual(result["list"][2]["nestedkey"], "nestedvalue")
        self.assertEqual(result["dict"]["key1"], "value1")
        self.assertEqual(result["dict"]["key2"][0], "listitem")
        self.assertEqual(result["dict"]["key2"][1]["deepkey"], "deepvalue")

        # Verify non-string values are preserved
        self.assertEqual(result["dict"]["key3"], 123)
        self.assertEqual(result["number"], 42)
        self.assertEqual(result["boolean"], True)
        self.assertIsNone(result["none"])

    def test_is_iterable_with_list(self):
        """Test is_iterable with list."""
        self.assertTrue(is_iterable([1, 2, 3]))

    def test_is_iterable_with_string(self):
        """Test is_iterable with string."""
        self.assertTrue(is_iterable("test"))

    def test_is_iterable_with_int(self):
        """Test is_iterable with integer."""
        self.assertFalse(is_iterable(123))

    def test_safe_int_cast_valid(self):
        """Test safe_int_cast with valid integer."""
        result = safe_int_cast("123")
        self.assertEqual(result, 123)

    def test_safe_int_cast_invalid(self):
        """Test safe_int_cast with invalid value."""
        result = safe_int_cast("invalid", default=0)
        self.assertEqual(result, 0)

    def test_safe_int_cast_list(self):
        """Test safe_int_cast with list."""
        result = safe_int_cast(["1", "2", "3"])
        self.assertEqual(result, [1, 2, 3])

    def test_get_request_worker_id_from_data(self):
        """Test get_request_worker_id from request.data."""
        request = type("R", (), {"data": {"worker_id": 42}, "query_params": {}, "headers": {}})()
        self.assertEqual(get_request_worker_id(request), 42)

    def test_get_request_worker_id_from_query_params(self):
        """Test get_request_worker_id from request.query_params when data has none."""
        request = type(
            "R",
            (),
            {"data": {}, "query_params": {"worker_id": "7"}, "headers": {}},
        )()
        self.assertEqual(get_request_worker_id(request), 7)

    def test_get_request_worker_id_from_header(self):
        """Test get_request_worker_id from X-Secator-Worker-Id header."""
        request = type(
            "R",
            (),
            {"data": {}, "query_params": {}, "headers": {"X-Secator-Worker-Id": "3"}},
        )()
        self.assertEqual(get_request_worker_id(request), 3)

    def test_get_request_worker_id_from_context(self):
        """Test get_request_worker_id from context when request has none."""
        request = type("R", (), {"data": {}, "query_params": {}, "headers": {}})()
        self.assertEqual(get_request_worker_id(request, context={"worker_id": 99}), 99)

    def test_get_request_worker_id_positive_only(self):
        """Test get_request_worker_id returns None for zero or negative."""
        request = type("R", (), {"data": {"worker_id": 0}, "query_params": {}, "headers": {}})()
        self.assertIsNone(get_request_worker_id(request))
        request.data["worker_id"] = -1
        self.assertIsNone(get_request_worker_id(request))

    def test_get_request_worker_id_invalid_returns_none(self):
        """Test get_request_worker_id returns None for invalid values."""
        request = type("R", (), {"data": {"worker_id": "x"}, "query_params": {}, "headers": {}})()
        self.assertIsNone(get_request_worker_id(request))

    def test_get_request_worker_id_no_source_returns_none(self):
        """Test get_request_worker_id returns None when no source provides a value."""
        request = type("R", (), {"data": {}, "query_params": {}, "headers": {}})()
        self.assertIsNone(get_request_worker_id(request))
        self.assertIsNone(get_request_worker_id(request, context={}))

    def test_safe_bool_cast_true_strings(self):
        """Test safe_bool_cast with true string values."""
        self.assertTrue(safe_bool_cast("true"))
        self.assertTrue(safe_bool_cast("True"))
        self.assertTrue(safe_bool_cast("TRUE"))
        self.assertTrue(safe_bool_cast("on"))
        self.assertTrue(safe_bool_cast("On"))
        self.assertTrue(safe_bool_cast("ON"))
        self.assertTrue(safe_bool_cast("1"))
        self.assertTrue(safe_bool_cast("yes"))
        self.assertTrue(safe_bool_cast("Yes"))
        self.assertTrue(safe_bool_cast("YES"))

    def test_safe_bool_cast_false_strings(self):
        """Test safe_bool_cast with false string values."""
        self.assertFalse(safe_bool_cast("false"))
        self.assertFalse(safe_bool_cast("False"))
        self.assertFalse(safe_bool_cast("FALSE"))
        self.assertFalse(safe_bool_cast("off"))
        self.assertFalse(safe_bool_cast("Off"))
        self.assertFalse(safe_bool_cast("OFF"))
        self.assertFalse(safe_bool_cast("0"))
        self.assertFalse(safe_bool_cast("no"))
        self.assertFalse(safe_bool_cast("No"))
        self.assertFalse(safe_bool_cast("NO"))
        self.assertFalse(safe_bool_cast(""))

    def test_safe_bool_cast_boolean_values(self):
        """Test safe_bool_cast with boolean values."""
        self.assertTrue(safe_bool_cast(True))
        self.assertFalse(safe_bool_cast(False))

    def test_safe_bool_cast_none(self):
        """Test safe_bool_cast with None."""
        self.assertFalse(safe_bool_cast(None))
        self.assertTrue(safe_bool_cast(None, default=True))

    def test_safe_bool_cast_integer_values(self):
        """Test safe_bool_cast with integer values."""
        self.assertTrue(safe_bool_cast(1))
        self.assertFalse(safe_bool_cast(0))
        self.assertTrue(safe_bool_cast(42))
        self.assertTrue(safe_bool_cast(-1))

    def test_safe_bool_cast_string_with_whitespace(self):
        """Test safe_bool_cast with strings containing whitespace."""
        self.assertTrue(safe_bool_cast(" true "))
        self.assertTrue(safe_bool_cast(" on "))
        self.assertTrue(safe_bool_cast(" 1 "))
        self.assertFalse(safe_bool_cast(" false "))
        self.assertFalse(safe_bool_cast(" off "))
        self.assertFalse(safe_bool_cast(" 0 "))

    def test_safe_bool_cast_invalid_string(self):
        """Test safe_bool_cast with invalid string values."""
        self.assertFalse(safe_bool_cast("invalid"))
        self.assertFalse(safe_bool_cast("maybe"))
        self.assertFalse(safe_bool_cast("unknown"))
        self.assertTrue(safe_bool_cast("invalid", default=True))

    def test_safe_bool_cast_default_value(self):
        """Test safe_bool_cast with custom default value."""
        self.assertFalse(safe_bool_cast(None, default=False))
        self.assertTrue(safe_bool_cast(None, default=True))
        self.assertFalse(safe_bool_cast("invalid", default=False))
        self.assertTrue(safe_bool_cast("invalid", default=True))

    def test_get_ip_info_ipv4(self):
        """Test get_ip_info with IPv4."""
        result = get_ip_info("192.168.1.1")
        self.assertIsNotNone(result)
        self.assertEqual(str(result), "192.168.1.1")

    def test_get_ip_info_invalid(self):
        """Test get_ip_info with invalid IP."""
        result = get_ip_info("invalid")
        self.assertIsNone(result)

    def test_get_ip_info_empty_string(self):
        """Test get_ip_info with empty string."""
        result = get_ip_info("")
        self.assertIsNone(result)

    def test_get_ip_info_none(self):
        """Test get_ip_info with None."""
        result = get_ip_info(None)
        self.assertIsNone(result)

    def test_get_ips_from_cidr_range(self):
        """Test get_ips_from_cidr_range."""
        result = get_ips_from_cidr_range("192.168.1.0/30")
        self.assertEqual(len(result), 4)
        self.assertIn("192.168.1.0", result)

    def test_get_ips_from_cidr_range_invalid(self):
        """Test get_ips_from_cidr_range with invalid CIDR."""
        result = get_ips_from_cidr_range("invalid")
        self.assertEqual(result, [])

    def test_get_ips_from_cidr_range_edge_cases(self):
        """Test get_ips_from_cidr_range with edge-case CIDR ranges."""
        # Test /32 (single IP)
        result = get_ips_from_cidr_range("192.168.1.1/32")
        self.assertEqual(len(result), 1)
        self.assertEqual(result, ["192.168.1.1"])

        # Test /31 (2 IPs - network and broadcast)
        result = get_ips_from_cidr_range("192.168.1.0/31")
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.0", result)
        self.assertIn("192.168.1.1", result)

        # Test /24 (256 IPs)
        result = get_ips_from_cidr_range("192.168.1.0/24")
        self.assertEqual(len(result), 256)
        self.assertIn("192.168.1.0", result)  # Network address
        self.assertIn("192.168.1.1", result)  # First usable
        self.assertIn("192.168.1.254", result)  # Last usable
        self.assertIn("192.168.1.255", result)  # Broadcast address

        # Test /16 (65536 IPs)
        result = get_ips_from_cidr_range("192.168.0.0/16")
        self.assertEqual(len(result), 65536)
        self.assertIn("192.168.0.0", result)  # Network address
        self.assertIn("192.168.255.255", result)  # Broadcast address

    def test_get_ips_from_cidr_range_ipv6_limitation(self):
        """Test get_ips_from_cidr_range with IPv6 CIDR ranges (currently not supported)."""
        # Note: The current implementation only supports IPv4 using IPv4Network
        # IPv6 addresses should return empty list

        # Test IPv6 /128 (single IP) - should return empty list
        result = get_ips_from_cidr_range("2001:db8::1/128")
        self.assertEqual(result, [])

        # Test IPv6 /127 (2 IPs) - should return empty list
        result = get_ips_from_cidr_range("2001:db8::/127")
        self.assertEqual(result, [])

        # Test IPv6 /64 - should return empty list
        result = get_ips_from_cidr_range("2001:db8::/64")
        self.assertEqual(result, [])

        # Test mixed IPv6 format - should return empty list
        result = get_ips_from_cidr_range("::1/128")
        self.assertEqual(result, [])

    def test_get_ips_from_cidr_range_special_cases(self):
        """Test get_ips_from_cidr_range with special network cases."""
        # Test loopback network
        result = get_ips_from_cidr_range("127.0.0.0/8")
        self.assertEqual(len(result), 16777216)  # 2^24
        self.assertIn("127.0.0.1", result)

        # Test private network
        result = get_ips_from_cidr_range("10.0.0.0/8")
        self.assertEqual(len(result), 16777216)  # 2^24
        self.assertIn("10.0.0.1", result)
        self.assertIn("10.255.255.254", result)

        # Test link-local network
        result = get_ips_from_cidr_range("169.254.0.0/16")
        self.assertEqual(len(result), 65536)  # 2^16
        self.assertIn("169.254.0.1", result)
        self.assertIn("169.254.255.254", result)

    def test_get_ips_from_cidr_range_malformed_inputs(self):
        """Test get_ips_from_cidr_range with various malformed inputs."""
        # Test empty string
        result = get_ips_from_cidr_range("")
        self.assertEqual(result, [])

        # Test None
        result = get_ips_from_cidr_range(None)
        self.assertEqual(result, [])

        # Test invalid IP format
        result = get_ips_from_cidr_range("999.999.999.999/24")
        self.assertEqual(result, [])

        # Test IP without slash (treated as /32 by ipaddress module)
        result = get_ips_from_cidr_range("192.168.1.1")
        self.assertEqual(len(result), 1)
        self.assertEqual(result, ["192.168.1.1"])

        # Test invalid prefix length
        result = get_ips_from_cidr_range("192.168.1.0/33")
        self.assertEqual(result, [])

        # Test negative prefix length
        result = get_ips_from_cidr_range("192.168.1.0/-1")
        self.assertEqual(result, [])

        # Test non-numeric prefix
        result = get_ips_from_cidr_range("192.168.1.0/abc")
        self.assertEqual(result, [])

        # Test IPv6 with invalid prefix
        result = get_ips_from_cidr_range("2001:db8::/129")
        self.assertEqual(result, [])
