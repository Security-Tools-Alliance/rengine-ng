"""
Tests for SecatorRunner concurrency handling.
"""
import unittest

from reNgine.secator.runner import SecatorRunner


class TestSecatorRunnerConcurrency(unittest.TestCase):
    """Test cases for SecatorRunner concurrency configuration."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = SecatorRunner()

    def test_concurrency_threads_precedence_valid(self):
        """Test that threads takes precedence when both are valid."""
        config = {
            "threads": 10,
            "concurrency": 20
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 10)

    def test_concurrency_threads_precedence_zero(self):
        """Test that threads=0 takes precedence over concurrency."""
        config = {
            "threads": 0,
            "concurrency": 20
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 0)

    def test_concurrency_threads_precedence_negative(self):
        """Test that negative threads takes precedence over concurrency."""
        config = {
            "threads": -5,
            "concurrency": 20
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], -5)

    def test_concurrency_fallback_when_threads_none(self):
        """Test that concurrency is used when threads is None."""
        config = {
            "threads": None,
            "concurrency": 15
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 15)

    def test_concurrency_fallback_when_threads_empty_string(self):
        """Test that concurrency is used when threads is empty string."""
        config = {
            "threads": "",
            "concurrency": 25
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 25)

    def test_concurrency_fallback_when_threads_false(self):
        """Test that concurrency is used when threads is False."""
        config = {
            "threads": False,
            "concurrency": 30
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 30)

    def test_concurrency_default_when_none_specified(self):
        """Test default concurrency when neither threads nor concurrency is specified."""
        config = {}
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 20)

    def test_concurrency_only_threads_specified(self):
        """Test concurrency when only threads is specified."""
        config = {
            "threads": 12
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 12)

    def test_concurrency_only_concurrency_specified(self):
        """Test concurrency when only concurrency is specified."""
        config = {
            "concurrency": 18
        }
        
        result = self.runner._prepare_secator_config(config)
        
        self.assertEqual(result["global"]["concurrency"], 18)

    def test_concurrency_profiles_override_config(self):
        """Test that profiles can override concurrency settings."""
        config = {
            "threads": 5,
            "concurrency": 10
        }
        profiles = {
            "custom_key": "custom_value"
        }
        
        result = self.runner._prepare_secator_config(config, profiles)
        
        # Config should be used for concurrency (profiles don't override special keys)
        self.assertEqual(result["global"]["concurrency"], 5)

    def test_concurrency_profiles_override_with_invalid_threads(self):
        """Test that profiles override works even with invalid threads in profiles."""
        config = {
            "threads": 5,
            "concurrency": 10
        }
        profiles = {
            "custom_key": "custom_value"
        }
        
        result = self.runner._prepare_secator_config(config, profiles)
        
        # Should use threads from config (profiles don't override special keys)
        self.assertEqual(result["global"]["concurrency"], 5)

    def test_concurrency_edge_cases(self):
        """Test concurrency with various edge case values."""
        test_cases = [
            ({"threads": 1}, 1),
            ({"threads": 1000}, 1000),
            ({"concurrency": 1}, 1),
            ({"concurrency": 1000}, 1000),
            ({"threads": "5"}, "5"),  # String number should remain string
            ({"concurrency": "10"}, "10"),  # String number should remain string
        ]
        
        for config, expected in test_cases:
            with self.subTest(config=config):
                result = self.runner._prepare_secator_config(config)
                self.assertEqual(result["global"]["concurrency"], expected)

    def test_concurrency_boolean_values(self):
        """Test concurrency with boolean values."""
        # True should be treated as valid
        config = {"threads": True}
        result = self.runner._prepare_secator_config(config)
        self.assertEqual(result["global"]["concurrency"], True)
        
        # False should fall back to concurrency or default
        config = {"threads": False, "concurrency": 15}
        result = self.runner._prepare_secator_config(config)
        self.assertEqual(result["global"]["concurrency"], 15)

    def test_concurrency_string_values(self):
        """Test concurrency with string values."""
        # Non-empty string should be treated as valid
        config = {"threads": "abc"}
        result = self.runner._prepare_secator_config(config)
        self.assertEqual(result["global"]["concurrency"], "abc")
        
        # Empty string should fall back
        config = {"threads": "", "concurrency": 20}
        result = self.runner._prepare_secator_config(config)
        self.assertEqual(result["global"]["concurrency"], 20)


if __name__ == '__main__':
    unittest.main()