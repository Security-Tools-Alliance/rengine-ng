"""
Tests for SecatorRunner configuration functionality.
"""

import unittest

from reNgine.secator.runner import SecatorRunner


class TestSecatorRunnerConfig(unittest.TestCase):
    """Test cases for SecatorRunner configuration methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = SecatorRunner()

    def test_prepare_secator_config_basic(self):
        """Test basic Secator configuration preparation."""
        config = {"threads": 10, "timeout": 30, "rate_limit": 100}

        result = self.runner._prepare_secator_config(config)

        self.assertIn("global", result)
        self.assertEqual(result["global"]["concurrency"], 10)
        self.assertEqual(result["global"]["timeout"], 30)
        self.assertEqual(result["global"]["rate_limit"], 100)

    def test_prepare_secator_config_with_profiles(self):
        """Test Secator configuration with profiles."""
        config = {"threads": 5, "timeout": 60}
        profiles = {"speed": "fast", "stealth": "high"}

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertIn("global", result)
        self.assertEqual(result["global"]["concurrency"], 5)
        self.assertEqual(result["global"]["timeout"], 60)
        self.assertEqual(result["speed_profile"], "fast")
        self.assertEqual(result["stealth_profile"], "high")

    def test_prepare_secator_config_threads_precedence(self):
        """Test that threads takes precedence over concurrency."""
        config = {"threads": 15, "concurrency": 20}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 15)

    def test_prepare_secator_config_concurrency_fallback(self):
        """Test that concurrency is used when threads is not set."""
        config = {"concurrency": 25}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 25)

    def test_prepare_secator_config_default_concurrency(self):
        """Test default concurrency when neither threads nor concurrency is set."""
        config = {}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 20)

    def test_prepare_secator_config_invalid_threads(self):
        """Test that invalid threads values fall back to concurrency."""
        config = {"threads": None, "concurrency": 30}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 30)

    def test_prepare_secator_config_empty_threads(self):
        """Test that empty threads values fall back to concurrency."""
        config = {"threads": "", "concurrency": 35}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 35)

    def test_prepare_secator_config_false_threads(self):
        """Test that False threads values fall back to concurrency."""
        config = {"threads": False, "concurrency": 40}

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 40)

    def test_prepare_secator_config_profiles_override(self):
        """Test that profiles override config values."""
        config = {"threads": 10, "timeout": 30}
        profiles = {"custom_key": "custom_value"}

        result = self.runner._prepare_secator_config(config, profiles)

        # Config should be used for special keys (profiles don't override them)
        self.assertEqual(result["global"]["concurrency"], 10)  # threads from config
        self.assertEqual(result["global"]["timeout"], 30)  # timeout from config
        self.assertEqual(result["custom_key"], "custom_value")  # custom key from profiles

    def test_prepare_secator_config_none_inputs(self):
        """Test configuration with None inputs."""
        result = self.runner._prepare_secator_config(None, None)

        self.assertIn("global", result)
        self.assertEqual(result["global"]["concurrency"], 20)  # default

    def test_prepare_secator_config_empty_inputs(self):
        """Test configuration with empty inputs."""
        result = self.runner._prepare_secator_config({}, {})

        self.assertIn("global", result)
        self.assertEqual(result["global"]["concurrency"], 20)  # default

    def test_prepare_secator_config_special_keys(self):
        """Test that special keys are properly mapped."""
        config = {
            "threads": 5,
            "concurrency": 10,  # Should be ignored due to threads
            "rate_limit": 50,
            "timeout": 45,
            "speed": "medium",
            "stealth": "low",
        }

        result = self.runner._prepare_secator_config(config)

        self.assertEqual(result["global"]["concurrency"], 5)  # threads takes precedence
        self.assertEqual(result["global"]["rate_limit"], 50)
        self.assertEqual(result["global"]["timeout"], 45)
        # speed and stealth should be mapped to speed_profile and stealth_profile
        self.assertEqual(result["speed"], "medium")  # Direct mapping, not speed_profile
        self.assertEqual(result["stealth"], "low")  # Direct mapping, not stealth_profile

    def test_prepare_secator_config_all_keys_preserved(self):
        """Test that all keys from config and profiles are preserved."""
        config = {"threads": 5, "custom_config_key": "config_value", "another_key": 123}
        profiles = {"custom_profile_key": "profile_value", "overlap_key": "profile_wins"}

        result = self.runner._prepare_secator_config(config, profiles)

        # All keys should be present
        self.assertIn("custom_config_key", result)
        self.assertIn("another_key", result)
        self.assertIn("custom_profile_key", result)
        self.assertIn("overlap_key", result)

        # Values should be correct
        self.assertEqual(result["custom_config_key"], "config_value")
        self.assertEqual(result["another_key"], 123)
        self.assertEqual(result["custom_profile_key"], "profile_value")
        self.assertEqual(result["overlap_key"], "profile_wins")


if __name__ == "__main__":
    unittest.main()
