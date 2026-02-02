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
        config = {"proxy": "socks5://127.0.0.1:9050", "delay": 5}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["sync"], False)
        self.assertEqual(result["proxy"], "socks5://127.0.0.1:9050")
        self.assertEqual(result["delay"], 5)
        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_with_profiles(self):
        """Test Secator configuration with profiles."""
        config = {"proxy": None, "delay": 0}
        profiles = ["polite", "stealth", "full", "all_ports"]

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["sync"], False)
        self.assertIsNone(result["proxy"])
        self.assertEqual(result["delay"], 0)
        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])
        self.assertIn("full", result["profiles"])
        self.assertIn("all_ports", result["profiles"])
        self.assertEqual(len(result["profiles"]), 4)

    def test_prepare_secator_config_default_delay(self):
        """Test default delay when not specified."""
        config = {"proxy": None}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 0)

    def test_prepare_secator_config_empty_profiles(self):
        """Test configuration with empty profiles list."""
        config = {"proxy": "http://proxy:8080", "delay": 10}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["sync"], False)
        self.assertEqual(result["proxy"], "http://proxy:8080")
        self.assertEqual(result["delay"], 10)
        self.assertIn("profiles", result)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_partial_profiles(self):
        """Test configuration with only some profiles enabled."""
        config = {"proxy": None, "delay": 5}
        profiles = ["polite", "full"]

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertIn("polite", result["profiles"])
        self.assertIn("full", result["profiles"])
        self.assertEqual(len(result["profiles"]), 2)

    def test_prepare_secator_config_none_inputs(self):
        """Test configuration with None inputs."""
        result = self.runner._prepare_secator_config(None, None)

        self.assertEqual(result["sync"], False)
        self.assertIsNone(result["proxy"])
        self.assertEqual(result["delay"], 0)
        self.assertIn("profiles", result)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_empty_inputs(self):
        """Test configuration with empty inputs."""
        result = self.runner._prepare_secator_config({}, [])

        self.assertEqual(result["sync"], False)
        self.assertIsNone(result["proxy"])
        self.assertEqual(result["delay"], 0)
        self.assertIn("profiles", result)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_sync_always_false(self):
        """Test that sync is always False."""
        config = {"proxy": None, "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["sync"], False)

    def test_prepare_secator_config_proxy_none(self):
        """Test configuration with proxy set to None."""
        config = {"proxy": None, "delay": 5}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertIsNone(result["proxy"])

    def test_prepare_secator_config_proxy_string(self):
        """Test configuration with proxy as string."""
        config = {"proxy": "socks5://127.0.0.1:9050", "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["proxy"], "socks5://127.0.0.1:9050")

    def test_prepare_secator_config_delay_zero(self):
        """Test configuration with delay set to 0."""
        config = {"proxy": None, "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 0)

    def test_prepare_secator_config_delay_positive(self):
        """Test configuration with positive delay."""
        config = {"proxy": None, "delay": 10}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 10)

    def test_prepare_secator_config_delay_default_when_omitted(self):
        """Test that delay defaults to 0 when config is non-empty but delay is omitted."""
        config = {"proxy": "http://proxy:8080"}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 0)
        self.assertEqual(result["proxy"], "http://proxy:8080")

    def test_prepare_secator_config_profiles_non_string_items(self):
        """Test that profiles with non-string items skip None and keep non-strings as-is."""
        config = {"proxy": None, "delay": 0}
        profiles = ["polite", 123, None, "full", True]

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertIn("polite", result["profiles"])
        self.assertIn("full", result["profiles"])
        self.assertIn(123, result["profiles"])
        self.assertIn(True, result["profiles"])
        self.assertNotIn(None, result["profiles"])


if __name__ == "__main__":
    unittest.main()
