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
        self.assertIsNone(result.get("proxy"))
        self.assertEqual(result["delay"], 0)
        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])
        self.assertIn("full", result["profiles"])
        self.assertIn("all_ports", result["profiles"])
        self.assertEqual(len(result["profiles"]), 4)

    def test_prepare_secator_config_default_delay(self):
        """When delay is absent from config, it is not forwarded to run_opts."""
        config = {"proxy": None}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertNotIn("delay", result)

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
        """When config and profiles are None, only sync and profiles keys are present."""
        result = self.runner._prepare_secator_config(None, None)

        self.assertEqual(result["sync"], False)
        self.assertNotIn("proxy", result)
        self.assertNotIn("delay", result)
        self.assertIn("profiles", result)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_empty_inputs(self):
        """When config and profiles are empty, only sync and profiles keys are present."""
        result = self.runner._prepare_secator_config({}, [])

        self.assertEqual(result["sync"], False)
        self.assertNotIn("proxy", result)
        self.assertNotIn("delay", result)
        self.assertIn("profiles", result)
        self.assertEqual(len(result["profiles"]), 0)

    def test_prepare_secator_config_sync_always_false(self):
        """Test that sync is always False."""
        config = {"proxy": None, "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["sync"], False)

    def test_prepare_secator_config_proxy_none(self):
        """When proxy is None in config, it is not forwarded to run_opts."""
        config = {"proxy": None, "delay": 5}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertNotIn("proxy", result)

    def test_prepare_secator_config_proxy_string(self):
        """Test configuration with proxy as string."""
        config = {"proxy": "socks5://127.0.0.1:9050", "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["proxy"], "socks5://127.0.0.1:9050")

    def test_prepare_secator_config_delay_zero(self):
        """Explicit delay=0 in config is forwarded to run_opts (0 is a valid value)."""
        config = {"proxy": None, "delay": 0}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 0)

    def test_prepare_secator_config_delay_positive(self):
        """Positive delay in config is forwarded to run_opts."""
        config = {"proxy": None, "delay": 10}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertEqual(result["delay"], 10)

    def test_prepare_secator_config_delay_absent_when_omitted(self):
        """When delay is absent from config, it is not added to run_opts."""
        config = {"proxy": "http://proxy:8080"}
        profiles = []

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertNotIn("delay", result)
        self.assertEqual(result["proxy"], "http://proxy:8080")

    def test_prepare_secator_config_profiles_non_string_items(self):
        """Test that profiles with non-string items skip None and convert non-strings to string."""
        config = {"proxy": None, "delay": 0}
        profiles = ["polite", 123, None, "full", True]

        result = self.runner._prepare_secator_config(config, profiles)

        self.assertIn("profiles", result)
        self.assertIsInstance(result["profiles"], list)
        self.assertIn("polite", result["profiles"])
        self.assertIn("full", result["profiles"])
        self.assertIn("123", result["profiles"])
        self.assertIn("True", result["profiles"])
        self.assertNotIn(None, result["profiles"])


if __name__ == "__main__":
    unittest.main()
