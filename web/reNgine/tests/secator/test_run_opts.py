"""
Tests for build_run_opts helper.
"""

import unittest

from reNgine.secator.run_opts import build_run_opts


class TestBuildRunOpts(unittest.TestCase):
    """Tests for build_run_opts."""

    def test_empty_config_returns_base_opts(self):
        result = build_run_opts({}, [])
        self.assertEqual(result["sync"], False)
        self.assertNotIn("proxy", result)
        self.assertNotIn("delay", result)
        self.assertEqual(result["profiles"], [])

    def test_profiles_reflected(self):
        result = build_run_opts({}, ["polite", "stealth"])
        self.assertEqual(result["profiles"], ["polite", "stealth"])

    def test_scalar_params_included_when_non_empty(self):
        config = {
            "threads": 10,
            "rate_limit": 100,
            "proxy": "http://proxy:8080",
            "delay": 2,
        }
        result = build_run_opts(config, [])
        self.assertEqual(result["threads"], 10)
        self.assertEqual(result["rate_limit"], 100)
        self.assertEqual(result["proxy"], "http://proxy:8080")
        self.assertEqual(result["delay"], 2)

    def test_none_and_empty_string_excluded(self):
        config = {
            "threads": 10,
            "rate_limit": None,
            "timeout": "",
            "proxy": None,
        }
        result = build_run_opts(config, [])
        self.assertEqual(result["threads"], 10)
        self.assertNotIn("rate_limit", result)
        self.assertNotIn("timeout", result)
        self.assertNotIn("proxy", result)

    def test_extra_config_included_when_non_empty_dict(self):
        config = {"extra_config": {"custom_key": "value"}}
        result = build_run_opts(config, [])
        self.assertEqual(result["extra_config"], {"custom_key": "value"})

    def test_extra_config_empty_dict_excluded(self):
        config = {"extra_config": {}}
        result = build_run_opts(config, [])
        self.assertNotIn("extra_config", result)

    def test_header_dict_converted_to_secator_string(self):
        """Header as dict (scan_config format) is converted to Secator ;; string format."""
        config = {"header": {"User-Agent": "Mozilla/5.0", "X-Custom": "value"}}
        result = build_run_opts(config, [])
        self.assertIn("header", result)
        self.assertIsInstance(result["header"], str)
        self.assertIn(";;", result["header"])
        self.assertIn("User-Agent: Mozilla/5.0", result["header"])
        self.assertIn("X-Custom: value", result["header"])

    def test_header_empty_dict_excluded(self):
        """Header as empty dict is not added to run_opts."""
        config = {"header": {}}
        result = build_run_opts(config, [])
        self.assertNotIn("header", result)

    def test_header_string_passed_through(self):
        """Header as string (already Secator format) is passed through unchanged."""
        config = {"header": "User-Agent: Mozilla/5.0;;X-Foo: bar"}
        result = build_run_opts(config, [])
        self.assertEqual(result["header"], "User-Agent: Mozilla/5.0;;X-Foo: bar")

    def test_header_dict_non_string_key_skipped(self):
        """Header dict with non-string key skips that key; only string keys are included."""
        config = {"header": {"X-Valid": "ok", 123: "invalid_key"}}
        result = build_run_opts(config, [])
        self.assertIn("header", result)
        self.assertIn("X-Valid: ok", result["header"])
        self.assertNotIn("123", result["header"])
