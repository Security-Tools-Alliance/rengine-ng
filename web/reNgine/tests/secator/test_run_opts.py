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
