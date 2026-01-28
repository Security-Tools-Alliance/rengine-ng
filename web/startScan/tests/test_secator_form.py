"""
Unit tests for Secator form parsing helpers.
"""

import json
from unittest.mock import patch

from django.conf import settings
from django.http import QueryDict

from startScan.secator_form import (
    build_start_secator_scan_kwargs,
    parse_execution_mode_params,
    parse_secator_config,
    parse_secator_profiles,
)
from utils.test_base import BaseTestCase


class TestSecatorFormHelpers(BaseTestCase):
    """Test cases for Secator POST parsing helpers."""

    def test_parse_execution_mode_params_missing(self):
        """Missing execution_mode should raise a user-facing error."""
        post = QueryDict("", mutable=True)
        with self.assertRaises(ValueError):
            parse_execution_mode_params(post)

    def test_parse_execution_mode_params_workflow_requires_workflow_id(self):
        """Workflow mode requires workflow_id."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "workflow"
        with self.assertRaises(ValueError):
            parse_execution_mode_params(post)

    def test_parse_execution_mode_params_tasks_requires_task_ids(self):
        """Tasks mode requires at least one task id."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        with self.assertRaises(ValueError):
            parse_execution_mode_params(post)

    def test_parse_execution_mode_params_tasks_rejects_invalid_task_ids(self):
        """Tasks mode should reject malformed task IDs with a user-facing error."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1", "not-an-int"])
        with self.assertRaises(ValueError) as ctx:
            parse_execution_mode_params(post)
        self.assertIn("valid task", str(ctx.exception).lower())

    def test_parse_execution_mode_params_scan_requires_scan_type(self):
        """Scan mode requires secator_scan_type."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "scan"
        with self.assertRaises(ValueError):
            parse_execution_mode_params(post)

    def test_parse_secator_config_clamps_delay(self):
        """Config parser should clamp delay to expected range."""
        post = QueryDict("", mutable=True)
        post["delay"] = "999999"
        post["secator_config"] = {"profiles": []}
        cfg = parse_secator_config(post)
        self.assertEqual(cfg["delay"], 60)
        self.assertIn("proxy", cfg)
        self.assertIn("profiles", cfg)

    def test_parse_secator_profiles_custom_overrides_builtin(self):
        """Custom profile selectors should override builtin hidden inputs."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "true"
        post["speed_profile"] = "polite"
        post["speed_custom_profile"] = "custom_speed"
        post["use_evasion_profile"] = "true"
        post["stealth_profile"] = "stealth"
        post["evasion_custom_profile"] = "custom_evasion"
        post["use_general_profile"] = "true"
        post["general_profile"] = "full"
        post["general_custom_profile"] = "custom_general"
        post["use_network_profile"] = "true"
        post["network_profile"] = "all_ports"
        post["network_custom_profile"] = "custom_network"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertIn("custom_speed", profiles)
        self.assertIn("custom_evasion", profiles)
        self.assertIn("custom_general", profiles)
        self.assertIn("custom_network", profiles)
        self.assertEqual(len(profiles), 4)

    def test_parse_secator_profiles_all_disabled(self):
        """When all profile switches are disabled, profiles list should be empty."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "false"
        post["use_evasion_profile"] = "false"
        post["use_general_profile"] = "false"
        post["use_network_profile"] = "false"
        post["speed_profile"] = "polite"
        post["stealth_profile"] = "stealth"
        post["general_profile"] = "full"
        post["network_profile"] = "all_ports"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertEqual(len(profiles), 0)

    def test_parse_secator_profiles_partial_enabled(self):
        """Only enabled profiles should be parsed."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "true"
        post["speed_profile"] = "polite"
        post["use_evasion_profile"] = "false"
        post["stealth_profile"] = "stealth"
        post["use_general_profile"] = "true"
        post["general_profile"] = "full"
        post["use_network_profile"] = "false"
        post["network_profile"] = "all_ports"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertIn("polite", profiles)
        self.assertIn("full", profiles)
        self.assertNotIn("stealth", profiles)
        self.assertNotIn("all_ports", profiles)
        self.assertEqual(len(profiles), 2)

    def test_parse_secator_profiles_single_enabled(self):
        """Single profile enabled should work correctly."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "true"
        post["speed_profile"] = "aggressive"
        post["use_evasion_profile"] = "false"
        post["use_general_profile"] = "false"
        post["use_network_profile"] = "false"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertIn("aggressive", profiles)
        self.assertEqual(len(profiles), 1)

    def test_parse_secator_profiles_switches_missing(self):
        """Missing switches should be treated as disabled (empty profiles list)."""
        post = QueryDict("", mutable=True)
        post["speed_profile"] = "polite"
        post["stealth_profile"] = "stealth"
        post["general_profile"] = "full"
        post["network_profile"] = "all_ports"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertEqual(len(profiles), 0)

    def test_build_start_secator_scan_kwargs_workflow(self):
        """Helper should build normalized kwargs for workflow mode."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "workflow"
        post["workflow_id"] = "123"
        post["scan_existing_elements"] = "true"
        post["secator_config"] = {"profiles": []}
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertEqual(kwargs["execution_mode"], "workflow")
        self.assertEqual(kwargs["workflow_id"], 123)
        self.assertIsNone(kwargs["task_ids"])
        self.assertIsNone(kwargs["secator_scan_type"])
        self.assertTrue(kwargs["scan_existing_elements"])
        self.assertIn("secator_config", kwargs)
        self.assertIn("profiles", kwargs["secator_config"])

    def test_parse_secator_config_malformed_json_warning(self):
        """Malformed JSON in secator_config should log a warning."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = "{invalid json}"
        post["delay"] = "5"
        with patch("startScan.secator_form.logger") as mock_logger:
            cfg = parse_secator_config(post)
            mock_logger.warning.assert_called_once()
            self.assertIn("Failed to decode", str(mock_logger.warning.call_args))
            # Should fallback to top-level fields
            self.assertEqual(cfg["delay"], 5)
            self.assertIn("profiles", cfg)

    def test_parse_secator_config_malformed_json_debug_raises(self):
        """Malformed JSON in secator_config should raise ValueError in DEBUG mode."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = "{invalid json}"
        with patch.object(settings, "DEBUG", True):
            with self.assertRaises(ValueError) as ctx:
                parse_secator_config(post)
            self.assertIn("Invalid JSON", str(ctx.exception))

    def test_parse_secator_config_delay_zero_preserved(self):
        """Explicit delay of 0 in secator_config should not be overridden by top-level."""
        post = QueryDict("", mutable=True)
        post["delay"] = "10"
        post["secator_config"] = {"delay": 0, "profiles": []}
        cfg = parse_secator_config(post)
        self.assertEqual(cfg["delay"], 0)

    def test_parse_secator_config_delay_none_uses_top_level(self):
        """Missing delay in secator_config should use top-level delay."""
        post = QueryDict("", mutable=True)
        post["delay"] = "5"
        post["secator_config"] = {"profiles": []}
        cfg = parse_secator_config(post)
        self.assertEqual(cfg["delay"], 5)

    def test_parse_secator_config_json_string(self):
        """secator_config as JSON string should be parsed correctly."""
        post = QueryDict("", mutable=True)
        config_dict = {"delay": 3, "proxy": "http://proxy:8080", "profiles": ["profile1"]}
        post["secator_config"] = json.dumps(config_dict)
        cfg = parse_secator_config(post)
        self.assertEqual(cfg["delay"], 3)
        self.assertEqual(cfg["proxy"], "http://proxy:8080")
        self.assertEqual(cfg["profiles"], ["profile1"])
