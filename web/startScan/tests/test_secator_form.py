"""
Unit tests for Secator form parsing helpers.
"""

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

    def test_parse_secator_config_clamps_values(self):
        """Config parser should clamp values to expected ranges."""
        post = QueryDict("", mutable=True)
        post["rate_limit"] = "999999"
        post["threads"] = "999999"
        post["timeout"] = "999999"
        post["delay"] = "999999"
        cfg = parse_secator_config(post)
        self.assertEqual(cfg["rate_limit"], 10000)
        self.assertEqual(cfg["threads"], 1000)
        self.assertEqual(cfg["timeout"], 3600)
        self.assertEqual(cfg["delay"], 60)

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
        post["expert_mode"] = "true"

        speed, stealth, general, network, expert = parse_secator_profiles(post)
        self.assertEqual(speed, "custom_speed")
        self.assertEqual(stealth, "custom_evasion")
        self.assertEqual(general, "custom_general")
        self.assertEqual(network, "custom_network")
        self.assertTrue(expert)

    def test_parse_secator_profiles_all_disabled(self):
        """When all profile switches are disabled, all profiles should be None."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "false"
        post["use_evasion_profile"] = "false"
        post["use_general_profile"] = "false"
        post["use_network_profile"] = "false"
        post["speed_profile"] = "polite"
        post["stealth_profile"] = "stealth"
        post["general_profile"] = "full"
        post["network_profile"] = "all_ports"

        speed, stealth, general, network, expert = parse_secator_profiles(post)
        self.assertIsNone(speed)
        self.assertIsNone(stealth)
        self.assertIsNone(general)
        self.assertIsNone(network)
        self.assertFalse(expert)

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

        speed, stealth, general, network, expert = parse_secator_profiles(post)
        self.assertEqual(speed, "polite")
        self.assertIsNone(stealth)
        self.assertEqual(general, "full")
        self.assertIsNone(network)
        self.assertFalse(expert)

    def test_parse_secator_profiles_single_enabled(self):
        """Single profile enabled should work correctly."""
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "true"
        post["speed_profile"] = "aggressive"
        post["use_evasion_profile"] = "false"
        post["use_general_profile"] = "false"
        post["use_network_profile"] = "false"

        speed, stealth, general, network, expert = parse_secator_profiles(post)
        self.assertEqual(speed, "aggressive")
        self.assertIsNone(stealth)
        self.assertIsNone(general)
        self.assertIsNone(network)
        self.assertFalse(expert)

    def test_parse_secator_profiles_switches_missing(self):
        """Missing switches should be treated as disabled (None profiles)."""
        post = QueryDict("", mutable=True)
        post["speed_profile"] = "polite"
        post["stealth_profile"] = "stealth"
        post["general_profile"] = "full"
        post["network_profile"] = "all_ports"

        speed, stealth, general, network, expert = parse_secator_profiles(post)
        self.assertIsNone(speed)
        self.assertIsNone(stealth)
        self.assertIsNone(general)
        self.assertIsNone(network)
        self.assertFalse(expert)

    def test_build_start_secator_scan_kwargs_workflow(self):
        """Helper should build normalized kwargs for workflow mode."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "workflow"
        post["workflow_id"] = "123"
        post["scan_existing_elements"] = "true"
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertEqual(kwargs["execution_mode"], "workflow")
        self.assertEqual(kwargs["workflow_id"], 123)
        self.assertIsNone(kwargs["task_ids"])
        self.assertIsNone(kwargs["secator_scan_type"])
        self.assertTrue(kwargs["scan_existing_elements"])

