"""
Unit tests for Secator form parsing helpers.
"""

import json
from unittest.mock import patch

from django.conf import settings
from django.http import QueryDict

from scanEngine.models import SecatorWorker
from startScan.secator.form import (
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
        self.assertNotIn("proxy", cfg)
        self.assertIn("profiles", cfg)

    def test_parse_secator_profiles_custom_overrides_builtin(self):
        """Custom profile selectors should override builtin hidden inputs."""
        post = self._make_post("true", "use_speed_profile", "polite", "speed_profile")
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
        post = self._make_post("false", "use_speed_profile", "false", "use_evasion_profile")
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
        post = self._make_post("true", "use_speed_profile", "polite", "speed_profile")
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
        post = self._make_post("true", "use_speed_profile", "aggressive", "speed_profile")
        post["use_evasion_profile"] = "false"
        post["use_general_profile"] = "false"
        post["use_network_profile"] = "false"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertIn("aggressive", profiles)
        self.assertEqual(len(profiles), 1)

    def test_parse_secator_profiles_switches_missing(self):
        """Missing switches should be treated as disabled (empty profiles list)."""
        post = self._make_post("polite", "speed_profile", "stealth", "stealth_profile")
        post["general_profile"] = "full"
        post["network_profile"] = "all_ports"

        profiles = parse_secator_profiles(post)
        self.assertIsInstance(profiles, list)
        self.assertEqual(len(profiles), 0)

    def test_build_start_secator_scan_kwargs_workflow(self):
        """Helper should build normalized kwargs for workflow mode."""
        post = self._make_post("workflow", "execution_mode", "123", "workflow_id")
        post["secator_config"] = {"profiles": []}
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertEqual(kwargs["execution_mode"], "workflow")
        self.assertEqual(kwargs["workflow_id"], 123)
        self.assertIsNone(kwargs["task_ids"])
        self.assertIsNone(kwargs["secator_scan_type"])
        self.assertIn("secator_config", kwargs)
        self.assertIn("profiles", kwargs["secator_config"])

    def test_parse_secator_config_malformed_json_warning(self):
        """Malformed JSON in secator_config should log via log_line with level warning."""
        post = self._make_post("{invalid json}", "secator_config", "5", "delay")
        with patch("startScan.secator.form.logger") as mock_logger:
            cfg = parse_secator_config(post)
            mock_logger.log_line.assert_called_once()
            call_args = mock_logger.log_line.call_args
            self.assertEqual(call_args[0][0], "[SECATOR_FORM]")
            self.assertEqual(call_args[0][1], "FORM")
            self.assertIn("Failed to decode", call_args[0][2])
            self.assertEqual(call_args[1].get("level"), "warning")
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

    def test_build_start_secator_scan_kwargs_includes_selected_targets(self):
        """build_start_secator_scan_kwargs should include targets_override when selected_targets is in POST."""
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["selected_targets"] = json.dumps(["https://a.com", "https://b.com"])
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertIn("targets_override", kwargs)
        self.assertEqual(kwargs["targets_override"], ["https://a.com", "https://b.com"])

    def test_build_start_secator_scan_kwargs_includes_selected_targets_per_task(self):
        """build_start_secator_scan_kwargs should include selected_targets_per_task when tasks + per_task in POST."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1", "2"])
        post["secator_config"] = "{}"
        post["selected_targets_per_task"] = json.dumps({"nmap": ["host1"], "httpx": ["host2"]})
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets_per_task", kwargs)
        self.assertEqual(kwargs["selected_targets_per_task"], {"nmap": ["host1"], "httpx": ["host2"]})
        self.assertNotIn("targets_override", kwargs)

    def test_build_start_secator_scan_kwargs_tasks_precedence_per_task_over_selected_targets(self):
        """When tasks mode and both selected_targets and selected_targets_per_task present, only per_task in kwargs."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1"])
        post["secator_config"] = "{}"
        post["selected_targets"] = json.dumps(["https://single.com"])
        post["selected_targets_per_task"] = json.dumps({"nmap": ["host1"]})
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets_per_task", kwargs)
        self.assertEqual(kwargs["selected_targets_per_task"], {"nmap": ["host1"]})
        self.assertNotIn("targets_override", kwargs)

    def test_build_start_secator_scan_kwargs_invalid_selected_targets_raises(self):
        """build_start_secator_scan_kwargs should raise ValueError when selected_targets is invalid JSON."""
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["selected_targets"] = "not valid json ["
        with self.assertRaises(ValueError) as ctx:
            build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets", str(ctx.exception))

    def _make_post(self, value1, key1, value2, key2):
        """Return a mutable QueryDict with two key-value pairs for use in form tests."""
        result = QueryDict("", mutable=True)
        result[key1] = value1
        result[key2] = value2
        return result

    def test_build_start_secator_scan_kwargs_invalid_selected_targets_per_task_raises(self):
        """build_start_secator_scan_kwargs should raise ValueError when selected_targets_per_task is invalid JSON."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1", "2"])
        post["secator_config"] = "{}"
        post["selected_targets_per_task"] = "{nmap: [host1]}"
        with self.assertRaises(ValueError) as ctx:
            build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets_per_task", str(ctx.exception))

    def test_build_start_secator_scan_kwargs_selected_targets_wrong_structure_raises(self):
        """build_start_secator_scan_kwargs should raise ValueError when selected_targets is JSON but not an array."""
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["selected_targets"] = '{"key": "value"}'
        with self.assertRaises(ValueError) as ctx:
            build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets", str(ctx.exception))
        self.assertIn("array", str(ctx.exception).lower())

    def test_build_start_secator_scan_kwargs_selected_targets_per_task_wrong_structure_raises(self):
        """build_start_secator_scan_kwargs should raise ValueError when selected_targets_per_task is JSON but not an object."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1", "2"])
        post["secator_config"] = "{}"
        post["selected_targets_per_task"] = '["nmap", "httpx"]'
        with self.assertRaises(ValueError) as ctx:
            build_start_secator_scan_kwargs(post)
        self.assertIn("selected_targets_per_task", str(ctx.exception))
        self.assertIn("object", str(ctx.exception).lower())

    def test_build_start_secator_scan_kwargs_includes_scan_history_id_when_provided(self):
        """build_start_secator_scan_kwargs should include scan_history_id when present in POST."""
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["scan_history_id"] = "42"
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertIn("scan_history_id", kwargs)
        self.assertEqual(kwargs["scan_history_id"], 42)

    def test_build_start_secator_scan_kwargs_omits_scan_history_id_when_empty(self):
        """build_start_secator_scan_kwargs should not include scan_history_id when missing or invalid."""
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        kwargs = build_start_secator_scan_kwargs(post)
        self.assertNotIn("scan_history_id", kwargs)

    # --- Fix 2: delay default behaviour ---

    def test_parse_secator_config_no_delay_when_not_provided(self):
        """delay is absent from result when neither JSON blob nor top-level field contains it."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = json.dumps({"profiles": []})
        cfg = parse_secator_config(post)
        self.assertNotIn("delay", cfg)

    def test_parse_secator_config_delay_present_when_provided_in_top_level(self):
        """delay is included when explicitly given in top-level POST field."""
        post = QueryDict("", mutable=True)
        post["delay"] = "3"
        post["secator_config"] = json.dumps({"profiles": []})
        cfg = parse_secator_config(post)
        self.assertIn("delay", cfg)
        self.assertEqual(cfg["delay"], 3)

    def test_parse_secator_config_delay_present_when_provided_in_json_blob(self):
        """delay is included when explicitly given inside the secator_config JSON blob."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = json.dumps({"delay": 2, "profiles": []})
        cfg = parse_secator_config(post)
        self.assertIn("delay", cfg)
        self.assertEqual(cfg["delay"], 2)

    def test_parse_secator_config_empty_string_delay_not_included(self):
        """An empty-string delay top-level field is treated as not provided."""
        post = QueryDict("", mutable=True)
        post["delay"] = ""
        post["secator_config"] = json.dumps({"profiles": []})
        cfg = parse_secator_config(post)
        self.assertNotIn("delay", cfg)

    def test_parse_secator_config_proxy_absent_when_not_provided(self):
        """proxy is absent from result when not set in POST."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = json.dumps({"profiles": []})
        cfg = parse_secator_config(post)
        self.assertNotIn("proxy", cfg)

    def test_parse_secator_config_proxy_present_when_provided(self):
        """proxy is included when explicitly given."""
        post = QueryDict("", mutable=True)
        post["secator_config"] = json.dumps({"proxy": "http://p:8080", "profiles": []})
        cfg = parse_secator_config(post)
        self.assertEqual(cfg.get("proxy"), "http://p:8080")

    # --- Fix 4: profiles fallback condition ---

    def test_build_start_secator_scan_kwargs_uses_parse_secator_profiles_when_json_blob_has_empty_profiles(self):
        """When secator_config JSON has profiles=[], the parsed checkbox profiles are applied."""
        post = QueryDict("", mutable=True)
        post["execution_mode"] = "tasks"
        post.setlist("task_ids", ["1"])
        post["secator_config"] = json.dumps({"profiles": []})
        post["use_speed_profile"] = "true"
        post["speed_profile"] = "aggressive"
        kwargs = build_start_secator_scan_kwargs(post)
        profiles = kwargs["secator_config"].get("profiles")
        self.assertIsNotNone(profiles)
        self.assertIn("aggressive", profiles)

    def test_build_start_secator_scan_kwargs_worker_id_omitted_when_not_in_scope(self):
        """When scope has allowed workers and POST worker_id is not in that list, worker_id is omitted."""
        self.data_generator.create_organization()
        scope = self.data_generator.create_scope()
        target = self.data_generator.target
        scope.targets.add(target)
        allowed_worker = SecatorWorker.objects.create(
            name="allowed-worker",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        disallowed_worker = SecatorWorker.objects.create(
            name="disallowed-worker",
            ssh_host="192.0.2.2",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope.workers.add(allowed_worker)
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["target_id"] = str(target.id)
        post["worker_id"] = str(disallowed_worker.id)
        kwargs = build_start_secator_scan_kwargs(post, target=target, scope=scope)
        self.assertNotIn("worker_id", kwargs)

    def test_build_start_secator_scan_kwargs_worker_id_included_when_in_scope(self):
        """When scope has allowed workers and POST worker_id is in that list, worker_id is included."""
        self.data_generator.create_organization()
        scope = self.data_generator.create_scope()
        target = self.data_generator.target
        scope.targets.add(target)
        allowed_worker = SecatorWorker.objects.create(
            name="allowed-worker",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope.workers.add(allowed_worker)
        post = self._make_post("workflow", "execution_mode", "1", "workflow_id")
        post["secator_config"] = "{}"
        post["target_id"] = str(target.id)
        post["worker_id"] = str(allowed_worker.id)
        kwargs = build_start_secator_scan_kwargs(post, target=target, scope=scope)
        self.assertIn("worker_id", kwargs)
        self.assertEqual(kwargs["worker_id"], allowed_worker.id)
