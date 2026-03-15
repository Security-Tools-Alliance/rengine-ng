"""
Unit tests for selected_targets parsing (parse_selected_targets, parse_selected_targets_per_task).
"""

import json

from reNgine.secator.selected_targets import (
    filter_selected_targets_per_task_for_target,
    filter_targets_by_target_value,
    filter_targets_override_for_target,
    parse_selected_targets,
    parse_selected_targets_per_task,
    resolve_selected_targets,
    validate_per_task_targets,
)
from utils.test_base import BaseTestCase


class TestParseSelectedTargets(BaseTestCase):
    """Test cases for parse_selected_targets."""

    def test_none_returns_empty_list(self):
        """parse_selected_targets(None) returns []."""
        self.assertEqual(parse_selected_targets(None), [])

    def test_empty_string_returns_empty_list(self):
        """parse_selected_targets('') returns []."""
        self.assertEqual(parse_selected_targets(""), [])

    def test_empty_list_returns_empty_list(self):
        """parse_selected_targets([]) returns []."""
        self.assertEqual(parse_selected_targets([]), [])

    def test_list_normalizes_strip_and_filter(self):
        """parse_selected_targets with list returns stripped non-empty strings."""
        result = parse_selected_targets(["  a  ", "b", None, "", "c"])
        self.assertEqual(result, ["a", "b", "c"])

    def test_json_string_list_returns_normalized(self):
        """parse_selected_targets with valid JSON array returns normalized list."""
        result = parse_selected_targets(json.dumps(["  x  ", "y"]))
        self.assertEqual(result, ["x", "y"])

    def test_invalid_json_raises_value_error(self):
        """parse_selected_targets with invalid JSON raises ValueError with field name."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets("not valid json [")
        self.assertIn("selected_targets", str(ctx.exception))
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_json_not_array_raises_value_error(self):
        """parse_selected_targets with JSON object instead of array raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets('{"key": "value"}')
        self.assertIn("selected_targets", str(ctx.exception))
        self.assertIn("array", str(ctx.exception).lower())

    def test_wrong_type_raises_value_error(self):
        """parse_selected_targets with wrong type (e.g. int) raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets(42)
        self.assertIn("selected_targets", str(ctx.exception))

    def test_custom_field_name_in_error_message(self):
        """parse_selected_targets uses field_name in error message."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets(42, field_name="custom_targets")
        self.assertIn("custom_targets", str(ctx.exception))


class TestParseSelectedTargetsPerTask(BaseTestCase):
    """Test cases for parse_selected_targets_per_task."""

    def test_none_returns_empty_dict(self):
        """parse_selected_targets_per_task(None) returns {}."""
        self.assertEqual(parse_selected_targets_per_task(None), {})

    def test_empty_string_returns_empty_dict(self):
        """parse_selected_targets_per_task('') returns {}."""
        self.assertEqual(parse_selected_targets_per_task(""), {})

    def test_empty_dict_returns_empty_dict(self):
        """parse_selected_targets_per_task({}) returns {}."""
        self.assertEqual(parse_selected_targets_per_task({}), {})

    def test_dict_normalizes_keys_and_values(self):
        """parse_selected_targets_per_task with dict returns normalized mapping."""
        result = parse_selected_targets_per_task(
            {
                "nmap": ["  h1  ", "h2", None, ""],
                "httpx": ["u1"],
            }
        )
        self.assertEqual(result, {"nmap": ["h1", "h2"], "httpx": ["u1"]})

    def test_dict_skips_empty_lists(self):
        """parse_selected_targets_per_task drops task keys whose normalized list is empty."""
        result = parse_selected_targets_per_task(
            {
                "nmap": ["a"],
                "empty": [],
                "blank": [None, "", "  "],
            }
        )
        self.assertEqual(result, {"nmap": ["a"]})

    def test_json_string_dict_returns_normalized(self):
        """parse_selected_targets_per_task with valid JSON object returns normalized dict."""
        result = parse_selected_targets_per_task(json.dumps({"nmap": ["host1"], "httpx": ["host2"]}))
        self.assertEqual(result, {"nmap": ["host1"], "httpx": ["host2"]})

    def test_invalid_json_raises_value_error(self):
        """parse_selected_targets_per_task with invalid JSON raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets_per_task("{nmap: [host1]}")
        self.assertIn("selected_targets_per_task", str(ctx.exception))
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_json_not_object_raises_value_error(self):
        """parse_selected_targets_per_task with JSON array instead of object raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets_per_task('["nmap", "httpx"]')
        self.assertIn("selected_targets_per_task", str(ctx.exception))
        self.assertIn("object", str(ctx.exception).lower())

    def test_wrong_type_raises_value_error(self):
        """parse_selected_targets_per_task with wrong type raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets_per_task(123)
        self.assertIn("selected_targets_per_task", str(ctx.exception))

    def test_custom_field_name_in_error_message(self):
        """parse_selected_targets_per_task uses field_name in error message."""
        with self.assertRaises(ValueError) as ctx:
            parse_selected_targets_per_task(123, field_name="custom_per_task")
        self.assertIn("custom_per_task", str(ctx.exception))


class TestResolveSelectedTargets(BaseTestCase):
    """Test cases for resolve_selected_targets."""

    def test_tasks_with_per_task_non_empty_uses_per_task_mode(self):
        """When execution_mode is tasks and selected_targets_per_task is non-empty, use per_task."""
        result = resolve_selected_targets(
            ["a", "b"],
            {"nmap": ["h1"], "httpx": ["h2"]},
            "tasks",
        )
        self.assertTrue(result["use_per_task"])
        self.assertIsNone(result.get("targets_override"))
        self.assertEqual(result["selected_targets_per_task"], {"nmap": ["h1"], "httpx": ["h2"]})

    def test_tasks_with_per_task_empty_uses_single_mode(self):
        """When execution_mode is tasks but selected_targets_per_task is empty, use single."""
        result = resolve_selected_targets(["a", "b"], {}, "tasks")
        self.assertFalse(result["use_per_task"])
        self.assertEqual(result["targets_override"], ["a", "b"])
        self.assertEqual(result["selected_targets_per_task"], {})

    def test_workflow_mode_ignores_per_task_uses_single(self):
        """When execution_mode is workflow, per_task is ignored; single mode with selected_targets."""
        result = resolve_selected_targets(
            ["x"],
            {"nmap": ["h1"]},
            "workflow",
        )
        self.assertFalse(result["use_per_task"])
        self.assertEqual(result["targets_override"], ["x"])
        self.assertEqual(result["selected_targets_per_task"], {})

    def test_scan_mode_ignores_per_task_uses_single(self):
        """When execution_mode is scan, per_task is ignored; single mode."""
        result = resolve_selected_targets(["y"], {"nmap": ["h1"]}, "scan")
        self.assertFalse(result["use_per_task"])
        self.assertEqual(result["targets_override"], ["y"])

    def test_single_mode_empty_selected_targets_returns_none_override(self):
        """When single mode and selected_targets is empty, targets_override is None."""
        result = resolve_selected_targets([], {}, "workflow")
        self.assertFalse(result["use_per_task"])
        self.assertIsNone(result["targets_override"])
        self.assertEqual(result["selected_targets_per_task"], {})

    def test_execution_mode_none_uses_single(self):
        """When execution_mode is None, use single mode."""
        result = resolve_selected_targets(["z"], {}, None)
        self.assertFalse(result["use_per_task"])
        self.assertEqual(result["targets_override"], ["z"])

    def test_resolve_raises_on_invalid_selected_targets_json(self):
        """resolve_selected_targets raises ValueError when selected_targets is invalid JSON."""
        with self.assertRaises(ValueError) as ctx:
            resolve_selected_targets("not json", {}, "workflow")
        self.assertIn("selected_targets", str(ctx.exception))

    def test_resolve_raises_on_invalid_per_task_json(self):
        """resolve_selected_targets raises ValueError when selected_targets_per_task is invalid."""
        with self.assertRaises(ValueError) as ctx:
            resolve_selected_targets([], "not json", "tasks")
        self.assertIn("selected_targets_per_task", str(ctx.exception))


class TestValidatePerTaskTargets(BaseTestCase):
    """Test cases for validate_per_task_targets."""

    def test_valid_tasks_return_empty_errors(self):
        """When all task_types exist and have targets, returns no errors."""
        task_type_to_id = {"nmap": 1, "httpx": 2}
        per_task = {"nmap": ["h1"], "httpx": ["h2"]}
        errors = validate_per_task_targets(per_task, task_type_to_id)
        self.assertEqual(errors, [])

    def test_unknown_task_type_returns_unknown_task_type_error(self):
        """Unknown task_type yields error with reason unknown_task_type."""
        task_type_to_id = {"nmap": 1}
        per_task = {"nmap": ["h1"], "unknown_task": ["x"]}
        errors = validate_per_task_targets(per_task, task_type_to_id)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["task_type"], "unknown_task")
        self.assertEqual(errors[0]["reason"], "unknown_task_type")
        self.assertIn("No active SecatorTask", errors[0]["detail"])

    def test_empty_targets_returns_no_targets_error(self):
        """Task with empty targets list yields error with reason no_targets."""
        task_type_to_id = {"nmap": 1}
        per_task = {"nmap": []}
        errors = validate_per_task_targets(per_task, task_type_to_id)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["task_type"], "nmap")
        self.assertEqual(errors[0]["reason"], "no_targets")
        self.assertIn("No non-empty targets", errors[0]["detail"])

    def test_multiple_errors_returned(self):
        """Multiple invalid entries yield multiple errors."""
        task_type_to_id = {"nmap": 1}
        per_task = {"unknown": ["x"], "nmap": [], "other_unknown": ["y"]}
        errors = validate_per_task_targets(per_task, task_type_to_id)
        self.assertEqual(len(errors), 3)
        reasons = {e["reason"] for e in errors}
        self.assertIn("unknown_task_type", reasons)
        self.assertIn("no_targets", reasons)


class TestFilterTargetsByTargetValue(BaseTestCase):
    """Test cases for filter_targets_by_target_value (multi-scan deduplication)."""

    def test_none_or_empty_returns_none(self):
        """filter_targets_by_target_value with None or empty list returns None."""
        self.assertIsNone(filter_targets_by_target_value("example.com", None))
        self.assertIsNone(filter_targets_by_target_value("example.com", []))

    def test_domain_exact_match(self):
        """Target value equal to host is kept."""
        result = filter_targets_by_target_value("septodont.de", ["septodont.de"])
        self.assertEqual(result, ["septodont.de"])

    def test_domain_subdomain_kept(self):
        """Subdomain of target value is kept."""
        result = filter_targets_by_target_value(
            "septodont.de",
            ["septodont.de", "www.septodont.de", "api.septodont.de", "other.com"],
        )
        self.assertEqual(result, ["septodont.de", "www.septodont.de", "api.septodont.de"])

    def test_url_with_path_and_port_extracts_host(self):
        """URL with path and port: host is extracted and matched."""
        result = filter_targets_by_target_value(
            "septodont.de",
            ["https://www.septodont.de:443/path", "https://other.com/"],
        )
        self.assertEqual(result, ["https://www.septodont.de:443/path"])

    def test_ip_exact_match_only(self):
        """IP target value: only exact host match is kept (no subdomain logic)."""
        result = filter_targets_by_target_value(
            "192.168.1.1",
            ["192.168.1.1", "192.168.1.2"],
        )
        self.assertEqual(result, ["192.168.1.1"])

    def test_empty_target_value_returns_none(self):
        """Empty or blank target_value returns None."""
        self.assertIsNone(filter_targets_by_target_value("", ["a.com"]))
        self.assertIsNone(filter_targets_by_target_value("   ", ["a.com"]))

    def test_filtered_list_empty_returns_none(self):
        """When no entry belongs to target value, returns None."""
        result = filter_targets_by_target_value(
            "septodont.de",
            ["other.com", "example.org"],
        )
        self.assertIsNone(result)

    def test_filter_targets_override_for_target_wrapper(self):
        """filter_targets_override_for_target is a wrapper of filter_targets_by_target_value."""
        result = filter_targets_override_for_target("apex.com", ["apex.com", "www.apex.com", "other.com"])
        self.assertEqual(result, ["apex.com", "www.apex.com"])

    def test_cidr_exact_match_kept(self):
        """CIDR target value: proposed target with same CIDR is kept."""
        result = filter_targets_by_target_value("172.16.0.0/24", ["172.16.0.0/24"])
        self.assertEqual(result, ["172.16.0.0/24"])

    def test_cidr_filters_other_types(self):
        """CIDR target value: only same CIDR is kept; domains and other CIDRs are excluded."""
        result = filter_targets_by_target_value(
            "172.16.0.0/24",
            ["172.16.0.0/24", "easi-services.fr", "10.0.0.0/8"],
        )
        self.assertEqual(result, ["172.16.0.0/24"])

    def test_domain_target_excludes_cidr(self):
        """Domain target value: CIDR in list does not match and is excluded."""
        result = filter_targets_by_target_value("easi-services.fr", ["172.16.0.0/24"])
        self.assertIsNone(result)


class TestFilterSelectedTargetsPerTaskForTarget(BaseTestCase):
    """Test cases for filter_selected_targets_per_task_for_target."""

    def test_none_or_empty_returns_none(self):
        """filter_selected_targets_per_task_for_target with None or empty dict returns None."""
        self.assertIsNone(filter_selected_targets_per_task_for_target("example.com", None))
        self.assertIsNone(filter_selected_targets_per_task_for_target("example.com", {}))

    def test_task_with_filtered_targets_kept(self):
        """Task whose list has at least one matching target is kept with filtered list."""
        result = filter_selected_targets_per_task_for_target(
            "apex.com",
            {"nmap": ["apex.com", "www.apex.com", "other.com"], "httpx": ["apex.com"]},
        )
        self.assertEqual(result, {"nmap": ["apex.com", "www.apex.com"], "httpx": ["apex.com"]})

    def test_task_with_all_filtered_out_excluded(self):
        """Task that ends up with no targets after filtering is excluded from result."""
        result = filter_selected_targets_per_task_for_target(
            "apex.com",
            {"nmap": ["apex.com"], "httpx": ["other.com"], "dns": ["other.org"]},
        )
        self.assertEqual(result, {"nmap": ["apex.com"]})

    def test_all_tasks_filtered_out_returns_none(self):
        """When every task has no targets belonging to target value, returns None."""
        result = filter_selected_targets_per_task_for_target(
            "apex.com",
            {"nmap": ["other.com"], "httpx": ["other.org"]},
        )
        self.assertIsNone(result)

    def test_cidr_target_keeps_only_mapcidr_with_same_cidr(self):
        """CIDR target value: only task with matching CIDR in list is kept."""
        result = filter_selected_targets_per_task_for_target(
            "172.16.0.0/24",
            {"mapcidr": ["172.16.0.0/24"], "dnsx": ["easi-services.fr"]},
        )
        self.assertEqual(result, {"mapcidr": ["172.16.0.0/24"]})
