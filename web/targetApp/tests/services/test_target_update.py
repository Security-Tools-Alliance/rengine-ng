"""
Tests for target update service: process_target_scan_override_from_post, build_update_target_context.
"""

from django.http import QueryDict

from targetApp.forms import UpdateTargetModelForm
from targetApp.services.target_update import (
    build_update_target_context,
    process_target_scan_override_from_post,
)
from utils.test_base import BaseTestCase


class ProcessTargetScanOverrideFromPostTest(BaseTestCase):
    """Tests for process_target_scan_override_from_post."""

    def test_valid_post_returns_override_and_no_fallback(self):
        post = QueryDict("", mutable=True)
        post["override_threads"] = "10"
        post["override_request_headers"] = "{}"
        scan_override, errors, fallback, headers_initial = process_target_scan_override_from_post(post)
        self.assertIn("threads", scan_override)
        self.assertEqual(errors, [])
        self.assertIsNone(fallback)
        self.assertIsNone(headers_initial)

    def test_invalid_request_headers_returns_errors_and_fallback(self):
        post = QueryDict("", mutable=True)
        post["override_request_headers"] = "not json"
        post["override_threads"] = "5"
        scan_override, errors, fallback, headers_initial = process_target_scan_override_from_post(post)
        self.assertEqual(len(errors), 1)
        self.assertIn("Invalid JSON", errors[0])
        self.assertIsNotNone(fallback)
        self.assertEqual(fallback["threads"], "5")
        self.assertEqual(fallback["rate_limit"], "")
        self.assertEqual(headers_initial, "not json")


class BuildUpdateTargetContextTest(BaseTestCase):
    """Tests for build_update_target_context."""

    def test_returns_expected_context_keys(self):
        self.data_generator.create_organization()
        target = self.data_generator.target
        form = UpdateTargetModelForm(instance=target)
        context = build_update_target_context(target, form)
        self.assertIn("target", context)
        self.assertIn("form", context)
        self.assertIn("target_scopes", context)
        self.assertIn("first_scope", context)
        self.assertIn("effective_params", context)
        self.assertIn("override_request_headers_initial", context)
        self.assertIn("override_form_fallback", context)
        self.assertIn("override_prefix", context)
        self.assertEqual(context["override_prefix"], "override_")
        self.assertIn("list_target_li", context)
        self.assertIn("target_data_active", context)
        self.assertEqual(context["target"], target)
        self.assertEqual(context["form"], form)

    def test_override_request_headers_initial_from_target_when_none_passed(self):
        self.data_generator.create_organization()
        target = self.data_generator.target
        target.scan_config = {"request_headers": {"X-Custom": "value"}}
        target.save()
        form = UpdateTargetModelForm(instance=target)
        context = build_update_target_context(target, form)
        self.assertIn('"X-Custom"', context["override_request_headers_initial"])
        self.assertIn("value", context["override_request_headers_initial"])

    def test_override_request_headers_initial_passed_overrides_target(self):
        self.data_generator.create_organization()
        target = self.data_generator.target
        form = UpdateTargetModelForm(instance=target)
        context = build_update_target_context(target, form, override_request_headers_initial='{"X-Passed": "ok"}')
        self.assertEqual(context["override_request_headers_initial"], '{"X-Passed": "ok"}')
