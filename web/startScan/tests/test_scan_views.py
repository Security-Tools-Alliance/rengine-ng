"""
Test cases for scan views functionality.
"""

import json
from unittest.mock import patch
import uuid

from django.core.exceptions import ValidationError
from django.http import QueryDict
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from scanEngine.models import SecatorProfile
from startScan.models import Command, Domain, ScanHistory, ScanSchedule, Subdomain
from startScan.views import (
    SCHEDULE_MODE_REQUIRED_MSG,
    _domains_for_scan_detail,
    _parse_scheduled_time_utc,
    _validate_schedule_form_post,
)
from targetApp.models import Scope, Target
from utils.test_base import BaseTestCase


class TestSubscanHistory(BaseTestCase):
    """Test cases for subscan history view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_subscan()

    def test_subscan_history_view(self):
        """Test the subscan history view."""
        response = self.client.get(
            reverse(
                "subscan_history",
                kwargs={"slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("subscans", response.context)
        self.assertGreaterEqual(len(response.context["subscans"]), 1)


class TestScanLogsView(BaseTestCase):
    """Test cases for scan logs view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_scan_activity()
        self.data_generator.create_command()

    def test_scan_logs_view_with_scan_id(self):
        """Test scan logs view with scan_id parameter."""
        url = reverse("scan_logs", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, 200)
        self.assertIn("hierarchical_structure", response.context)

    def test_scan_logs_view_with_activity_id(self):
        """Test scan logs view with activity_id parameter."""
        url = reverse("scan_logs", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.get(url, {"activity_id": self.data_generator.scan_activity.id})
        self.assertEqual(response.status_code, 200)
        self.assertIn("hierarchical_structure", response.context)

    def test_scan_logs_view_missing_parameters(self):
        """Test scan logs view without required parameters."""
        url = reverse("scan_logs", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

    def test_scan_logs_view_with_include_pending(self):
        """Test scan logs view with include_pending parameter."""
        url = reverse("scan_logs", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id, "include_pending": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("hierarchical_structure", response.context)


class TestDomainsForScanDetail(BaseTestCase):
    """Test _domains_for_scan_detail: only current scan and apex/root domains (exclude hostname-style names)."""

    def test_returns_only_domains_for_given_scan(self):
        """Domains from other scans are not included."""
        self.data_generator.create_project_base()
        scan_a = self.data_generator.scan_history
        Domain.objects.create(name="apex-a.com", insert_date=timezone.now(), scan_history=scan_a)
        scan_b = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=2,
            target=self.data_generator.target,
        )
        Domain.objects.create(name="apex-b.com", insert_date=timezone.now(), scan_history=scan_b)
        result = _domains_for_scan_detail(scan_a.id)
        names = [d.name for d in result]
        for d in result:
            self.assertEqual(d.scan_history_id, scan_a.id, "Only domains for scan_a should be returned")
        self.assertIn("apex-a.com", names)
        self.assertNotIn("apex-b.com", names)

    def test_excludes_domain_names_with_more_than_two_labels(self):
        """Hostname-style names (e.g. www.example.com) are excluded so only apex/root domains appear."""
        self.data_generator.create_project_base()
        scan = self.data_generator.scan_history
        Domain.objects.create(name="example.com", insert_date=timezone.now(), scan_history=scan)
        Domain.objects.create(name="www.example.com", insert_date=timezone.now(), scan_history=scan)
        Domain.objects.create(name="sub.example.com", insert_date=timezone.now(), scan_history=scan)
        result = _domains_for_scan_detail(scan.id)
        names = [d.name for d in result]
        self.assertIn("example.com", names)
        self.assertNotIn("www.example.com", names)
        self.assertNotIn("sub.example.com", names)


class TestExportUrls(BaseTestCase):
    """Test cases for export URLs view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        # Create subdomain with http_url
        self.data_generator.create_subdomain(http_url="https://admin.example.com")

    def test_export_urls_view(self):
        """Test the export URLs view."""
        response = self.client.get(
            reverse(
                "export_http_urls",
                kwargs={
                    "scan_id": self.data_generator.scan_history.id,
                    "slug": self.data_generator.project.slug,
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertIn("urls_", response["Content-Disposition"])

    def test_export_empty_urls_view(self):
        """Test the export URLs view when there are no URLs."""
        # Delete all subdomains with http_url
        Subdomain.objects.filter(scan_history=self.data_generator.scan_history).update(http_url=None)

        response = self.client.get(
            reverse(
                "export_http_urls",
                kwargs={
                    "scan_id": self.data_generator.scan_history.id,
                    "slug": self.data_generator.project.slug,
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertEqual(response.content.decode(), "")


class TestStartMultipleScan(BaseTestCase):
    """Test cases for start multiple scan view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_start_multiple_scan_view_get(self):
        """Test the start multiple scan view GET request."""
        response = self.client.get(
            reverse(
                "start_multiple_scan",
                kwargs={"slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("domain_list", response.context)
        self.assertIn("domain_ids", response.context)
        self.assertIn("default_profiles", response.context)
        self.assertIn("custom_profiles_by_category", response.context)
        for category in ["speed", "evasion", "general", "network"]:
            self.assertIn(category, response.context["custom_profiles_by_category"])

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("startScan.views.start_secator_scan")
    def test_start_multiple_scan_view_post(self, mock_start_scan):
        """Test the start multiple scan view POST request."""
        mock_start_scan.return_value = {"status": True, "scan_id": self.data_generator.scan_history.id}

        data = {
            "execution_mode": "scan",
            "secator_scan_type": "domain",
            "list_of_target_id": str(self.data_generator.target.id),
        }
        response = self.client.post(
            reverse(
                "start_multiple_scan",
                kwargs={"slug": self.data_generator.project.slug},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        mock_start_scan.assert_called()

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("startScan.views.start_secator_scan")
    def test_start_multiple_scan_filters_targets_override_per_target(self, mock_start_scan):
        """Multiple scan must pass targets_override filtered to each target (deduplication)."""
        mock_start_scan.return_value = {"status": True, "scan_id": self.data_generator.scan_history.id}

        target_a = self.data_generator.target
        target_b = Target.objects.create(
            project=self.data_generator.project,
            value="example-second.com",
            target_type="host",
            insert_date=timezone.now(),
        )
        subdomain_a = "www." + target_a.value
        target_ids_str = "%s,%s" % (target_a.id, target_b.id)
        selected_targets = json.dumps([target_a.value, target_b.value, subdomain_a])

        data = {
            "execution_mode": "scan",
            "secator_scan_type": "subdomain",
            "list_of_target_id": target_ids_str,
            "selected_targets": selected_targets,
        }
        response = self.client.post(
            reverse(
                "start_multiple_scan",
                kwargs={"slug": self.data_generator.project.slug},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(mock_start_scan.call_count, 2)

        call_target_ids = [call.kwargs["target_id"] for call in mock_start_scan.call_args_list]
        self.assertIn(target_a.id, call_target_ids)
        self.assertIn(target_b.id, call_target_ids)
        self.assertNotEqual(call_target_ids[0], call_target_ids[1])

        for call in mock_start_scan.call_args_list:
            tid = call.kwargs["target_id"]
            override = call.kwargs.get("targets_override")
            if tid == target_a.id:
                self.assertIsNotNone(override, "target A should get filtered targets_override")
                self.assertIn(target_a.value, override)
                self.assertIn(subdomain_a, override)
                self.assertNotIn(target_b.value, override)
            else:
                self.assertEqual(tid, target_b.id)
                self.assertIsNotNone(override, "target B should get filtered targets_override")
                self.assertIn(target_b.value, override)
                self.assertNotIn(target_a.value, override)
                self.assertNotIn(subdomain_a, override)


class TestSecatorProfilesContext(BaseTestCase):
    """Test cases for Secator profiles context in scan start views."""

    def test_start_scan_ui_has_profiles_context(self):
        """start_scan_ui should always provide profile context keys."""
        response = self.client.get(
            reverse(
                "start_scan",
                kwargs={
                    "slug": self.data_generator.project.slug,
                    "target_id": self.data_generator.target.id,
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("default_profiles", response.context)
        self.assertIn("custom_profiles_by_category", response.context)
        self.assertIn(b'id="start_scan_execution_mode"', response.content)

    def test_start_scan_ui_has_effective_params_context(self):
        """start_scan_ui should provide scan_params_effective in context."""
        response = self.client.get(
            reverse(
                "start_scan",
                kwargs={
                    "slug": self.data_generator.project.slug,
                    "target_id": self.data_generator.target.id,
                },
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("scan_params_effective", response.context)
        effective = response.context["scan_params_effective"]
        self.assertIsInstance(effective, dict)
        self.assertIn("threads", effective)
        self.assertIn("profiles", effective)
        for key, info in effective.items():
            if key == "profile_display_list":
                continue
            self.assertIsInstance(info, dict, msg="Expected dict for %s" % key)
            self.assertIn("value", info)
            self.assertIn("source", info)

    def test_start_organization_scan_has_profiles_context(self):
        """start_organization_scan should always provide profile context keys."""
        response = self.client.get(
            reverse(
                "start_organization_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("default_profiles", response.context)
        self.assertIn("custom_profiles_by_category", response.context)
        self.assertIn(b'id="start_org_scan_execution_mode"', response.content)

    def test_start_organization_scan_get_returns_target_list_context(self):
        """start_organization_scan GET should provide target_list and target_ids (not domain_list)."""
        response = self.client.get(
            reverse(
                "start_organization_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("target_list", response.context)
        self.assertIn("target_ids", response.context)
        self.assertNotIn("domain_list", response.context)

    def test_start_organization_scan_post_empty_targets_redirects_with_warning(self):
        """start_organization_scan POST with no targets should redirect back with explicit message."""
        self.data_generator.organization.targets.clear()
        scope_qs = Scope.objects.filter(organization=self.data_generator.organization)
        for scope in scope_qs:
            scope.targets.clear()
        data = {
            "execution_mode": "scan",
            "secator_scan_type": "domain",
        }
        response = self.client.post(
            reverse(
                "start_organization_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            reverse(
                "start_organization_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": self.data_generator.organization.id},
            ),
            fetch_redirect_response=False,
        )
        response_follow = self.client.get(response.url)
        messages_list = list(response_follow.context["messages"]) if response_follow.context.get("messages") else []
        self.assertTrue(
            any("Add targets to one or more scopes" in str(m) for m in messages_list),
            "Expected warning about adding targets to scopes or legacy",
        )

    def test_start_scope_scan_get_returns_200_and_quick_scan_context(self):
        """start_scope_scan GET should return 200 and quick scan form context."""
        scope = self.data_generator.create_scope()
        response = self.client.get(
            reverse(
                "start_scope_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": scope.id},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("target_list", response.context)
        self.assertIn("target_ids", response.context)
        self.assertIn("quick_scan_entity_name", response.context)
        self.assertEqual(response.context["quick_scan_entity_name"], scope.name)
        self.assertIn(b'id="start_scope_scan_execution_mode"', response.content)

    def test_start_scope_scan_post_empty_targets_redirects_with_warning(self):
        """start_scope_scan POST with no targets should redirect back to form."""
        scope = self.data_generator.create_scope()
        scope.targets.clear()
        data = {
            "execution_mode": "scan",
            "secator_scan_type": "domain",
        }
        response = self.client.post(
            reverse(
                "start_scope_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": scope.id},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            reverse(
                "start_scope_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": scope.id},
            ),
            fetch_redirect_response=False,
        )

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    @patch("startScan.views._run_secator_scan_or_per_task")
    def test_start_scope_scan_post_with_targets_redirects_to_scan_history(self, mock_run):
        """start_scope_scan POST with targets should run scans and redirect to scan_history."""
        mock_run.return_value = (1, 0)
        scope = self.data_generator.create_scope()
        data = {
            "execution_mode": "scan",
            "secator_scan_type": "domain",
        }
        response = self.client.post(
            reverse(
                "start_scope_scan",
                kwargs={"slug": self.data_generator.project.slug, "id": scope.id},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            reverse("scan_history", kwargs={"slug": self.data_generator.project.slug}),
            fetch_redirect_response=False,
        )
        self.assertEqual(mock_run.call_count, 1)

    def test_start_multiple_scan_renders_custom_profile_option(self):
        """start_multiple_scan should render custom profile options when they exist."""
        profile_name = f"custom-speed-{str(uuid.uuid4())[:8]}"
        SecatorProfile.objects.create(
            name=profile_name,
            category="speed",
            description="Custom speed profile for tests",
            opts="rate_limit: 10\n",
            profile_type="custom",
            is_active=True,
        )

        response = self.client.get(
            reverse(
                "start_multiple_scan",
                kwargs={"slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(profile_name.encode(), response.content)
        self.assertIn(b'id="start_multi_scan_execution_mode"', response.content)

    @override_settings(DEBUG=True)
    def test_build_secator_profiles_context_raises_on_unknown_category_in_debug(self):
        """Unknown SecatorProfile categories should fail fast in DEBUG."""
        SecatorProfile.objects.create(
            name=f"custom-unknown-{str(uuid.uuid4())[:8]}",
            category="unexpected_category",
            description="Unknown category profile for tests",
            opts="rate_limit: 10\n",
            profile_type="custom",
            is_active=True,
        )

        from startScan.secator.profiles import build_secator_profiles_context

        with self.assertRaises(ValueError):
            build_secator_profiles_context()


class TestDetailVulnScan(BaseTestCase):
    """Test cases for detail vulnerability scan view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_vulnerability()

    def test_detail_vuln_scan_view(self):
        """Test the detail vulnerability scan view."""
        response = self.client.get(
            reverse(
                "all_vulns",
                kwargs={
                    "slug": self.data_generator.project.slug,
                },
            )
        )
        self.assertEqual(response.status_code, 200)


class TestDeleteAllScanResults(BaseTestCase):
    """Test cases for delete all scan results view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("startScan.views.safe_rmtree")
    def test_delete_all_scan_results_view(self, mock_safe_rmtree):
        """Test the delete all scan results view."""
        response = self.client.post(
            reverse(
                "delete_all_scan_results",
                kwargs={"slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertIn("status", response_data)


class TestDeleteAllScreenshots(BaseTestCase):
    """Test cases for delete all screenshots view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("startScan.views.safe_rmtree")
    def test_delete_all_screenshots_view(self, mock_safe_rmtree):
        """Test the delete all screenshots view."""
        response = self.client.post(
            reverse(
                "delete_all_screenshots",
                kwargs={"slug": self.data_generator.project.slug},
            )
        )
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertIn("status", response_data)


class TestDeleteScans(BaseTestCase):
    """Test cases for delete scans view."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("startScan.views.safe_rmtree")
    def test_delete_scans_view(self, mock_safe_rmtree):
        """Test the delete scans view."""
        # The view expects scan IDs as POST keys (not in a list)
        data = {str(self.data_generator.scan_history.id): self.data_generator.scan_history.id}
        response = self.client.post(
            reverse(
                "delete_multiple_scans",
                kwargs={"slug": self.data_generator.project.slug},
            ),
            data,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/history", response.url)

    def test_delete_scans_view_empty_data(self):
        """Test the delete scans view with empty data."""
        response = self.client.post(
            reverse(
                "delete_multiple_scans",
                kwargs={"slug": self.data_generator.project.slug},
            ),
            {},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/history", response.url)


class TestBuildCommandHierarchy(BaseTestCase):
    """Test cases for build_command_hierarchy utility function."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_scan_activity()

    def test_build_command_hierarchy_scan_only(self):
        """Test building hierarchy with scan command only."""
        from startScan.views import build_command_hierarchy

        scan_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="scan",
            name="test_scan",
            time=timezone.now(),
        )

        hierarchy = build_command_hierarchy([scan_command])
        self.assertEqual(len(hierarchy), 1)
        self.assertEqual(hierarchy[0]["command"], scan_command)
        self.assertEqual(len(hierarchy[0]["workflows"]), 0)
        self.assertEqual(len(hierarchy[0]["tasks"]), 0)

    def test_build_command_hierarchy_scan_with_tasks(self):
        """Test building hierarchy with scan and direct tasks."""
        from startScan.views import build_command_hierarchy

        scan_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="scan",
            name="test_scan",
            time=timezone.now(),
        )

        task_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="task",
            name="test_task",
            time=timezone.now(),
        )

        hierarchy = build_command_hierarchy([scan_command, task_command])
        self.assertEqual(len(hierarchy), 1)
        self.assertEqual(hierarchy[0]["command"], scan_command)
        self.assertEqual(len(hierarchy[0]["workflows"]), 0)
        self.assertEqual(len(hierarchy[0]["tasks"]), 1)
        self.assertEqual(hierarchy[0]["tasks"][0], task_command)

    def test_build_command_hierarchy_scan_with_workflow_and_tasks(self):
        """Test building hierarchy with scan, workflow, and tasks."""
        from startScan.views import build_command_hierarchy

        scan_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="scan",
            name="test_scan",
            time=timezone.now(),
        )

        workflow_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="workflow",
            name="test_workflow",
            workflow_name="test_workflow",
            time=timezone.now(),
        )

        task_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="task",
            name="test_task",
            ancestor_id="test_workflow",
            time=timezone.now(),
        )

        hierarchy = build_command_hierarchy([scan_command, workflow_command, task_command])
        self.assertEqual(len(hierarchy), 1)
        self.assertEqual(hierarchy[0]["command"], scan_command)
        self.assertEqual(len(hierarchy[0]["workflows"]), 1)
        self.assertEqual(len(hierarchy[0]["workflows"][0]["tasks"]), 1)
        self.assertEqual(hierarchy[0]["workflows"][0]["tasks"][0], task_command)

    def test_build_command_hierarchy_empty_list(self):
        """Test building hierarchy with empty list."""
        from startScan.views import build_command_hierarchy

        hierarchy = build_command_hierarchy([])
        self.assertEqual(len(hierarchy), 0)

    def test_build_command_hierarchy_standalone_workflow(self):
        """Test building hierarchy with standalone workflow (no scan parent)."""
        from startScan.views import build_command_hierarchy

        workflow_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="workflow",
            name="test_workflow",
            workflow_name="test_workflow",
            time=timezone.now(),
        )

        task_command = Command.objects.create(
            scan_history=self.data_generator.scan_history,
            activity=self.data_generator.scan_activity,
            runner_type="task",
            name="test_task",
            ancestor_id="test_workflow",
            time=timezone.now(),
        )

        hierarchy = build_command_hierarchy([workflow_command, task_command])
        self.assertEqual(len(hierarchy), 1)
        self.assertEqual(hierarchy[0]["command"], workflow_command)
        self.assertEqual(len(hierarchy[0]["tasks"]), 1)
        self.assertEqual(hierarchy[0]["tasks"][0], task_command)


class TestScheduleFormValidation(BaseTestCase):
    """Unit tests for schedule form validation (_validate_schedule_form_post)."""

    def test_invalid_schedule_mode(self):
        """Unknown scheduled_mode should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = "invalid"
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertEqual(err, SCHEDULE_MODE_REQUIRED_MSG)

    def test_periodic_missing_frequency(self):
        """Periodic mode with missing frequency should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency_type"] = ScanSchedule.FREQUENCY_MINUTES
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertIn("interval", err.lower())

    def test_periodic_empty_frequency(self):
        """Periodic mode with empty frequency string should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency"] = "   "
        post["frequency_type"] = ScanSchedule.FREQUENCY_MINUTES
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)

    def test_periodic_invalid_frequency_not_number(self):
        """Periodic mode with non-numeric frequency should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency"] = "abc"
        post["frequency_type"] = ScanSchedule.FREQUENCY_MINUTES
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertIn("positive", err.lower())

    def test_periodic_invalid_frequency_zero(self):
        """Periodic mode with frequency 0 should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency"] = "0"
        post["frequency_type"] = ScanSchedule.FREQUENCY_MINUTES
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)

    def test_periodic_invalid_frequency_type(self):
        """Periodic mode with unknown frequency_type should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency"] = "30"
        post["frequency_type"] = "invalid_unit"
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertIn("frequency", err.lower())

    def test_periodic_valid(self):
        """Valid periodic form should return (None, normalized_mode)."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_PERIODIC
        post["frequency"] = "30"
        post["frequency_type"] = ScanSchedule.FREQUENCY_HOURS
        err, mode = _validate_schedule_form_post(post)
        self.assertIsNone(err)
        self.assertEqual(mode, ScanSchedule.SCHEDULE_MODE_PERIODIC)

    def test_clocked_missing_scheduled_time(self):
        """Clocked mode with missing scheduled_time should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_CLOCKED
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertIn("date and time", err.lower())

    def test_clocked_empty_scheduled_time(self):
        """Clocked mode with empty scheduled_time should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_CLOCKED
        post["scheduled_time"] = "   "
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)

    def test_clocked_invalid_datetime_format(self):
        """Clocked mode with invalid datetime format should return an error."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_CLOCKED
        post["scheduled_time"] = "not-a-date"
        err, _ = _validate_schedule_form_post(post)
        self.assertIsNotNone(err)
        self.assertIn("format", err.lower())

    def test_clocked_valid(self):
        """Valid clocked form should return (None, normalized_mode)."""
        post = QueryDict("", mutable=True)
        post["scheduled_mode"] = ScanSchedule.SCHEDULE_MODE_CLOCKED
        post["scheduled_time"] = "2030-01-15 14:30"
        err, mode = _validate_schedule_form_post(post)
        self.assertIsNone(err)
        self.assertEqual(mode, ScanSchedule.SCHEDULE_MODE_CLOCKED)


class TestScheduleScanView(BaseTestCase):
    """Integration tests for schedule_scan view (schedule form validation)."""

    def setUp(self):
        """Ensure workflow exists so secator kwargs build succeeds."""
        super().setUp()
        self.data_generator.create_secator_workflow()

    def test_schedule_scan_post_clocked_without_time_returns_error(self):
        """POST with clocked mode but no scheduled_time should re-render form with error."""
        url = reverse(
            "schedule_scan",
            kwargs={
                "slug": self.data_generator.project.slug,
                "host_id": self.data_generator.domain.id,
            },
        )
        post_data = {
            "execution_mode": "workflow",
            "workflow_id": str(self.data_generator.secator_workflow.id),
            "scheduled_mode": ScanSchedule.SCHEDULE_MODE_CLOCKED,
        }
        response = self.client.post(url, post_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "date and time", status_code=200)


class TestParseScheduledTimeUtc(BaseTestCase):
    """Unit tests for _parse_scheduled_time_utc helper."""

    def test_valid_returns_aware_datetime(self):
        """Valid 'YYYY-MM-DD HH:MM' string should return timezone-aware UTC datetime."""
        result = _parse_scheduled_time_utc("2030-06-15 10:30", 0)
        self.assertIsNotNone(result)
        self.assertTrue(timezone.is_aware(result))

    def test_invalid_format_returns_none(self):
        """Malformed scheduled_time should return None (no 500)."""
        self.assertIsNone(_parse_scheduled_time_utc("not-a-date", 0))
        self.assertIsNone(_parse_scheduled_time_utc("2030/06/15 10:30", 0))

    def test_empty_returns_none(self):
        """Empty or whitespace string should return None."""
        self.assertIsNone(_parse_scheduled_time_utc("", 0))
        self.assertIsNone(_parse_scheduled_time_utc("   ", 0))


class TestScanScheduleModelValidation(BaseTestCase):
    """Unit tests for ScanSchedule.clean() and get_frequency_type_display_for_value."""

    def test_periodic_without_frequency_value_raises(self):
        """Periodic schedule with null frequency_value should raise ValidationError on save."""
        schedule = self.data_generator.build_scan_schedule(
            self.data_generator.target,
            self.user,
            schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
        )
        schedule.frequency_value = None
        with self.assertRaises(ValidationError) as ctx:
            schedule.save()
        self.assertIn("frequency_value", ctx.exception.message_dict)

    def test_clocked_without_scheduled_time_raises(self):
        """Clocked schedule with null scheduled_time should raise ValidationError on save."""
        next_run = timezone.now() + timezone.timedelta(days=1)
        schedule = self.data_generator.build_scan_schedule(
            self.data_generator.target,
            self.user,
            schedule_mode=ScanSchedule.SCHEDULE_MODE_CLOCKED,
            next_run=next_run,
        )
        schedule.scheduled_time = None
        with self.assertRaises(ValidationError) as ctx:
            schedule.save()
        self.assertIn("scheduled_time", ctx.exception.message_dict)

    def test_periodic_valid_saves(self):
        """Periodic schedule with frequency_value and frequency_type should save."""
        schedule = self.data_generator.create_scan_schedule(
            self.data_generator.target,
            self.user,
            schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
        )
        self.assertIsNotNone(schedule.id)

    def test_get_frequency_type_display_for_value_singular_when_one(self):
        """Display should be singular (e.g. Minute) when frequency_value is 1."""
        schedule = self.data_generator.build_scan_schedule(
            self.data_generator.target,
            self.user,
            frequency_value=1,
        )
        self.assertEqual(schedule.get_frequency_type_display_for_value(), "Minute")

    def test_get_frequency_type_display_for_value_plural_when_not_one(self):
        """Display should be plural (e.g. Minutes) when frequency_value is not 1."""
        schedule = self.data_generator.build_scan_schedule(
            self.data_generator.target,
            self.user,
            frequency_value=2,
        )
        self.assertEqual(schedule.get_frequency_type_display_for_value(), "Minutes")

    def test_initiated_by_required_raises(self):
        """Schedule with null initiated_by should raise ValidationError on save."""
        schedule = self.data_generator.build_scan_schedule(
            self.data_generator.target,
            self.user,
            schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
        )
        schedule.initiated_by_id = None
        with self.assertRaises(ValidationError) as ctx:
            schedule.save()
        self.assertIn("initiated_by", ctx.exception.message_dict)
