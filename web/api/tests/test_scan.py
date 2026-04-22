"""
This file contains the test cases for the API views.
"""

import json
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from api.serializers import ScanHistoryDatatableSerializer, SubScanDatatableSerializer
from reNgine.services.scan_finding_metrics import (
    SCAN_FINDING_IP_ALIVE_KEY,
    SCAN_FINDING_IP_COUNT_KEY,
    get_scan_finding_counts,
)
from startScan.models import (
    Domain,
    EndPoint,
    IpAddress,
    LlmAttackSurfaceAnalysis,
    ScanHistory,
    SecatorRunner,
    Subdomain,
    SubScan,
    Technology,
)
from utils.test_base import BaseTestCase


class TestScanStatus(BaseTestCase):
    """Test case for checking scan status."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_scan_status(self):
        """Test checking the status of a scan."""
        url = reverse("api:scan_status")
        response = self.client.get(url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("scans", response.data)
        self.assertIn("tasks", response.data)
        self.assertIsInstance(response.data["scans"], dict)
        self.assertIsInstance(response.data["tasks"], dict)
        if response.data["scans"]:
            self.assertIn("id", response.data["scans"]["completed"][0])
            self.assertIn("scan_status", response.data["scans"]["completed"][0])


class TestListScanHistory(BaseTestCase):
    """Test case for listing scan history."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_scan_history(self):
        """Test listing scan history for a project."""
        url = reverse("api:listScanHistory")
        response = self.client.get(url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], self.data_generator.scan_history.id)

    def test_list_scan_history_datatable_summary_ip_counts_match_get_scan_finding_counts(self) -> None:
        """DataTable summary IP fields align with get_scan_finding_counts (detail page / WebSocket)."""
        scan = self.data_generator.scan_history
        domain = self.data_generator.domain
        sub = self.data_generator.create_subdomain(scan_history=scan, domain=domain)
        ip = IpAddress.objects.create(address="192.0.2.88", version=4, alive=True)
        sub.ip_addresses.add(ip)
        expected = get_scan_finding_counts(scan.id)

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 50,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        row = next((r for r in rows if r.get("id") == scan.id), None)
        self.assertIsNotNone(row, msg="Expected scan row in DataTable response")
        summary = row.get("summary") or {}
        self.assertEqual(summary.get("ip_address_count"), expected[SCAN_FINDING_IP_COUNT_KEY])
        self.assertEqual(summary.get("ip_alive_count"), expected[SCAN_FINDING_IP_ALIVE_KEY])

    def test_list_scan_history_datatable_filter_by_scope(self):
        """DataTable filter_scope keeps only scans whose target is linked to the selected scope name(s)."""
        scan_with_scope = self.data_generator.scan_history
        scope_name = "Scope-Filter-Test-203.0.113"
        self.data_generator.create_scope(name=scope_name)
        self.data_generator.create_target()
        other_target = self.data_generator.target
        scan_no_scope = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=other_target,
        )
        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 50,
                "filter_scope": scope_name,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = {row["id"] for row in response.data.get("data", [])}
        self.assertIn(scan_with_scope.id, ids)
        self.assertNotIn(scan_no_scope.id, ids)

    def test_list_scan_history_datatable_includes_attack_surface_counts(self) -> None:
        scan = self.data_generator.scan_history
        ct = ContentType.objects.get_for_model(ScanHistory)
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=scan.id,
            llm_model="unit-scan-history-model-a",
            body_markdown="A",
        )
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=scan.id,
            llm_model="unit-scan-history-model-b",
            body_markdown="B",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 50,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data") or []
        row = next((r for r in rows if r.get("id") == scan.id), None)
        self.assertIsNotNone(row)
        self.assertTrue(row.get("attack_surface"))
        self.assertEqual(row.get("attack_surface_count"), 2)


class TestScanHistoryFilterChoices(BaseTestCase):
    """Tests for ScanHistoryFilterChoices API (filter dropdowns for scan/subscan history)."""

    def setUp(self):
        super().setUp()

    def test_returns_400_without_project(self):
        """GET without project param returns 400."""
        url = reverse("api:scanHistoryFilterChoices")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

    def test_returns_organizations_status_labels_targets_scan_engines(self):
        """GET with project returns organizations, scan_status_labels, task_status_labels, targets, scan_engines."""
        url = reverse("api:scanHistoryFilterChoices")
        response = self.client.get(url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("organizations", response.data)
        self.assertIn("scopes", response.data)
        self.assertIn("scan_status_labels", response.data)
        self.assertIn("task_status_labels", response.data)
        self.assertIn("targets", response.data)
        self.assertIn("scan_engines", response.data)
        self.assertIsInstance(response.data["organizations"], list)
        self.assertIsInstance(response.data["scopes"], list)
        self.assertIsInstance(response.data["scan_status_labels"], list)
        self.assertIsInstance(response.data["task_status_labels"], list)
        self.assertIsInstance(response.data["targets"], list)
        self.assertIsInstance(response.data["scan_engines"], list)

    def test_includes_secator_runner_types_in_scan_engines(self):
        """Scan type choices include workflow and task labels shown in scan history."""
        secator_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["httpx"],
        )
        SecatorRunner.objects.create(
            scan_history=secator_scan,
            runner_type="workflow",
            runner_name="recon-workflow",
        )
        task_only_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["httpx"],
        )
        SecatorRunner.objects.create(
            scan_history=task_only_scan,
            runner_type="task",
            runner_name="httpx",
        )

        url = reverse("api:scanHistoryFilterChoices")
        response = self.client.get(url, {"project": self.data_generator.project.slug})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("scan_engines", response.data)
        expected_workflow_label = f"{secator_scan.display_runner_type}: {secator_scan.display_scan_name}"
        self.assertIn(expected_workflow_label, response.data["scan_engines"])
        self.assertTrue(
            any(label.startswith("Task: ") for label in response.data["scan_engines"]),
            msg="Expected at least one Task label in scan_engines",
        )
        self.assertIn("scan_engine_options", response.data)
        self.assertTrue(
            any(
                isinstance(item, dict) and item.get("value") and item.get("label")
                for item in response.data["scan_engine_options"]
            )
        )


class TestScanHistoryScanTypeFiltering(BaseTestCase):
    """Tests for ListScanHistory scan type filter with Secator labels."""

    def test_filter_scan_engine_with_secator_workflow_label(self):
        secator_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["nuclei"],
        )
        SecatorRunner.objects.create(
            scan_history=secator_scan,
            runner_type="workflow",
            runner_name="my-workflow",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": f"{secator_scan.display_runner_type}: {secator_scan.display_scan_name}",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(secator_scan.id, ids)

    def test_filter_scan_engine_with_task_label(self):
        task_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["httpx"],
        )
        SecatorRunner.objects.create(
            scan_history=task_scan,
            runner_type="task",
            runner_name="httpx",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": "Task",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(task_scan.id, ids)

    def test_filter_scan_engine_with_legacy_label(self):
        legacy_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=True,
            scan_type=self.data_generator.engine_type,
            tasks=["legacy"],
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": f"Legacy: {self.data_generator.engine_type.engine_name}",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(legacy_scan.id, ids)

    def test_filter_scan_engine_with_multi_task_label(self):
        task_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["dnsx", "jswhois"],
        )
        SecatorRunner.objects.create(
            scan_history=task_scan,
            runner_type="task",
            runner_name="dnsx",
        )
        SecatorRunner.objects.create(
            scan_history=task_scan,
            runner_type="task",
            runner_name="jswhois",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": "Task: dnsx, jswhois",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(task_scan.id, ids)

    def test_filter_scan_engine_with_stable_multi_task_key(self):
        task_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["dnsx", "jswhois"],
        )
        SecatorRunner.objects.create(
            scan_history=task_scan,
            runner_type="task",
            runner_name="dnsx",
        )
        SecatorRunner.objects.create(
            scan_history=task_scan,
            runner_type="task",
            runner_name="jswhois",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": "task_names:dnsx,jswhois",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(task_scan.id, ids)

    def test_filter_scan_engine_with_single_task_key_does_not_overmatch(self):
        httpx_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["httpx"],
        )
        SecatorRunner.objects.create(
            scan_history=httpx_scan,
            runner_type="task",
            runner_name="httpx",
        )
        cariddi_scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            target=self.data_generator.target,
            is_legacy_scan=False,
            tasks=["cariddi"],
        )
        SecatorRunner.objects.create(
            scan_history=cariddi_scan,
            runner_type="task",
            runner_name="cariddi",
        )

        url = reverse("api:listScanHistory")
        response = self.client.get(
            url,
            {
                "project": self.data_generator.project.slug,
                "start": 0,
                "length": 25,
                "filter_scan_engine": "task_names:httpx",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = response.data.get("data", [])
        ids = [row.get("id") for row in rows]
        self.assertIn(httpx_scan.id, ids)
        self.assertNotIn(cariddi_scan.id, ids)


class TestScanEngineUsedDisplay(BaseTestCase):
    """Regression: unified Type: Name string for scan engine column (legacy prefix for engine-based subscans)."""

    def test_legacy_scan_history_scan_engine_used_matches_datatable_serializer(self) -> None:
        legacy_scan = self.data_generator.create_scan_history(is_legacy=True)
        self.assertTrue(legacy_scan.scan_engine_used.startswith("Legacy: "))
        self.assertIn(self.data_generator.engine_type.engine_name, legacy_scan.scan_engine_used)
        row = ScanHistoryDatatableSerializer(legacy_scan).data
        self.assertEqual(row["scan_engine_text"], legacy_scan.scan_engine_used)

    def test_legacy_subscan_datatable_includes_legacy_prefix(self) -> None:
        legacy_scan = self.data_generator.create_scan_history(is_legacy=True)
        subdomain = self.data_generator.subdomain
        subdomain.scan_history = legacy_scan
        subdomain.save(update_fields=["scan_history_id"])
        engine = self.data_generator.engine_type
        subscan = SubScan.objects.create(
            start_scan_date=timezone.now(),
            scan_history=legacy_scan,
            subdomain=subdomain,
            status=1,
            engine=engine,
        )
        row = SubScanDatatableSerializer(subscan).data
        self.assertTrue(row["scan_engine_text"].startswith("Legacy: "))
        self.assertIn(engine.engine_name, row["scan_engine_text"])

    def test_scan_engine_used_shows_legacy_when_engine_type_without_backfill_flag(self) -> None:
        """Pre-backfill rows: scan_type set but is_legacy_scan False must not show bare Secator."""
        engine = self.data_generator.engine_type
        scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=2,
            target=self.data_generator.target,
            is_legacy_scan=False,
            scan_type=engine,
            tasks=["fetch_url"],
        )
        self.assertTrue(scan.uses_legacy_engine_profile)
        self.assertTrue(scan.scan_engine_used.startswith("Legacy: "))
        self.assertIn(engine.engine_name, scan.scan_engine_used)
        row = ScanHistoryDatatableSerializer(scan).data
        self.assertEqual(row["scan_engine_text"], scan.scan_engine_used)


class TestListS3BucketsDatatable(BaseTestCase):
    """Tests for ListS3BucketsDatatable DataTables API."""

    def setUp(self):
        super().setUp()
        from startScan.models import S3Bucket

        self.bucket = S3Bucket.objects.create(
            name="test-bucket",
            region="us-east-1",
            provider="aws",
        )
        self.data_generator.scan_history.buckets.add(self.bucket)

    def test_returns_datatables_format_with_scan_history(self):
        """GET with scan_history returns draw, recordsTotal, recordsFiltered, data."""
        url = reverse("api:listS3Buckets")
        response = self.client.get(
            url,
            {"scan_history": self.data_generator.scan_history.id, "start": 0, "length": 10},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("draw", response.data)
        self.assertIn("recordsTotal", response.data)
        self.assertIn("recordsFiltered", response.data)
        self.assertIn("data", response.data)
        self.assertGreaterEqual(response.data["recordsTotal"], 1)
        self.assertGreaterEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], "test-bucket")

    def test_returns_empty_without_scan_history(self):
        """GET without scan_history returns empty data."""
        url = reverse("api:listS3Buckets")
        response = self.client.get(url, {"start": 0, "length": 10})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["recordsTotal"], 0)
        self.assertEqual(response.data["data"], [])

    def test_optional_filter_bucket_name_filters_results(self):
        """GET with filter_bucket_name returns only matching buckets."""
        from api.helpers.datatables import FILTER_PARAM_BUCKET_NAME

        url = reverse("api:listS3Buckets")
        base_params = {"scan_history": self.data_generator.scan_history.id, "start": 0, "length": 10}
        response = self.client.get(url, {**base_params, FILTER_PARAM_BUCKET_NAME: "test-bucket"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(response.data["recordsFiltered"], 1)
        self.assertEqual(response.data["data"][0]["name"], "test-bucket")
        response2 = self.client.get(url, {**base_params, FILTER_PARAM_BUCKET_NAME: "nonexistent-bucket"})
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.data["recordsFiltered"], 0)
        self.assertEqual(response2.data["data"], [])


class TestListWordlistsDatatable(BaseTestCase):
    """Tests for ListWordlistsDatatable DataTables API."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_wordlist()

    def test_returns_datatables_format(self):
        """GET with start/length returns DataTables format."""
        url = reverse("api:listWordlists")
        response = self.client.get(url, {"start": 0, "length": 10})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("draw", response.data)
        self.assertIn("recordsTotal", response.data)
        self.assertIn("recordsFiltered", response.data)
        self.assertIn("data", response.data)
        self.assertIsInstance(response.data["data"], list)

    def test_optional_filter_name_filters_results(self):
        """GET with filter_name returns only matching wordlists."""
        from api.helpers.datatables import FILTER_PARAM_NAME

        url = reverse("api:listWordlists")
        wordlist_name = self.data_generator.wordlist.name
        response = self.client.get(url, {"start": 0, "length": 10, FILTER_PARAM_NAME: wordlist_name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(response.data["recordsFiltered"], 1)
        names = [r["name"] for r in response.data["data"]]
        self.assertIn(wordlist_name, names)
        response2 = self.client.get(url, {"start": 0, "length": 10, FILTER_PARAM_NAME: "NonExistentWordlist"})
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.data["recordsFiltered"], 0)


class TestListScanEnginesDatatable(BaseTestCase):
    """Tests for ListScanEnginesDatatable DataTables API."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_engine_type()

    def test_returns_datatables_format(self):
        """GET with start/length returns DataTables format."""
        url = reverse("api:listScanEngines")
        response = self.client.get(url, {"start": 0, "length": 10})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("draw", response.data)
        self.assertIn("recordsTotal", response.data)
        self.assertIn("recordsFiltered", response.data)
        self.assertIn("data", response.data)
        self.assertIsInstance(response.data["data"], list)

    def test_optional_filter_engine_name_filters_results(self):
        """GET with filter_engine_name returns only matching engines."""
        from api.helpers.datatables import FILTER_PARAM_ENGINE_NAME

        url = reverse("api:listScanEngines")
        engine_name = self.data_generator.engine_type.engine_name
        response = self.client.get(url, {"start": 0, "length": 10, FILTER_PARAM_ENGINE_NAME: engine_name})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(response.data["recordsFiltered"], 1)
        names = [r["engine_name"] for r in response.data["data"]]
        self.assertIn(engine_name, names)
        response2 = self.client.get(url, {"start": 0, "length": 10, FILTER_PARAM_ENGINE_NAME: "NonExistentEngine"})
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.data["recordsFiltered"], 0)


class TestListActivityLogsViewSet(BaseTestCase):
    """Tests for the ListActivityLogsViewSet."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_scan_history()
        self.data_generator.create_scan_activity()
        self.data_generator.create_command()

    def test_get_queryset(self):
        """Test retrieving activity logs."""
        url = reverse("api:activity-logs-list")
        response = self.client.get(url, {"activity_id": self.data_generator.scan_activity.id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["command"], self.data_generator.command.command)

    def test_get_queryset_no_logs(self):
        """Test retrieving activity logs when there are none."""
        non_existent_activity_id = 9999  # An ID that doesn't exist
        url = reverse("api:activity-logs-list")
        response = self.client.get(url, {"activity_id": non_existent_activity_id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 0)


class TestListScanLogsViewSet(BaseTestCase):
    """Tests for the ListScanLogsViewSet class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_scan_logs(self):
        """Test retrieving scan logs."""
        url = reverse("api:scan-logs-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)


class TestStopScan(BaseTestCase):
    """Tests for the StopScan class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_subscan()

    @patch("reNgine.secator.control.SecatorScanController")
    def test_stop_scan(self, mock_controller_class):
        """Test stopping a scan."""
        mock_controller = mock_controller_class.return_value
        mock_controller.stop_scan.return_value = True
        url = reverse("api:stop_scan")
        data = {"scan_id": self.data_generator.scan_history.id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_controller_class.assert_called_once_with(self.data_generator.scan_history.id)
        mock_controller.stop_scan.assert_called_once()

    @patch("reNgine.secator.control.SecatorScanController")
    def test_stop_subscan(self, mock_controller_class):
        """Test stopping a subscan."""
        mock_controller = mock_controller_class.return_value
        mock_controller.stop_subscan.return_value = True
        url = reverse("api:stop_scan")
        subscan_id = self.data_generator.subscans[-1].id if self.data_generator.subscans else 1
        data = {"subscan_id": subscan_id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_controller.stop_subscan.assert_called_once_with(subscan_id)

    @patch("reNgine.secator.control.SecatorScanController")
    def test_stop_scan_failure(self, mock_controller_class):
        """Test stopping a scan when it fails."""
        mock_controller = mock_controller_class.return_value
        mock_controller.stop_scan.return_value = False
        url = reverse("api:stop_scan")
        data = {"scan_id": self.data_generator.scan_history.id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])


class TestStopActivity(BaseTestCase):
    """Tests for the StopActivity class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_scan_activity()

    @patch("reNgine.secator.control.SecatorScanController")
    def test_stop_activity_success(self, mock_controller_class):
        """Test stopping an activity successfully."""
        mock_controller = mock_controller_class.return_value
        mock_controller.stop_activity.return_value = True
        url = reverse("api:stop_activity")
        data = {"activity_id": self.data_generator.scan_activity.id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_controller_class.assert_called_once_with(self.data_generator.scan_history.id)
        mock_controller.stop_activity.assert_called_once_with(self.data_generator.scan_activity.id)

    @patch("reNgine.secator.control.SecatorScanController")
    def test_stop_activity_failure(self, mock_controller_class):
        """Test stopping an activity when it fails."""
        mock_controller = mock_controller_class.return_value
        mock_controller.stop_activity.return_value = False
        url = reverse("api:stop_activity")
        data = {"activity_id": self.data_generator.scan_activity.id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["status"])

    def test_stop_activity_missing_id(self):
        """Test stopping an activity without providing activity_id."""
        url = reverse("api:stop_activity")
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])

    def test_stop_activity_not_found(self):
        """Test stopping an activity that doesn't exist."""
        url = reverse("api:stop_activity")
        data = {"activity_id": 99999}
        response = self.client.post(url, data)
        # The API returns 400 when activity is not found (get_object_or_404 raises Http404 which is caught)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])


# TestInitiateSubTask - Secator subscan (workflow/scan/tasks) with optional selected_targets_per_task


class TestInitiateSubTask(BaseTestCase):
    """Test InitiateSubTask API with tasks mode and selected_targets_per_task."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_secator_task()

    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_initiate_subtask_tasks_mode_with_selected_targets_per_task(self, mock_scan_repo_cls, mock_start_scan):
        """When selected_targets_per_task is provided, one shared ScanHistory for all tasks."""
        scan_history = self.data_generator.scan_history
        shared_scan_id = scan_history.id
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_start_scan.return_value = {"status": True, "scan_id": shared_scan_id}

        subdomain = self.data_generator.subdomain
        task_type = self.data_generator.secator_task.task_type
        url = reverse("api:initiate_subscan")
        data = {
            "subdomain_ids": [subdomain.id],
            "task_names": [task_type],
            "selected_targets_per_task": {
                task_type: [self.data_generator.domain.name, subdomain.name],
            },
        }

        response = self.client.post(url, data=json.dumps(data), content_type="application/json")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["scan_id"], shared_scan_id)
        self.assertEqual(response.data["message"], "Subscans initiated for 1 task(s)")
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["task_type"], task_type)
        self.assertEqual(response.data["results"][0]["scan_id"], shared_scan_id)

        mock_start_scan.assert_called_once()
        call_kwargs = mock_start_scan.call_args[1]
        self.assertEqual(call_kwargs["execution_mode"], "tasks")
        self.assertEqual(call_kwargs["task_ids"], [self.data_generator.secator_task.id])
        self.assertEqual(call_kwargs["scan_history_id"], shared_scan_id)
        self.assertEqual(
            call_kwargs["targets_override"],
            [self.data_generator.domain.name, subdomain.name],
        )

    @patch("api.views.start_secator_scan")
    def test_initiate_subtask_workflow_mode_with_scan_history_id_creates_subscans(self, mock_start_scan):
        """When workflow_id and scan_history_id are provided, one SubScan per subdomain and start_secator_scan receives scan_history_id and subscan_id."""
        self.data_generator.create_secator_workflow()
        scan = self.data_generator.scan_history
        subdomain = self.data_generator.subdomain
        mock_start_scan.return_value = {"status": True, "scan_id": scan.id}

        url = reverse("api:initiate_subscan")
        data = {
            "subdomain_ids": [subdomain.id],
            "workflow_id": self.data_generator.secator_workflow.id,
            "scan_history_id": scan.id,
        }

        response = self.client.post(url, data=json.dumps(data), content_type="application/json")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["status"])
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["status"], "success")

        mock_start_scan.assert_called_once()
        call_kwargs = mock_start_scan.call_args[1]
        self.assertEqual(call_kwargs["execution_mode"], "workflow")
        self.assertEqual(call_kwargs["scan_history_id"], scan.id)
        self.assertIsNotNone(call_kwargs["subscan_id"])

        from startScan.models import SubScan

        subscans = list(
            SubScan.objects.filter(
                scan_history=scan, subdomain=subdomain, type=self.data_generator.secator_workflow.name
            )
        )
        self.assertGreaterEqual(len(subscans), 1)
        created_ids = [s.id for s in subscans]
        self.assertIn(call_kwargs["subscan_id"], created_ids)

    @patch("api.views.start_secator_scan")
    def test_initiate_subtask_accepts_subdomains_same_target_different_domains(self, mock_start_scan):
        """When subdomain_ids span multiple domains but same target, POST returns 200."""
        self.data_generator.create_secator_workflow()
        target = self.data_generator.target
        subdomain1 = self.data_generator.subdomain
        scan2 = ScanHistory.objects.create(
            target=target,
            start_scan_date=timezone.now(),
            scan_status=2,
            is_legacy_scan=False,
            tasks=["subdomain_discovery"],
        )
        domain2 = Domain.objects.create(
            name="other-example.com",
            insert_date=timezone.now(),
            scan_history=scan2,
        )
        subdomain2 = Subdomain.objects.create(
            name="other.admin.example.com",
            domain=domain2,
            scan_history=scan2,
        )
        mock_start_scan.return_value = {"status": True, "scan_id": scan2.id}

        url = reverse("api:initiate_subscan")
        data = {
            "subdomain_ids": [subdomain1.id, subdomain2.id],
            "workflow_id": self.data_generator.secator_workflow.id,
            "scan_history_id": self.data_generator.scan_history.id,
        }

        response = self.client.post(url, data=json.dumps(data), content_type="application/json")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["status"])
        self.assertEqual(len(response.data["results"]), 2)

    def test_initiate_subtask_subdomains_different_targets_returns_400(self):
        """When subdomain_ids belong to more than one target, POST returns 400 with same target message."""
        self.data_generator.create_secator_workflow()
        first_subdomain_id = self.data_generator.subdomain.id
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        subdomain2 = self.data_generator.create_subdomain(name="sub.target2.com")

        url = reverse("api:initiate_subscan")
        data = {
            "subdomain_ids": [first_subdomain_id, subdomain2.id],
            "workflow_id": self.data_generator.secator_workflow.id,
        }

        response = self.client.post(url, data=json.dumps(data), content_type="application/json")

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data["status"])
        self.assertIn("error", response.data)
        self.assertIn("same target", response.data["error"].lower())


class TestListEngines(BaseTestCase):
    """Test case for listing engines."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_engines(self):
        """Test listing all available engines."""
        url = reverse("api:listEngines")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("engines", response.data)
        self.assertGreaterEqual(len(response.data["engines"]), 1)


class TestVisualiseData(BaseTestCase):
    """Test case for visualising scan data."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_visualise_data(self):
        """Test retrieving visualisation data for a scan."""
        url = reverse("api:queryAllScanResultVisualise")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data["description"], self.data_generator.target.value)


class TestListTechnology(BaseTestCase):
    """Test case for listing technologies."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_technology(self):
        """Test listing technologies for a target."""
        url = reverse("api:listTechnologies")
        response = self.client.get(url, {"target_id": self.data_generator.target.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("technologies", response.data)
        self.assertGreaterEqual(len(response.data["technologies"]), 1)
        self.assertEqual(
            response.data["technologies"][0]["name"],
            self.data_generator.technology.name,
        )

    def test_list_technology_filtered_by_scan_id(self):
        """ListTechnologies with scan_id returns only technologies for that scan."""
        scan1 = self.data_generator.scan_history
        scan2 = self.data_generator.create_scan_history()
        domain2 = self.data_generator.create_domain(scan_history=scan2)
        sub2 = self.data_generator.create_subdomain(name="sub2.example.com", scan_history=scan2, domain=domain2)
        tech2 = Technology.objects.create(name="Other Technology")
        sub2.technologies.add(tech2)

        url = reverse("api:listTechnologies")
        response1 = self.client.get(url, {"scan_id": scan1.id})
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        tech_names_1 = {t["name"] for t in response1.data["technologies"]}
        self.assertIn(self.data_generator.technology.name, tech_names_1)
        self.assertNotIn("Other Technology", tech_names_1)

        response2 = self.client.get(url, {"scan_id": scan2.id})
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        tech_names_2 = {t["name"] for t in response2.data["technologies"]}
        self.assertIn("Other Technology", tech_names_2)
        self.assertNotIn(self.data_generator.technology.name, tech_names_2)

    def test_list_technology_includes_endpoint_linked_non_legacy_count(self):
        """Tech present on both links for one subdomain is counted once."""
        scan = self.data_generator.scan_history
        domain = self.data_generator.domain
        subdomain = self.data_generator.create_subdomain(
            name="stack.example.com",
            scan_history=scan,
            domain=domain,
        )
        endpoint = EndPoint.objects.create(
            scan_history=scan,
            domain=domain,
            subdomain=subdomain,
            http_url="https://stack.example.com/",
            discovered_date=timezone.now(),
        )
        endpoint_only_tech = Technology.objects.create(
            scan_history=scan,
            name="endpoint-only-tech",
        )
        endpoint.techs.add(endpoint_only_tech)
        subdomain.technologies.add(endpoint_only_tech)

        url = reverse("api:listTechnologies")
        response = self.client.get(url, {"scan_id": scan.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        by_name = {row["name"]: int(row["count"]) for row in response.data["technologies"]}
        self.assertIn("endpoint-only-tech", by_name)
        self.assertEqual(by_name["endpoint-only-tech"], 1)


class TestDirectoryViewSet(BaseTestCase):
    """Tests for the Directory ViewSet API."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_directory_scan()
        self.data_generator.create_directory_file()
        self.data_generator.directory_scan.directory_files.add(self.data_generator.directory_file)
        self.data_generator.subdomain.directories.add(self.data_generator.directory_scan)

    def test_get_directory_files(self):
        """Test retrieving directory files."""
        api_url = reverse("api:directories-list")
        response = self.client.get(api_url, {"scan_history": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.directory_file.name)

    def test_get_directory_files_by_subdomain(self):
        """Test retrieving directory files by subdomain."""
        api_url = reverse("api:directories-list")
        response = self.client.get(api_url, {"subdomain_id": self.data_generator.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.data_generator.directory_file.name)

    def test_list_directories_requires_scan_or_subdomain(self):
        """List without scan_history or subdomain_id returns 400."""
        api_url = reverse("api:directories-list")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status", True))
        self.assertIn("message", response.data)


class TestListSubScans(BaseTestCase):
    """Test case for listing subscans."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.subscans = self.data_generator.create_subscan()

    def test_list_subscans(self):
        """Test listing all subscans."""
        api_url = reverse("api:listSubScans")
        response = self.client.post(api_url, {"scan_history_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("total_count", response.data)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertGreaterEqual(response.data["total_count"], len(response.data["results"]))

        found_subscan = next(
            (s for s in response.data["results"] if s["id"] == self.subscans[-1].id),
            None,
        )
        self.assertIsNotNone(found_subscan, "Created subscan not found in results")
        self.assertEqual(found_subscan["id"], self.subscans[-1].id)

    def test_list_subscans_respects_limit_and_returns_total_count(self):
        """Test that limit truncates results and total_count reflects full count."""
        api_url = reverse("api:listSubScans")
        response = self.client.post(
            api_url,
            {"scan_history_id": self.data_generator.scan_history.id, "limit": 1},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("total_count", response.data)
        self.assertLessEqual(len(response.data.get("results", [])), 1)
        self.assertGreaterEqual(response.data["total_count"], len(response.data.get("results", [])))

    def test_list_subscans_by_target_id(self):
        """Test listing subscans filtered by target_id returns same scan history subscans."""
        self.data_generator.scan_history.target = self.data_generator.target
        self.data_generator.scan_history.save(update_fields=["target_id"])
        api_url = reverse("api:listSubScans")
        response = self.client.post(
            api_url,
            {"target_id": self.data_generator.target.id},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIn("results", response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertGreaterEqual(response.data["total_count"], 1)


class TestFetchSubscanResults(BaseTestCase):
    """Test case for fetching subscan results."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_subscan()

    def test_fetch_subscan_results(self):
        """Test fetching results of a subscan."""
        api_url = reverse("api:fetch_subscan_results")
        response = self.client.get(api_url, {"subscan_id": self.data_generator.subscans[-1].id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subscan", response.data)
        self.assertIn("result", response.data)
        self.assertIsInstance(response.data["result"], list)

    def test_fetch_subscan_results_invalid_id(self):
        """Test fetching results with non-existent subscan_id returns error."""
        api_url = reverse("api:fetch_subscan_results")
        response = self.client.get(api_url, {"subscan_id": 999999})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data.get("status", True))
        self.assertIn("error", response.data)

    def test_fetch_subscan_results_secator_type_returns_list(self):
        """Test fetching results for Secator task type returns result list and engine fallback."""
        subscan = self.data_generator.subscans[-1]
        subscan.type = "nuclei"
        subscan.save()
        api_url = reverse("api:fetch_subscan_results")
        response = self.client.get(api_url, {"subscan_id": subscan.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subscan", response.data)
        self.assertIn("result", response.data)
        self.assertIsInstance(response.data["result"], list)
        self.assertEqual(response.data["subscan"]["type"], "nuclei")
        self.assertIn("engine", response.data["subscan"])
        self.assertEqual(response.data["subscan"]["engine"], "nuclei")


class TestListInterestingKeywords(BaseTestCase):
    """Tests for listing interesting keywords."""

    @patch("api.views.get_lookup_keywords")
    def test_list_interesting_keywords(self, mock_get_keywords):
        """Test listing interesting keywords."""
        mock_get_keywords.return_value = ["keyword1", "keyword2"]
        api_url = reverse("api:listInterestingKeywords")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, ["keyword1", "keyword2"])
