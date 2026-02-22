"""
This file contains the test cases for the API views.
"""

import json
from unittest.mock import patch

from django.urls import reverse
from rest_framework import status

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
