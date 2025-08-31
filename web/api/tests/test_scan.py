"""
This file contains the test cases for the API views.
"""
import json
from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase

__all__ = [
    'TestScanStatus',
    'TestListScanHistory',
    'TestListActivityLogsViewSet',
    'TestListScanLogsViewSet',
    'TestStopScan',
    'TestInitiateSubTask',
    'TestListEngines',
    'TestVisualiseData',
    'TestListTechnology',
    'TestDirectoryViewSet',
    'TestListSubScans',
    'TestFetchSubscanResults',
    'TestListInterestingKeywords'
]

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
        url = reverse('api:activity-logs-list')
        response = self.client.get(url, {'activity_id': self.data_generator.scan_activity.id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertGreaterEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['command'], self.data_generator.command.command)

    def test_get_queryset_no_logs(self):
        """Test retrieving activity logs when there are none."""
        non_existent_activity_id = 9999  # An ID that doesn't exist
        url = reverse('api:activity-logs-list')
        response = self.client.get(url, {'activity_id': non_existent_activity_id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 0)

class TestListScanLogsViewSet(BaseTestCase):
    """Tests for the ListScanLogsViewSet class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_scan_logs(self):
        """Test retrieving scan logs."""
        url = reverse("api:scan-logs-list")
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)

class TestStopScan(BaseTestCase):
    """Tests for the StopScan class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("api.views.StopScan")
    def test_stop_scan(self, mock_stop_scan):
        """Test stopping a scan."""
        mock_stop_scan.return_value = True
        url = reverse("api:stop_scan")
        data = {"scan_id": self.data_generator.scan_history.id}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

class TestInitiateSubTask(BaseTestCase):
    """Tests for the InitiateSubTask class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("api.views.initiate_subscan")
    def test_initiate_subtask(self, mock_initiate_subscan):
        """Test initiating a subtask."""
        mock_initiate_subscan.return_value = True
        url = reverse("api:initiate_subscan")
        data = {
            "subdomain_ids": [self.data_generator.subdomain.id,self.data_generator.subdomain.id],
            "tasks": ['httpcrawl','osint'],
            "engine_id": "1",
        }
        response = self.client.post(url, data=json.dumps(data), content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

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
        response = self.client.get(
            url, {"scan_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)
        self.assertEqual(response.data["description"], self.data_generator.domain.name)


class TestListTechnology(BaseTestCase):
    """Test case for listing technologies."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_list_technology(self):
        """Test listing technologies for a target."""
        url = reverse("api:listTechnologies")
        response = self.client.get(url, {"target_id": self.data_generator.domain.id})
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
        self.data_generator.directory_scan.directory_files.add(
            self.data_generator.directory_file
        )
        self.data_generator.subdomain.directories.add(
            self.data_generator.directory_scan
        )

    def test_get_directory_files(self):
        """Test retrieving directory files."""
        api_url = reverse("api:directories-list")
        response = self.client.get(
            api_url, {"scan_history": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.directory_file.name
        )

    def test_get_directory_files_by_subdomain(self):
        """Test retrieving directory files by subdomain."""
        api_url = reverse("api:directories-list")
        response = self.client.get(
            api_url, {"subdomain_id": self.data_generator.subdomain.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertGreaterEqual(len(response.data["results"]), 1)
        self.assertEqual(
            response.data["results"][0]["name"], self.data_generator.directory_file.name
        )

class TestListSubScans(BaseTestCase):
    """Test case for listing subscans."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

        self.subscans = self.data_generator.create_subscan()
        # Now self.subscans is a list with the created subscan
        self.subscans[-1].celery_ids = ["test_celery_id"]
        self.subscans[-1].save()

    def test_list_subscans(self):
        """Test listing all subscans."""
        api_url = reverse("api:listSubScans")
        response = self.client.post(
            api_url, {"scan_history_id": self.data_generator.scan_history.id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertTrue(response.data["status"])
        self.assertGreaterEqual(len(response.data["results"]), 1)
        
        # Test if the created subscan is in the results  
        found_subscan = next((s for s in response.data["results"] if s["celery_ids"] and len(s["celery_ids"]) > 0 and s["celery_ids"][0] == "test_celery_id"), None)
        self.assertIsNotNone(found_subscan, "Le subscan créé n'a pas été trouvé dans les résultats")
        self.assertEqual(found_subscan["id"], self.subscans[-1].id)

class TestFetchSubscanResults(BaseTestCase):
    """Test case for fetching subscan results."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_subscan()

    def test_fetch_subscan_results(self):
        """Test fetching results of a subscan."""
        api_url = reverse("api:fetch_subscan_results")
        response = self.client.get(
            api_url, {"subscan_id": self.data_generator.subscans[-1].id}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("subscan", response.data)
        self.assertIn("result", response.data)

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
