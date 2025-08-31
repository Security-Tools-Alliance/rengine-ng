"""
This file contains the test cases for the startScan views and models.
"""
import json
from unittest.mock import patch
from django.urls import reverse
from django.utils import timezone
from django.test import override_settings
from utils.test_base import BaseTestCase
from utils.test_utils import MockTemplate
from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability, ScanActivity

__all__ = [
    'TestStartScanViews',
    'TestStartScanModels',
]

class TestStartScanViews(BaseTestCase):
    """Test cases for startScan views."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @override_settings(CELERY_TASK_ALWAYS_EAGER=True)
    def test_start_scan_view(self):
        """Test the start scan view."""
        data = {
            'domain_name': self.data_generator.domain.name,
            'scan_mode': self.data_generator.engine_type.id,
            'importSubdomainTextArea': "www.example.com\nmail.example.com",
            'outOfScopeSubdomainTextarea': "www.example.com\nmail.example.com",
            'filterPath': "www.example.com",
        }
        response = self.client.post(reverse('start_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'domain_id': self.data_generator.domain.id
        }), data)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/scan/{self.data_generator.project.slug}/history")
        
        scan = ScanHistory.objects.latest('id')
        self.assertEqual(scan.domain, self.data_generator.domain)
        self.assertEqual(scan.scan_type.id, self.data_generator.engine_type.id)

    def test_scan_history_view(self):
        """Test the scan history view."""
        response = self.client.get(reverse('scan_history', kwargs={
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertIn('scan_history', response.context)

    def test_detail_scan_view(self):
        """Test the detail scan view."""
        response = self.client.get(reverse('detail_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        #self.assertIn('scan_history', response.context)

    @patch('startScan.views.delete_scan')
    def test_delete_scan_view(self, mock_delete_scan):
        """Test the delete scan view."""
        mock_delete_scan.return_value = True
        response = self.client.post(reverse('delete_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'id': self.data_generator.scan_history.id,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {'status': 'true'})

    @patch('startScan.views.delete_scan')
    @MockTemplate.mock_template('base/_items/top_bar.html')
    def test_delete_scan_view_failure(self, mock_delete_scan):
        """Test the delete scan view when deletion fails."""
        mock_delete_scan.return_value = False
        response = self.client.post(reverse('delete_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'id': 999,
        }))
        self.assertEqual(response.status_code, 404)

    def test_stop_scan_view(self):
        """Test the stop scan view."""
        response = self.client.post(reverse('stop_scan', kwargs={
            'id': self.data_generator.scan_history.id,
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', json.loads(response.content))

    def test_export_subdomains_view(self):
        """Test the export subdomains view."""
        response = self.client.get(reverse('export_subdomains', kwargs={
            'scan_id': self.data_generator.scan_history.id,
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')

    def test_export_empty_subdomains_view(self):
        """Test the export subdomains view when there are no subdomains."""
        Subdomain.objects.all().delete()

        response = self.client.get(reverse('export_subdomains', kwargs={
            'scan_id': self.data_generator.scan_history.id,
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertEqual(response.content.decode(), '')

    def test_export_endpoints_view(self):
        """Test the export endpoints view."""
        response = self.client.get(reverse('export_endpoints', kwargs={
            'scan_id': self.data_generator.scan_history.id,
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')

    def test_export_empty_endpoints_view(self):
        """Test the export endpoints view when there are no endpoints."""
        # Delete all endpoints
        EndPoint.objects.all().delete()

        response = self.client.get(reverse('export_endpoints', kwargs={
            'scan_id': self.data_generator.scan_history.id,
            'slug': self.data_generator.project.slug,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertEqual(response.content.decode(), '')

class TestStartScanModels(BaseTestCase):
    """Test cases for startScan models."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_scan_history_model(self):
        """Test the ScanHistory model."""
        self.assertIsInstance(self.data_generator.scan_history, ScanHistory)
        self.assertEqual(str(self.data_generator.scan_history), self.data_generator.domain.name)

    def test_scan_history_model_with_missing_fields(self):
        """Test the ScanHistory model with missing fields."""
        minimal_scan_history = ScanHistory.objects.create(
            domain=self.data_generator.domain,
            scan_type=self.data_generator.engine_type,
            start_scan_date=timezone.now(),
        )
        self.assertIsInstance(minimal_scan_history, ScanHistory)
        self.assertEqual(str(minimal_scan_history), f"{self.data_generator.domain.name}")
        self.assertIsNone(minimal_scan_history.initiated_by)
        self.assertIsNone(minimal_scan_history.tasks)

    def test_subdomain_model(self):
        """Test the Subdomain model."""
        self.assertIsInstance(self.data_generator.subdomain, Subdomain)
        self.assertEqual(str(self.data_generator.subdomain), self.data_generator.subdomain.name)

    def test_subdomain_model_with_missing_fields(self):
        """Test the Subdomain model with missing fields."""
        minimal_subdomain = Subdomain.objects.create(
            name='test.example.com',
            target_domain=self.data_generator.domain
        )
        self.assertIsInstance(minimal_subdomain, Subdomain)
        self.assertEqual(str(minimal_subdomain), 'test.example.com')
        self.assertIsNone(minimal_subdomain.http_url)
        self.assertIsNone(minimal_subdomain.discovered_date)

    def test_endpoint_model(self):
        """Test the EndPoint model."""
        self.assertIsInstance(self.data_generator.endpoint, EndPoint)
        self.assertEqual(str(self.data_generator.endpoint), self.data_generator.endpoint.http_url)

    def test_endpoint_model_with_missing_fields(self):
        """Test the EndPoint model with missing fields."""
        minimal_endpoint = EndPoint.objects.create(
            target_domain=self.data_generator.domain,
            http_url='http://test.example.com'
        )
        self.assertIsInstance(minimal_endpoint, EndPoint)
        self.assertEqual(str(minimal_endpoint), 'http://test.example.com')
        self.assertIsNone(minimal_endpoint.response_time)
        self.assertIsNone(minimal_endpoint.discovered_date)

    def test_vulnerability_model(self):
        """Test the Vulnerability model."""
        self.assertIsInstance(self.data_generator.vulnerabilities[0], Vulnerability)
        self.assertEqual(str(self.data_generator.vulnerabilities[0].name), self.data_generator.vulnerabilities[0].name)

    def test_vulnerability_model_with_missing_fields(self):
        """Test the Vulnerability model with missing fields."""
        minimal_vulnerability = Vulnerability.objects.create(
            name='Test Vulnerability',
            target_domain=self.data_generator.domain,
            severity=1
        )
        self.assertIsInstance(minimal_vulnerability, Vulnerability)
        self.assertEqual(str(minimal_vulnerability.name), 'Test Vulnerability')
        self.assertIsNone(minimal_vulnerability.source)
        self.assertIsNone(minimal_vulnerability.description)

    def test_scan_activity_model(self):
        """Test the ScanActivity model."""
        self.assertIsInstance(self.data_generator.scan_activity, ScanActivity)
        self.assertEqual(str(self.data_generator.scan_activity), "Test Type")

    def test_scan_activity_model_with_missing_fields(self):
        """Test the ScanActivity model with missing fields."""
        minimal_scan_activity = ScanActivity.objects.create(
            scan_of=self.data_generator.scan_history,
            name="Test Type",
            time=timezone.now(),
            status=1
        )
        self.assertIsInstance(minimal_scan_activity, ScanActivity)
        self.assertEqual(minimal_scan_activity.name, "Test Type")
        self.assertIsNone(minimal_scan_activity.error_message)
