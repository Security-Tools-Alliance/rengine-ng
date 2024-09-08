"""
This file contains the test cases for the startScan views and models.
"""
import json
from unittest.mock import patch, MagicMock
from django.test import Client
from django.urls import reverse
from utils.test_base import BaseTestCase
from django.utils import timezone
from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability, ScanActivity

__all__ = [
    'TestStartScanViews',
    'TestStartScanModels'
]

class TestStartScanViews(BaseTestCase):
    """Test cases for startScan views."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()
        self.client = Client()
        self.client.force_login(self.user)
        
    def test_index_view(self):
        """Test the index view of startScan."""
        response = self.client.get(reverse('start_scan_ui', kwargs={'slug': self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertIn('scan_engines', response.context)

    def test_start_scan_view(self):
        """Test the start scan view."""
        data = {
            'domain_name': self.data_generator.domain.name,
            'scan_type': 'full',
            'engine': self.data_generator.engine.id
        }
        response = self.client.post(reverse('start_scan', kwargs={'slug': self.data_generator.project.slug}), data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', json.loads(response.content))

    def test_scan_history_view(self):
        """Test the scan history view."""
        response = self.client.get(reverse('scan_history', kwargs={'slug': self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertIn('scan_history', response.context)

    def test_detail_scan_view(self):
        """Test the detail scan view."""
        response = self.client.get(reverse('detail_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertIn('scan_history', response.context)

    @patch('startScan.views.delete_scan')
    def test_delete_scan_view(self, mock_delete_scan):
        """Test the delete scan view."""
        mock_delete_scan.return_value = True
        response = self.client.post(reverse('delete_scan', kwargs={
            'id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {'status': True})

    def test_stop_scan_view(self):
        """Test the stop scan view."""
        response = self.client.post(reverse('stop_scan', kwargs={
            'slug': self.data_generator.project.slug,
            'id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', json.loads(response.content))

    def test_export_subdomains_view(self):
        """Test the export subdomains view."""
        response = self.client.get(reverse('export_subdomains', kwargs={
            'slug': self.data_generator.project.slug,
            'scan_id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_export_endpoints_view(self):
        """Test the export endpoints view."""
        response = self.client.get(reverse('export_endpoints', kwargs={
            'slug': self.data_generator.project.slug,
            'scan_id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_export_vulnerabilities_view(self):
        """Test the export vulnerabilities view."""
        response = self.client.get(reverse('export_vulnerabilities', kwargs={
            'slug': self.data_generator.project.slug,
            'scan_id': self.data_generator.scan_history.id
        }))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

class TestStartScanModels(BaseTestCase):
    """Test cases for startScan models."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()

    def test_scan_history_model(self):
        """Test the ScanHistory model."""
        self.assertIsInstance(self.data_generator.scan_history, ScanHistory)
        self.assertEqual(str(self.data_generator.scan_history), f"{self.data_generator.domain.name}_{self.data_generator.scan_history.start_scan_date}")

    def test_subdomain_model(self):
        """Test the Subdomain model."""
        self.assertIsInstance(self.data_generator.subdomain, Subdomain)
        self.assertEqual(str(self.data_generator.subdomain), self.data_generator.subdomain.name)

    def test_endpoint_model(self):
        """Test the EndPoint model."""
        self.assertIsInstance(self.data_generator.endpoint, EndPoint)
        self.assertEqual(str(self.data_generator.endpoint), self.data_generator.endpoint.http_url)

    def test_vulnerability_model(self):
        """Test the Vulnerability model."""
        self.assertIsInstance(self.data_generator.vulnerability, Vulnerability)
        self.assertEqual(str(self.data_generator.vulnerability), self.data_generator.vulnerability.name)

    def test_scan_activity_model(self):
        """Test the ScanActivity model."""
        self.assertIsInstance(self.data_generator.scan_activity, ScanActivity)
        self.assertEqual(str(self.data_generator.scan_activity), f"{self.data_generator.scan_activity.scan_of.domain.name}_{self.data_generator.scan_activity.time}")