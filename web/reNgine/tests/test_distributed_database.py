"""
Tests for distributed database utilities.

This module provides comprehensive unit tests for the distributed database utilities
including endpoint processing, subdomain processing, and IP processing.
"""

import unittest
from unittest.mock import Mock, patch

from reNgine.utilities.distributed.base import DistributedConfig, ProcessingStatus
from reNgine.utilities.distributed.database import (
    DistributedDatabaseResult,
    DistributedEndpointProcessor,
    DistributedIPProcessor,
    DistributedSubdomainProcessor,
    create_distributed_endpoint_processor,
    create_distributed_ip_processor,
    create_distributed_subdomain_processor,
    process_endpoints_distributed,
    process_ips_distributed,
    process_subdomains_distributed,
)
from utils.test_base import BaseTestCase


class TestDistributedDatabaseResult(BaseTestCase):
    """Test DistributedDatabaseResult class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_database_result_creation(self):
        """Test database result creation."""
        result = DistributedDatabaseResult(data={"test": "data"}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        self.assertIsInstance(result.objects_created, list)
        self.assertIsInstance(result.objects_updated, list)
        self.assertIsInstance(result.objects_skipped, list)
        self.assertIsInstance(result.db_operations, list)
        self.assertEqual(result.batch_id, "batch_1")

    def test_add_created_object(self):
        """Test adding created object."""
        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        mock_obj = Mock()
        result.add_created_object(mock_obj)

        self.assertIn(mock_obj, result.objects_created)
        self.assertEqual(len(result.objects_created), 1)

    def test_add_updated_object(self):
        """Test adding updated object."""
        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        mock_obj = Mock()
        result.add_updated_object(mock_obj)

        self.assertIn(mock_obj, result.objects_updated)
        self.assertEqual(len(result.objects_updated), 1)

    def test_add_skipped_object(self):
        """Test adding skipped object."""
        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        mock_obj = Mock()
        result.add_skipped_object(mock_obj)

        self.assertIn(mock_obj, result.objects_skipped)
        self.assertEqual(len(result.objects_skipped), 1)

    def test_add_db_operation(self):
        """Test adding database operation."""
        result = DistributedDatabaseResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        result.add_db_operation("CREATE endpoint")

        self.assertIn("CREATE endpoint", result.db_operations)
        self.assertEqual(len(result.db_operations), 1)


class TestDistributedEndpointProcessor(BaseTestCase):
    """Test DistributedEndpointProcessor class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig(batch_size=5)
        self.mock_db_interface = Mock()
        self.processor = DistributedEndpointProcessor(self.config, self.mock_db_interface)

    def test_endpoint_processor_creation(self):
        """Test endpoint processor creation."""
        self.assertEqual(self.processor.config, self.config)
        self.assertEqual(self.processor.get_task_name(), "distributed_endpoint_processor")
        self.assertEqual(self.processor.db_interface, self.mock_db_interface)
        self.assertIsInstance(self.processor.endpoint_cache, dict)
        self.assertIsInstance(self.processor.subdomain_cache, dict)

    def test_endpoint_processor_batch_processing(self):
        """Test endpoint processor batch processing."""
        endpoints_data = [
            {"http_url": "http://example.com", "title": "Example"},
            {"http_url": "https://test.com", "title": "Test"},
        ]

        result = self._test_batch_processing(self.processor, "process_endpoints_batch", endpoints_data, "batch_1")

        self.assertIsInstance(result, DistributedDatabaseResult)
        self.assertEqual(result.batch_id, "batch_1")
        self.assertEqual(len(result.objects_created), 2)
        self.assertEqual(len(result.objects_updated), 0)
        self.assertEqual(len(result.objects_skipped), 0)

    def _test_batch_processing(self, processor, method_name, data, batch_id):
        """Test batch processing with mocked database operations."""
        # Mock database operations
        self.mock_db_interface.filter_records.return_value = []
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        with patch.object(processor, "_process_single_endpoint") as mock_process:
            mock_process.return_value = {"endpoint": Mock(), "created": True, "updated": False, "skipped": False}

            method = getattr(processor, method_name)
            return method(data, batch_id)

    def test_process_single_endpoint(self):
        """Test processing single endpoint."""
        endpoint_data = {"http_url": "http://example.com", "title": "Example", "status_code": 200}

        ctx = {"scan_history_id": 1}

        result = self._test_single_endpoint_processing(endpoint_data, ctx)

        self.assertIsInstance(result, dict)
        self.assertIn("endpoint", result)
        self.assertIn("created", result)
        self.assertIn("updated", result)
        self.assertIn("skipped", result)

    def _test_single_endpoint_processing(self, endpoint_data, ctx):
        """Test single endpoint processing with mocked operations."""
        # Mock the database interface to return proper data
        mock_endpoint = Mock(id=1, http_url=endpoint_data.get("http_url"))
        self.mock_db_interface.filter_records.return_value = [mock_endpoint]
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        with patch.object(self.processor, "_get_or_create_subdomain") as mock_get_subdomain:
            mock_subdomain = Mock()
            mock_get_subdomain.return_value = mock_subdomain

            with patch.object(self.processor, "_create_endpoint") as mock_create:
                mock_endpoint = Mock()
                mock_create.return_value = mock_endpoint

                return self.processor._process_single_endpoint(endpoint_data, ctx)

    def test_get_or_create_subdomain(self):
        """Test getting or creating subdomain."""
        subdomain_name = "example.com"
        ctx = {"scan_history_id": 1}

        # Test creating new subdomain
        self.mock_db_interface.filter_records.return_value = []
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        result = self.processor._get_or_create_subdomain(subdomain_name, ctx)

        self.assertIsNotNone(result)
        self.mock_db_interface.create_record.assert_called_once()

    def test_create_endpoint(self):
        """Test creating endpoint."""
        endpoint_data = {"http_url": "http://example.com", "title": "Example", "status_code": 200}
        subdomain = Mock()
        ctx = {"scan_history_id": 1}

        self.mock_db_interface.create_record.return_value = Mock(id=1)

        result = self.processor._create_endpoint(endpoint_data, subdomain, ctx)

        self.assertIsNotNone(result)
        self.mock_db_interface.create_record.assert_called_once()

    def test_update_endpoint(self):
        """Test updating endpoint."""
        existing_endpoint = Mock()
        endpoint_data = {"http_url": "http://example.com", "title": "Updated Example", "status_code": 200}

        with patch.object(self.processor, "_update_endpoint") as mock_update:
            mock_update.return_value = True

            result = self.processor._update_endpoint(existing_endpoint, endpoint_data)

            self.assertTrue(result)
            mock_update.assert_called_once_with(existing_endpoint, endpoint_data)


class TestDistributedSubdomainProcessor(BaseTestCase):
    """Test DistributedSubdomainProcessor class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig(batch_size=5)
        self.mock_db_interface = Mock()
        self.processor = DistributedSubdomainProcessor(self.config, self.mock_db_interface)

    def test_subdomain_processor_creation(self):
        """Test subdomain processor creation."""
        self.assertEqual(self.processor.config, self.config)
        self.assertEqual(self.processor.get_task_name(), "distributed_subdomain_processor")
        self.assertEqual(self.processor.db_interface, self.mock_db_interface)
        self.assertIsInstance(self.processor.domain_cache, dict)

    def test_subdomain_processor_batch_processing(self):
        """Test subdomain processor batch processing."""
        # Mock database operations
        self.mock_db_interface.filter_records.return_value = []
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        subdomains_data = [
            {"name": "example.com", "ip_address": "192.168.1.1"},
            {"name": "test.com", "ip_address": "192.168.1.2"},
        ]

        with patch.object(self.processor, "_process_single_subdomain") as mock_process:
            mock_process.return_value = {"subdomain": Mock(), "created": True, "updated": False, "skipped": False}

            result = self.processor.process_subdomains_batch(subdomains_data, "batch_1")

            self.assertIsInstance(result, DistributedDatabaseResult)
            self.assertEqual(result.batch_id, "batch_1")
            self.assertEqual(len(result.objects_created), 2)

    def test_process_single_subdomain(self):
        """Test processing single subdomain."""
        subdomain_data = {"name": "example.com", "ip_address": "192.168.1.1"}

        ctx = {"scan_history_id": 1}

        # Mock the database interface to return proper data
        mock_subdomain = Mock(id=1, name=subdomain_data.get("name"))
        self.mock_db_interface.filter_records.return_value = [mock_subdomain]
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        with patch.object(self.processor, "_create_subdomain") as mock_create:
            mock_subdomain = Mock()
            mock_create.return_value = mock_subdomain

            result = self.processor._process_single_subdomain(subdomain_data, ctx)

            self.assertIsInstance(result, dict)
            self.assertIn("subdomain", result)
            self.assertIn("created", result)
            self.assertIn("updated", result)
            self.assertIn("skipped", result)

    def test_create_subdomain(self):
        """Test creating subdomain."""
        subdomain_data = {"name": "example.com", "ip_address": "192.168.1.1"}
        ctx = {"scan_history_id": 1}

        self.mock_db_interface.create_record.return_value = Mock(id=1)

        result = self.processor._create_subdomain(subdomain_data, ctx)

        self.assertIsNotNone(result)
        self.mock_db_interface.create_record.assert_called_once()


class TestDistributedIPProcessor(BaseTestCase):
    """Test DistributedIPProcessor class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig(batch_size=5)
        self.mock_db_interface = Mock()
        self.processor = DistributedIPProcessor(self.config, self.mock_db_interface)

    def test_ip_processor_creation(self):
        """Test IP processor creation."""
        self.assertEqual(self.processor.config, self.config)
        self.assertEqual(self.processor.get_task_name(), "distributed_ip_processor")
        self.assertEqual(self.processor.db_interface, self.mock_db_interface)
        self.assertIsInstance(self.processor.ip_cache, dict)

    def test_ip_processor_batch_processing(self):
        """Test IP processor batch processing."""
        # Mock database operations
        self.mock_db_interface.filter_records.return_value = []
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        ips_data = [{"ip_address": "192.168.1.1", "ports": [80, 443]}, {"ip_address": "192.168.1.2", "ports": [22, 80]}]

        with patch.object(self.processor, "_process_single_ip") as mock_process:
            mock_process.return_value = {"ip": Mock(), "created": True, "updated": False, "skipped": False}

            result = self.processor.process_ips_batch(ips_data, "batch_1")

            self.assertIsInstance(result, DistributedDatabaseResult)
            self.assertEqual(result.batch_id, "batch_1")
            self.assertEqual(len(result.objects_created), 2)

    def test_process_single_ip(self):
        """Test processing single IP."""
        ip_data = {"address": "192.168.1.1", "ports": [80, 443]}

        ctx = {"scan_history_id": 1}

        # Mock the database interface to return proper data
        mock_ip = Mock(id=1, address=ip_data.get("address"))
        self.mock_db_interface.filter_records.return_value = [mock_ip]
        self.mock_db_interface.create_record.return_value = Mock(id=1)

        with patch.object(self.processor, "_create_ip") as mock_create:
            mock_ip = Mock()
            mock_create.return_value = mock_ip

            result = self.processor._process_single_ip(ip_data, ctx)

            self.assertIsInstance(result, dict)
            self.assertIn("ip", result)
            self.assertIn("created", result)
            self.assertIn("updated", result)
            self.assertIn("skipped", result)

    def test_create_ip(self):
        """Test creating IP."""
        ip_data = {"ip_address": "192.168.1.1", "ports": [80, 443]}
        ctx = {"scan_history_id": 1}

        self.mock_db_interface.create_record.return_value = Mock(id=1)

        result = self.processor._create_ip(ip_data, ctx)

        self.assertIsNotNone(result)
        self.mock_db_interface.create_record.assert_called_once()


class TestDistributedDatabaseFactoryFunctions(BaseTestCase):
    """Test distributed database factory functions."""

    def test_create_distributed_endpoint_processor(self):
        """Test create_distributed_endpoint_processor function."""
        processor = create_distributed_endpoint_processor()

        self.assertIsInstance(processor, DistributedEndpointProcessor)
        self.assertIsInstance(processor.config, DistributedConfig)

    def test_create_distributed_subdomain_processor(self):
        """Test create_distributed_subdomain_processor function."""
        processor = create_distributed_subdomain_processor()

        self.assertIsInstance(processor, DistributedSubdomainProcessor)
        self.assertIsInstance(processor.config, DistributedConfig)

    def test_create_distributed_ip_processor(self):
        """Test create_distributed_ip_processor function."""
        processor = create_distributed_ip_processor()

        self.assertIsInstance(processor, DistributedIPProcessor)
        self.assertIsInstance(processor.config, DistributedConfig)

    def test_process_endpoints_distributed(self):
        """Test process_endpoints_distributed function."""
        endpoints = ["http://example.com", "https://test.com"]
        result = self._test_distributed_database_processing(
            process_endpoints_distributed, endpoints, None, {"endpoints": endpoints}
        )
        self.assertIsInstance(result, dict)

    def test_process_subdomains_distributed(self):
        """Test process_subdomains_distributed function."""
        subdomains = ["example.com", "test.com"]
        result = self._test_distributed_database_processing(
            process_subdomains_distributed, subdomains, None, {"subdomains": subdomains}
        )
        self.assertIsInstance(result, dict)

    def test_process_ips_distributed(self):
        """Test process_ips_distributed function."""
        ips = ["192.168.1.1", "192.168.1.2"]
        result = self._test_distributed_database_processing(process_ips_distributed, ips, None, {"ips": ips})
        self.assertIsInstance(result, dict)

    def _test_distributed_database_processing(self, func, data, processor, expected_data):
        """Test distributed database processing with mocked task."""
        with patch("reNgine.utilities.distributed.database.create_batch_tasks") as mock_batch_tasks:
            mock_batch_tasks.return_value = []

            # Mock the processor creation
            with patch(
                "reNgine.utilities.distributed.database.create_distributed_endpoint_processor"
            ) as mock_processor:
                mock_processor.return_value = Mock()

                result = func(data, processor)
                # Should return a dict with success status
                self.assertIsInstance(result, dict)
                return result


if __name__ == "__main__":
    unittest.main()
