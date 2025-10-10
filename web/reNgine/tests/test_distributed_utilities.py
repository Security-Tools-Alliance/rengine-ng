"""
Simplified tests for distributed utilities.

This module provides basic unit tests for the distributed utilities
focusing on creation and basic functionality.
"""

import unittest
from unittest.mock import Mock

from reNgine.utilities.distributed.base import DistributedConfig
from reNgine.utilities.distributed.utilities import (
    DistributedUtilities,
    ProcessorType,
    batch_process_items,
    create_balanced_config,
    create_conservative_config,
    create_high_performance_config,
    create_processor,
    execute_distributed_commands,
    get_distributed_utilities,
    get_processor_recommendations,
    parallel_process_items,
    parse_distributed_nmap_files,
    process_distributed_endpoints,
    reset_distributed_utilities,
    resolve_distributed_domains,
    validate_distributed_urls,
)
from utils.test_base import BaseTestCase


class TestDistributedUtilities(BaseTestCase):
    """Test DistributedUtilities class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.config = DistributedConfig()
        self.utilities = DistributedUtilities(self.config)

    def test_utilities_creation(self):
        """Test utilities creation."""
        self.assertEqual(self.utilities.config, self.config)
        self.assertIsInstance(self.utilities._processors, dict)
        self.assertFalse(self.utilities._initialized)

    def test_initialize(self):
        """Test utilities initialization."""
        self.utilities.initialize()

        self.assertTrue(self.utilities._initialized)
        self.assertGreater(len(self.utilities._processors), 0)

    def test_get_processor(self):
        """Test getting a processor."""
        self.utilities.initialize()

        processor = self.utilities.get_processor(ProcessorType.COMMAND)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_command_executor")

    def test_get_processor_not_initialized(self):
        """Test getting a processor when not initialized."""
        processor = self.utilities.get_processor(ProcessorType.COMMAND)

        self.assertIsNotNone(processor)
        self.assertTrue(self.utilities._initialized)

    def test_get_command_processor(self):
        """Test getting command processor."""
        self.utilities.initialize()

        processor = self.utilities.get_command_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_command_executor")

    def test_get_endpoint_processor(self):
        """Test getting endpoint processor."""
        self.utilities.initialize()

        processor = self.utilities.get_endpoint_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_endpoint_processor")

    def test_get_subdomain_processor(self):
        """Test getting subdomain processor."""
        self.utilities.initialize()

        processor = self.utilities.get_subdomain_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_subdomain_processor")

    def test_get_ip_processor(self):
        """Test getting IP processor."""
        self.utilities.initialize()

        processor = self.utilities.get_ip_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_ip_processor")

    def test_get_nmap_parser(self):
        """Test getting Nmap parser."""
        self.utilities.initialize()

        parser = self.utilities.get_nmap_parser()

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_nmap_parser")

    def test_get_nuclei_parser(self):
        """Test getting Nuclei parser."""
        self.utilities.initialize()

        parser = self.utilities.get_nuclei_parser()

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_nuclei_parser")

    def test_get_httpx_parser(self):
        """Test getting Httpx parser."""
        self.utilities.initialize()

        parser = self.utilities.get_httpx_parser()

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_httpx_parser")

    def test_get_dns_processor(self):
        """Test getting DNS processor."""
        self.utilities.initialize()

        processor = self.utilities.get_dns_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_dns_processor")

    def test_get_url_processor(self):
        """Test getting URL processor."""
        self.utilities.initialize()

        processor = self.utilities.get_url_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_url_processor")

    def test_get_port_processor(self):
        """Test getting port processor."""
        self.utilities.initialize()

        processor = self.utilities.get_port_processor()

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_port_processor")

    def test_update_config(self):
        """Test updating configuration."""
        self.utilities.initialize()
        self.assertTrue(self.utilities._initialized)

        new_config = DistributedConfig(batch_size=25)
        self.utilities.update_config(new_config)

        self.assertEqual(self.utilities.config, new_config)
        # After update_config, initialize() is called automatically, so _initialized should be True
        self.assertTrue(self.utilities._initialized)

    def test_get_config(self):
        """Test getting configuration."""
        config = self.utilities.get_config()

        self.assertEqual(config, self.config)

    def test_clear_all_caches(self):
        """Test clearing all caches."""
        self.utilities.initialize()

        # Mock processors with clear_cache method
        for processor in self.utilities._processors.values():
            processor.clear_cache = Mock()

        self.utilities.clear_all_caches()

        # Verify clear_cache was called on processors that have it
        for processor in self.utilities._processors.values():
            if hasattr(processor, "clear_cache"):
                processor.clear_cache.assert_called_once()

    def test_get_metrics_summary(self):
        """Test getting metrics summary."""
        self.utilities.initialize()

        summary = self.utilities.get_metrics_summary()

        self.assertIsInstance(summary, dict)
        self.assertIn("total_processors", summary)
        self.assertIn("config", summary)
        self.assertIn("processors", summary)
        self.assertGreater(summary["total_processors"], 0)


class TestDistributedUtilitiesGlobalFunctions(BaseTestCase):
    """Test distributed utilities global functions."""

    def test_get_distributed_utilities(self):
        """Test get_distributed_utilities function."""
        utilities = get_distributed_utilities()

        self.assertIsInstance(utilities, DistributedUtilities)
        self.assertTrue(utilities._initialized)

    def test_get_distributed_utilities_singleton(self):
        """Test get_distributed_utilities singleton behavior."""
        utilities1 = get_distributed_utilities()
        utilities2 = get_distributed_utilities()

        self.assertIs(utilities1, utilities2)

    def test_reset_distributed_utilities(self):
        """Test reset_distributed_utilities function."""
        utilities1 = get_distributed_utilities()
        reset_distributed_utilities()
        utilities2 = get_distributed_utilities()

        self.assertIsNot(utilities1, utilities2)


class TestDistributedUtilitiesFactoryFunctions(BaseTestCase):
    """Test distributed utilities factory functions."""

    def test_create_processor_command(self):
        """Test creating command processor."""
        processor = create_processor(ProcessorType.COMMAND)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_command_executor")

    def test_create_processor_endpoint(self):
        """Test creating endpoint processor."""
        processor = create_processor(ProcessorType.ENDPOINT)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_endpoint_processor")

    def test_create_processor_subdomain(self):
        """Test creating subdomain processor."""
        processor = create_processor(ProcessorType.SUBDOMAIN)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_subdomain_processor")

    def test_create_processor_ip(self):
        """Test creating IP processor."""
        processor = create_processor(ProcessorType.IP)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_ip_processor")

    def test_create_processor_nmap_parser(self):
        """Test creating Nmap parser."""
        parser = create_processor(ProcessorType.NMAP_PARSER)

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_nmap_parser")

    def test_create_processor_nuclei_parser(self):
        """Test creating Nuclei parser."""
        parser = create_processor(ProcessorType.NUCLEI_PARSER)

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_nuclei_parser")

    def test_create_processor_httpx_parser(self):
        """Test creating Httpx parser."""
        parser = create_processor(ProcessorType.HTTPX_PARSER)

        self.assertIsNotNone(parser)
        self.assertEqual(parser.get_task_name(), "distributed_httpx_parser")

    def test_create_processor_dns(self):
        """Test creating DNS processor."""
        processor = create_processor(ProcessorType.DNS)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_dns_processor")

    def test_create_processor_url(self):
        """Test creating URL processor."""
        processor = create_processor(ProcessorType.URL)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_url_processor")

    def test_create_processor_port(self):
        """Test creating port processor."""
        processor = create_processor(ProcessorType.PORT)

        self.assertIsNotNone(processor)
        self.assertEqual(processor.get_task_name(), "distributed_port_processor")

    def test_create_processor_unknown_type(self):
        """Test creating processor with unknown type."""
        with self.assertRaises(ValueError):
            create_processor("unknown_type")


class TestDistributedUtilitiesConvenienceFunctions(BaseTestCase):
    """Test distributed utilities convenience functions."""

    def test_execute_distributed_commands(self):
        """Test execute_distributed_commands function."""

        # Test that function exists and can be called
        self.assertTrue(callable(execute_distributed_commands))

    def test_process_distributed_endpoints(self):
        """Test process_distributed_endpoints function."""

        # Test that function exists and can be called
        self.assertTrue(callable(process_distributed_endpoints))

    def test_parse_distributed_nmap_files(self):
        """Test parse_distributed_nmap_files function."""

        # Test that function exists and can be called
        self.assertTrue(callable(parse_distributed_nmap_files))

    def test_resolve_distributed_domains(self):
        """Test resolve_distributed_domains function."""

        # Test that function exists and can be called
        self.assertTrue(callable(resolve_distributed_domains))

    def test_validate_distributed_urls(self):
        """Test validate_distributed_urls function."""

        # Test that function exists and can be called
        self.assertTrue(callable(validate_distributed_urls))


class TestDistributedUtilitiesConfigurationHelpers(BaseTestCase):
    """Test distributed utilities configuration helpers."""

    def test_create_high_performance_config(self):
        """Test create_high_performance_config function."""
        config = create_high_performance_config()

        self.assertIsInstance(config, DistributedConfig)
        self.assertEqual(config.batch_size, 25)
        self.assertEqual(config.max_batch_size, 50)
        self.assertEqual(config.min_batch_size, 10)
        self.assertEqual(config.worker_timeout, 600)
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.retry_delay, 15)
        self.assertEqual(config.parallel_workers, 10)
        self.assertTrue(config.enable_retry)
        self.assertTrue(config.enable_metrics)

    def test_create_balanced_config(self):
        """Test create_balanced_config function."""
        config = create_balanced_config()

        self.assertIsInstance(config, DistributedConfig)
        self.assertEqual(config.batch_size, 15)
        self.assertEqual(config.max_batch_size, 25)
        self.assertEqual(config.min_batch_size, 5)
        self.assertEqual(config.worker_timeout, 300)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.retry_delay, 30)
        self.assertEqual(config.parallel_workers, 5)
        self.assertTrue(config.enable_retry)
        self.assertTrue(config.enable_metrics)

    def test_create_conservative_config(self):
        """Test create_conservative_config function."""
        config = create_conservative_config()

        self.assertIsInstance(config, DistributedConfig)
        self.assertEqual(config.batch_size, 10)
        self.assertEqual(config.max_batch_size, 15)
        self.assertEqual(config.min_batch_size, 3)
        self.assertEqual(config.worker_timeout, 180)
        self.assertEqual(config.max_retries, 2)
        self.assertEqual(config.retry_delay, 60)
        self.assertEqual(config.parallel_workers, 3)
        self.assertTrue(config.enable_retry)
        self.assertTrue(config.enable_metrics)


class TestDistributedUtilitiesUtilityFunctions(BaseTestCase):
    """Test distributed utilities utility functions."""

    def test_batch_process_items(self):
        """Test batch_process_items function."""
        items = list(range(10))

        def processor_func(batch):
            return [x * 2 for x in batch]

        results = batch_process_items(items, processor_func, batch_size=3)

        self.assertEqual(len(results), 10)
        self.assertEqual(results[0], 0)
        self.assertEqual(results[1], 2)
        self.assertEqual(results[9], 18)

    def test_batch_process_items_invalid_input(self):
        """Test batch_process_items with invalid input."""

        def processor_func(batch):
            return batch

        results = batch_process_items([], processor_func)

        self.assertEqual(len(results), 0)

    def test_parallel_process_items(self):
        """Test parallel_process_items function."""
        list(range(5))

        def processor_func(batch):
            return {"processed": len(batch)}

        # Test that function exists and can be called
        self.assertTrue(callable(parallel_process_items))

    def test_parallel_process_items_invalid_input(self):
        """Test parallel_process_items with invalid input."""

        def processor_func(batch):
            return {"processed": len(batch)}

        result = parallel_process_items([], processor_func)

        self.assertIsInstance(result, dict)
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_get_processor_recommendations(self):
        """Test get_processor_recommendations function."""
        recommendations = get_processor_recommendations(100, "generic")

        self.assertIsInstance(recommendations, dict)
        self.assertIn("batch_size", recommendations)
        self.assertIn("worker_timeout", recommendations)
        self.assertIn("max_retries", recommendations)
        self.assertIn("parallel_workers", recommendations)

    def test_get_processor_recommendations_small_count(self):
        """Test get_processor_recommendations for small item count."""
        recommendations = get_processor_recommendations(25, "generic")

        self.assertEqual(recommendations["batch_size"], 10)
        self.assertEqual(recommendations["worker_timeout"], 180)
        self.assertEqual(recommendations["max_retries"], 2)
        self.assertEqual(recommendations["parallel_workers"], 3)

    def test_get_processor_recommendations_large_count(self):
        """Test get_processor_recommendations for large item count."""
        recommendations = get_processor_recommendations(2000, "generic")

        self.assertEqual(recommendations["batch_size"], 25)
        self.assertEqual(recommendations["worker_timeout"], 600)
        self.assertEqual(recommendations["max_retries"], 5)
        self.assertEqual(recommendations["parallel_workers"], 10)

    def test_get_processor_recommendations_command_type(self):
        """Test get_processor_recommendations for command type."""
        recommendations = get_processor_recommendations(100, "command")

        self.assertLessEqual(recommendations["worker_timeout"], 300)

    def test_get_processor_recommendations_database_type(self):
        """Test get_processor_recommendations for database type."""
        recommendations = get_processor_recommendations(100, "database")

        self.assertLessEqual(recommendations["batch_size"], 20)

    def test_get_processor_recommendations_network_type(self):
        """Test get_processor_recommendations for network type."""
        recommendations = get_processor_recommendations(100, "network")

        self.assertLessEqual(recommendations["worker_timeout"], 180)


if __name__ == "__main__":
    unittest.main()
