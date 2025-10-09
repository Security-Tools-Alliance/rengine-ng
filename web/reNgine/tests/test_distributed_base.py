"""
Tests for distributed base utilities.

This module provides comprehensive unit tests for the base distributed utilities
including configuration, results, error handling, metrics, and task base classes.
"""

import unittest
import time
from unittest.mock import MagicMock, patch, Mock
from typing import List, Dict, Any

from reNgine.utilities.distributed.base import (
    DistributedConfig,
    DistributedResult,
    ProcessingStatus,
    DistributedErrorHandler,
    DistributedMetrics,
    DistributedTaskBase,
    DistributedCommandProcessor,
    DistributedDatabaseProcessor,
    DistributedParserProcessor,
    create_distributed_config,
    validate_distributed_input,
    create_batch_tasks,
    aggregate_distributed_results
)

from utils.test_base import BaseTestCase


class TestDistributedConfig(BaseTestCase):
    """Test DistributedConfig class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
    
    def test_default_config(self):
        """Test default configuration values."""
        config = DistributedConfig()
        
        self.assertEqual(config.batch_size, 15)
        self.assertEqual(config.max_batch_size, 25)
        self.assertEqual(config.min_batch_size, 5)
        self.assertEqual(config.worker_timeout, 300)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.retry_delay, 30)
        self.assertEqual(config.parallel_workers, 5)
        self.assertTrue(config.enable_retry)
        self.assertTrue(config.enable_metrics)
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = DistributedConfig(
            batch_size=20,
            max_retries=5,
            parallel_workers=10
        )
        
        self.assertEqual(config.batch_size, 20)
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.parallel_workers, 10)
    
    def test_config_validation(self):
        """Test configuration validation."""
        self._test_batch_size_validation()
        self._test_timeout_validation()
        self._test_retries_validation()
    
    def _test_batch_size_validation(self):
        """Test batch size validation."""
        # Test batch size adjustment
        config = DistributedConfig(batch_size=2)  # Below minimum
        config.validate()
        self.assertEqual(config.batch_size, 5)  # Should be adjusted to minimum
        
        config = DistributedConfig(batch_size=50)  # Above maximum
        config.validate()
        self.assertEqual(config.batch_size, 25)  # Should be adjusted to maximum
    
    def _test_timeout_validation(self):
        """Test timeout validation."""
        config = DistributedConfig(worker_timeout=0)
        config.validate()
        self.assertEqual(config.worker_timeout, 300)  # Should be set to default
    
    def _test_retries_validation(self):
        """Test retries validation."""
        config = DistributedConfig(max_retries=-1)
        config.validate()
        self.assertEqual(config.max_retries, 0)  # Should be set to 0


class TestDistributedResult(BaseTestCase):
    """Test DistributedResult class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
    
    def test_successful_result(self):
        """Test successful result creation."""
        result = DistributedResult(
            data={"test": "data"},
            status=ProcessingStatus.COMPLETED,
            batch_id="batch_1",
            processing_time=1.5
        )
        
        self.assertTrue(result.is_successful)
        self.assertFalse(result.is_failed)
        self.assertEqual(result.data, {"test": "data"})
        self.assertEqual(result.status, ProcessingStatus.COMPLETED)
        self.assertEqual(result.batch_id, "batch_1")
        self.assertEqual(result.processing_time, 1.5)
    
    def test_failed_result(self):
        """Test failed result creation."""
        result = DistributedResult(
            data=None,
            status=ProcessingStatus.FAILED,
            errors=["Test error"],
            processing_time=0.5
        )
        
        self.assertFalse(result.is_successful)
        self.assertTrue(result.is_failed)
        self.assertEqual(result.status, ProcessingStatus.FAILED)
        self.assertEqual(result.errors, ["Test error"])
    
    def test_result_with_metadata(self):
        """Test result with metadata."""
        metadata = {"worker_id": "worker_1", "timestamp": time.time()}
        result = DistributedResult(
            data=[1, 2, 3],
            status=ProcessingStatus.COMPLETED,
            metadata=metadata
        )
        
        self.assertEqual(result.metadata, metadata)
        self.assertTrue(result.is_successful)


class TestDistributedErrorHandler(BaseTestCase):
    """Test DistributedErrorHandler class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig(max_retries=3, retry_delay=1)
        self.error_handler = DistributedErrorHandler(self.config)
    
    def test_error_handler_creation(self):
        """Test error handler creation."""
        self.assertEqual(self.error_handler.config, self.config)
        self.assertIsInstance(self.error_handler.retry_counts, dict)
        self.assertIsInstance(self.error_handler.error_history, dict)
    
    def test_should_retry(self):
        """Test retry logic."""
        # Should retry when under max retries and retryable error
        self.assertTrue(self.error_handler.should_retry("batch_1", ConnectionError("test")))
        
        # Should not retry when at max retries
        self.error_handler.retry_counts["batch_1"] = 3
        self.assertFalse(self.error_handler.should_retry("batch_1", ConnectionError("test")))
        
        # Should not retry non-retryable errors
        self.assertFalse(self.error_handler.should_retry("batch_2", ValueError("test")))
    
    def test_record_error(self):
        """Test error recording."""
        error = Exception("Test error")
        self.error_handler.record_error("batch_1", error)
        
        self.assertEqual(self.error_handler.retry_counts["batch_1"], 1)
        self.assertIn("Exception: Test error", self.error_handler.error_history["batch_1"])
    
    def test_get_retry_delay(self):
        """Test retry delay calculation."""
        # First retry
        delay1 = self.error_handler.get_retry_delay("batch_1")
        self.assertEqual(delay1, 1)  # 1 * 2^0 = 1
        
        # Second retry
        self.error_handler.retry_counts["batch_1"] = 1
        delay2 = self.error_handler.get_retry_delay("batch_1")
        self.assertEqual(delay2, 2)  # 1 * 2^1 = 2
    
    def test_get_error_summary(self):
        """Test error summary generation."""
        self.error_handler.record_error("batch_1", Exception("Error 1"))
        self.error_handler.record_error("batch_1", Exception("Error 2"))
        
        summary = self.error_handler.get_error_summary("batch_1")
        self.assertEqual(len(summary), 2)
        self.assertIn("Error 1", summary[0])
        self.assertIn("Error 2", summary[1])


class TestDistributedMetrics(BaseTestCase):
    """Test DistributedMetrics class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.metrics = DistributedMetrics()
    
    def test_metrics_creation(self):
        """Test metrics creation."""
        self.assertGreater(self.metrics.start_time, 0)
        self.assertIsInstance(self.metrics.batch_metrics, dict)
        self.assertIsInstance(self.metrics.worker_metrics, dict)
    
    def test_record_batch_start(self):
        """Test recording batch start."""
        self.metrics.record_batch_start("batch_1", 10)
        
        self.assertIn("batch_1", self.metrics.batch_metrics)
        batch_info = self.metrics.batch_metrics["batch_1"]
        self.assertEqual(batch_info["batch_size"], 10)
        self.assertEqual(batch_info["status"], ProcessingStatus.IN_PROGRESS)
    
    def test_record_batch_completion(self):
        """Test recording batch completion."""
        self.metrics.record_batch_start("batch_1", 10)
        self.metrics.record_batch_completion("batch_1", True, 1.5)
        
        batch_info = self.metrics.batch_metrics["batch_1"]
        self.assertTrue(batch_info["success"])
        self.assertEqual(batch_info["processing_time"], 1.5)
        self.assertEqual(batch_info["status"], ProcessingStatus.COMPLETED)
    
    def test_record_worker_activity(self):
        """Test recording worker activity."""
        self.metrics.record_worker_activity("worker_1", "processing", items=5)
        
        self.assertIn("worker_1", self.metrics.worker_metrics)
        activities = self.metrics.worker_metrics["worker_1"]["activities"]
        self.assertEqual(len(activities), 1)
        self.assertEqual(activities[0]["activity"], "processing")
        self.assertEqual(activities[0]["items"], 5)
    
    def test_get_summary(self):
        """Test getting metrics summary."""
        # Record some batch activity
        self.metrics.record_batch_start("batch_1", 10)
        self.metrics.record_batch_completion("batch_1", True, 1.0)
        
        self.metrics.record_batch_start("batch_2", 5)
        self.metrics.record_batch_completion("batch_2", False, 0.5)
        
        summary = self.metrics.get_summary()
        
        self.assertEqual(summary["total_batches"], 2)
        self.assertEqual(summary["successful_batches"], 1)
        self.assertEqual(summary["failed_batches"], 1)
        self.assertEqual(summary["success_rate"], 0.5)
        self.assertEqual(summary["total_processing_time"], 1.5)


class TestDistributedTaskBase(BaseTestCase):
    """Test DistributedTaskBase abstract class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig()
    
    def test_task_base_creation(self):
        """Test task base creation."""
        # Create a concrete implementation for testing
        class TestTask(DistributedTaskBase):
            def get_task_name(self):
                return "test_task"
            
            def get_queue_name(self):
                return "test_queue"
        
        task = TestTask(self.config)
        
        self.assertEqual(task.config, self.config)
        self.assertIsNotNone(task.error_handler)
        self.assertIsNotNone(task.metrics)
        self.assertIsNotNone(task._lock)
    
    def test_create_batch_id(self):
        """Test batch ID creation."""
        class TestTask(DistributedTaskBase):
            def get_task_name(self):
                return "test_task"
            
            def get_queue_name(self):
                return "test_queue"
        
        task = TestTask()
        
        # Test default prefix
        batch_id1 = task.create_batch_id()
        self.assertTrue(batch_id1.startswith("batch_"))
        self.assertEqual(len(batch_id1), 14)  # "batch_" + 8 hex chars
        
        # Test custom prefix
        batch_id2 = task.create_batch_id("custom")
        self.assertTrue(batch_id2.startswith("custom_"))
        self.assertEqual(len(batch_id2), 15)  # "custom_" + 8 hex chars
        
        # Test uniqueness
        batch_id3 = task.create_batch_id()
        self.assertNotEqual(batch_id1, batch_id3)
    
    def test_logging_methods(self):
        """Test logging methods."""
        class TestTask(DistributedTaskBase):
            def get_task_name(self):
                return "test_task"
            
            def get_queue_name(self):
                return "test_queue"
        
        task = TestTask()
        
        # Test logging start
        with patch('reNgine.utilities.distributed.base.logger') as mock_logger:
            task.log_processing_start("batch_1", 10)
            mock_logger.info.assert_called_with("Starting test_task batch batch_1 with 10 items")
        
        # Test logging completion
        with patch('reNgine.utilities.distributed.base.logger') as mock_logger:
            task.log_processing_completion("batch_1", True, 1.5)
            mock_logger.info.assert_called_with("test_task batch batch_1 completed in 1.50s")
        
        # Test logging error
        with patch('reNgine.utilities.distributed.base.logger') as mock_logger:
            task.log_processing_error("batch_1", "Test error", 0.5)
            mock_logger.error.assert_called_with("test_task batch batch_1 failed after 0.50s: Test error")


class TestDistributedCommandProcessor(BaseTestCase):
    """Test DistributedCommandProcessor class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig()
    
    def test_command_processor_creation(self):
        """Test command processor creation."""
        class TestCommandProcessor(DistributedCommandProcessor):
            def get_task_name(self):
                return "test_command_processor"
        
        processor = TestCommandProcessor(self.config)
        
        self.assertEqual(processor.config, self.config)
        self.assertEqual(processor.get_queue_name(), "run_command_queue")
        self.assertIsInstance(processor.command_history, dict)
    
    def test_record_command(self):
        """Test command recording."""
        processor = self._create_test_command_processor()
        
        # Record commands
        processor.record_command("batch_1", "echo test1")
        processor.record_command("batch_1", "echo test2")
        processor.record_command("batch_2", "echo test3")
        
        # Test command history
        self._verify_command_history(processor, "batch_1", ["echo test1", "echo test2"])
        self._verify_command_history(processor, "batch_2", ["echo test3"])
        self._verify_command_history(processor, "batch_3", [])
    
    def _create_test_command_processor(self):
        """Create a test command processor."""
        class TestCommandProcessor(DistributedCommandProcessor):
            def get_task_name(self):
                return "test_command_processor"
        
        return TestCommandProcessor()
    
    def _verify_command_history(self, processor, batch_id, expected_commands):
        """Verify command history for a batch."""
        history = processor.get_command_history(batch_id)
        self.assertEqual(len(history), len(expected_commands))
        for command in expected_commands:
            self.assertIn(command, history)


class TestDistributedDatabaseProcessor(BaseTestCase):
    """Test DistributedDatabaseProcessor class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig()
    
    def test_database_processor_creation(self):
        """Test database processor creation."""
        class TestDatabaseProcessor(DistributedDatabaseProcessor):
            def get_task_name(self):
                return "test_database_processor"
        
        processor = TestDatabaseProcessor(self.config)
        
        self.assertEqual(processor.config, self.config)
        self.assertEqual(processor.get_queue_name(), "cpu_queue")
        self.assertIsInstance(processor.db_operations, dict)
        self.assertIsNone(processor.db_interface)
    
    def test_record_db_operation(self):
        """Test database operation recording."""
        processor = self._create_test_database_processor()
        
        # Record operations
        processor.record_db_operation("batch_1", "CREATE endpoint")
        processor.record_db_operation("batch_1", "UPDATE subdomain")
        processor.record_db_operation("batch_2", "DELETE ip")
        
        # Test operation history
        self._verify_db_operations(processor, "batch_1", ["CREATE endpoint", "UPDATE subdomain"])
        self._verify_db_operations(processor, "batch_2", ["DELETE ip"])
        self._verify_db_operations(processor, "batch_3", [])
    
    def _create_test_database_processor(self):
        """Create a test database processor."""
        class TestDatabaseProcessor(DistributedDatabaseProcessor):
            def get_task_name(self):
                return "test_database_processor"
        
        return TestDatabaseProcessor()
    
    def _verify_db_operations(self, processor, batch_id, expected_operations):
        """Verify database operations for a batch."""
        operations = processor.get_db_operations(batch_id)
        self.assertEqual(len(operations), len(expected_operations))
        for operation in expected_operations:
            self.assertIn(operation, operations)


class TestDistributedParserProcessor(BaseTestCase):
    """Test DistributedParserProcessor class."""
    
    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig()
    
    def test_parser_processor_creation(self):
        """Test parser processor creation."""
        class TestParserProcessor(DistributedParserProcessor):
            def get_task_name(self):
                return "test_parser_processor"
        
        processor = TestParserProcessor(self.config)
        
        self.assertEqual(processor.config, self.config)
        self.assertEqual(processor.get_queue_name(), "io_queue")
        self.assertIsInstance(processor.parsed_items, dict)
    
    def test_record_parsed_item(self):
        """Test parsed item recording."""
        class TestParserProcessor(DistributedParserProcessor):
            def get_task_name(self):
                return "test_parser_processor"
        
        processor = TestParserProcessor()
        
        # Record parsed items
        processor.record_parsed_item("batch_1", {"host": "example.com", "port": 80})
        processor.record_parsed_item("batch_1", {"host": "test.com", "port": 443})
        processor.record_parsed_item("batch_2", {"host": "demo.com", "port": 22})
        
        # Test parsed items
        items_1 = processor.get_parsed_items("batch_1")
        self.assertEqual(len(items_1), 2)
        self.assertIn({"host": "example.com", "port": 80}, items_1)
        self.assertIn({"host": "test.com", "port": 443}, items_1)
        
        items_2 = processor.get_parsed_items("batch_2")
        self.assertEqual(len(items_2), 1)
        self.assertIn({"host": "demo.com", "port": 22}, items_2)
        
        # Test non-existent batch
        items_3 = processor.get_parsed_items("batch_3")
        self.assertEqual(len(items_3), 0)


class TestDistributedFactoryFunctions(BaseTestCase):
    """Test distributed factory functions."""
    
    def test_create_distributed_config(self):
        """Test create_distributed_config function."""
        config = create_distributed_config()
        
        self.assertIsInstance(config, DistributedConfig)
        self.assertEqual(config.batch_size, 15)  # Default value
    
    def test_validate_distributed_input(self):
        """Test validate_distributed_input function."""
        # Valid input
        self.assertTrue(validate_distributed_input(["item1", "item2"]))
        
        # Invalid input (empty)
        self.assertFalse(validate_distributed_input([]))
        
        # Invalid input (None)
        self.assertFalse(validate_distributed_input(None))
    
    def test_create_batch_tasks(self):
        """Test create_batch_tasks function."""
        items = list(range(20))  # 20 items
        task_func = Mock()
        batches = create_batch_tasks(items, task_func, batch_size=5)
        
        # Should return a list of batch tasks
        self.assertIsInstance(batches, list)
        self.assertEqual(len(batches), 4)  # 20/5 = 4 batches
    
    def test_aggregate_distributed_results(self):
        """Test aggregate_distributed_results function."""
        results = [
            DistributedResult(data=[1, 2], status=ProcessingStatus.COMPLETED),
            DistributedResult(data=[3, 4], status=ProcessingStatus.COMPLETED),
            DistributedResult(data=None, status=ProcessingStatus.FAILED, errors=["error"])
        ]
        
        aggregated = aggregate_distributed_results(results)
        
        # Should return a dictionary with summary information
        self.assertIsInstance(aggregated, dict)
        self.assertTrue(aggregated["success"])
        self.assertEqual(aggregated["total_items"], 5)
        self.assertEqual(aggregated["successful_items"], 4)
        self.assertEqual(aggregated["failed_items"], 1)
        self.assertIn("error", aggregated["errors"])


if __name__ == '__main__':
    unittest.main()
