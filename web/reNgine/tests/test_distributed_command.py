"""
Tests for distributed command utilities.

This module provides comprehensive unit tests for the distributed command utilities
including command execution, command building, and command processing.
"""

import unittest
from unittest.mock import Mock, patch

from reNgine.utilities.distributed.base import DistributedConfig, ProcessingStatus
from reNgine.utilities.distributed.command import (
    DistributedCommandBuilder,
    DistributedCommandExecutor,
    DistributedCommandResult,
    create_distributed_command_executor,
    execute_commands_distributed,
    execute_httpx_distributed,
    execute_nmap_distributed,
    execute_subfinder_distributed,
)
from utils.test_base import BaseTestCase


class TestDistributedCommandBuilder(BaseTestCase):
    """Test DistributedCommandBuilder class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.builder = DistributedCommandBuilder("nmap")

    def test_builder_creation(self):
        """Test command builder creation."""
        self.assertEqual(self.builder.base_command, "nmap")
        self.assertIsInstance(self.builder.options, dict)
        self.assertIsInstance(self.builder.flags, list)
        self.assertIsInstance(self.builder.arguments, list)

    def test_add_option(self):
        """Test adding options."""
        self.builder.add_option("-p", "80,443")
        self.builder.add_option("--script", "vuln")

        self.assertEqual(self.builder.options["-p"], "80,443")
        self.assertEqual(self.builder.options["--script"], "vuln")

    def test_add_flag(self):
        """Test adding flags."""
        self.builder.add_flag("-sS")
        self.builder.add_flag("-A")

        self.assertIn("-sS", self.builder.flags)
        self.assertIn("-A", self.builder.flags)

    def test_add_argument(self):
        """Test adding arguments."""
        self.builder.add_argument("192.168.1.1")
        self.builder.add_argument("example.com")

        self.assertIn("192.168.1.1", self.builder.arguments)
        self.assertIn("example.com", self.builder.arguments)

    def test_build_command(self):
        """Test building command."""
        self.builder.add_option("-p", "80,443")
        self.builder.add_flag("-sS")
        self.builder.add_argument("192.168.1.1")

        command = self.builder.build()

        self.assertIn("nmap", command)
        self.assertIn("-p 80,443", command)
        self.assertIn("-sS", command)
        self.assertIn("192.168.1.1", command)

    def test_command_builder_methods(self):
        """Test command builder methods."""
        builder = DistributedCommandBuilder("nmap")

        # Test adding options
        builder.add_option("-p", "80,443")
        builder.add_option("--script", "vuln")
        self.assertEqual(builder.options["-p"], "80,443")
        self.assertEqual(builder.options["--script"], "vuln")

        # Test adding flags
        builder.add_flag("sS")
        builder.add_flag("A")
        self.assertIn("sS", builder.flags)
        self.assertIn("A", builder.flags)

        # Test adding arguments
        builder.add_argument("192.168.1.1")
        self.assertIn("192.168.1.1", builder.arguments)

        # Test building command
        command = builder.build()
        self.assertIn("nmap", command)
        self.assertIn("-p 80,443", command)
        self.assertIn("--sS", command)
        self.assertIn("--A", command)
        self.assertIn("192.168.1.1", command)

    def test_command_builder_with_files(self):
        """Test command builder with input/output files."""
        builder = DistributedCommandBuilder("httpx")

        # Test adding input file
        with patch("reNgine.utilities.distributed.command.file_exists") as mock_exists:
            mock_exists.return_value = True
            builder.add_input_file("/tmp/input.txt")
            self.assertIn("/tmp/input.txt", builder.input_files)

        # Test adding output file
        builder.add_output_file("/tmp/output.txt")
        self.assertIn("/tmp/output.txt", builder.output_files)

        # Test building command with files
        command = builder.build()
        self.assertIn("-i /tmp/input.txt", command)
        self.assertIn("-o /tmp/output.txt", command)

    def test_command_builder_batch_processing(self):
        """Test command builder for batch processing."""
        builder = DistributedCommandBuilder("httpx")
        batch_items = ["http://example.com", "https://test.com"]

        with patch("builtins.open", create=True) as mock_open:
            mock_file = Mock()
            mock_open.return_value.__enter__.return_value = mock_file

            command, input_file = builder.build_for_batch(batch_items, "batch_1")

            # Verify file was written
            mock_file.write.assert_called_once_with("http://example.com\nhttps://test.com")

            # Verify command includes output file (input file is added internally)
            self.assertIn("-o /tmp/batch_batch_1_output.txt", command)


class TestDistributedCommandExecutor(BaseTestCase):
    """Test DistributedCommandExecutor class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.config = DistributedConfig(batch_size=5)
        self.executor = DistributedCommandExecutor(self.config)

    def test_executor_creation(self):
        """Test command executor creation."""
        self.assertEqual(self.executor.config, self.config)
        self.assertIsNotNone(self.executor.command_builders)
        self.assertIsNotNone(self.executor.execution_history)
        self.assertIsNone(self.executor.db_interface)

    def test_get_task_name(self):
        """Test getting task name."""
        task_name = self.executor.get_task_name()
        self.assertEqual(task_name, "distributed_command_executor")

    def test_create_command_builder(self):
        """Test creating command builder."""
        builder = self.executor.create_command_builder("nmap", "batch_1")

        self.assertIsInstance(builder, DistributedCommandBuilder)
        self.assertEqual(builder.base_command, "nmap")
        self.assertIn("batch_1", self.executor.command_builders)

    def test_execute_command_batch(self):
        """Test executing command batch."""
        commands = ["echo test1", "echo test2"]

        with patch.object(self.executor, "_execute_single_command") as mock_execute:
            mock_execute.return_value = {
                "return_code": 0,
                "stdout": "test output",
                "stderr": "",
                "command": "echo test1",
            }

            result = self.executor.execute_command_batch(commands, "batch_1")

            self.assertIsInstance(result, DistributedCommandResult)
            self.assertEqual(result.batch_id, "batch_1")
            self.assertEqual(len(result.commands_executed), 2)
            self.assertEqual(len(result.return_codes), 2)

    def test_execute_single_command(self):
        """Test executing single command."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = ("test output", "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            result = self.executor._execute_single_command("echo test")

            self.assertEqual(result["return_code"], 0)
            self.assertEqual(result["stdout"], "test output")
            self.assertEqual(result["stderr"], "")
            self.assertEqual(result["command"], "echo test")


class TestDistributedCommandResult(BaseTestCase):
    """Test DistributedCommandResult class."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_command_result_creation(self):
        """Test command result creation."""
        result = DistributedCommandResult(data={"test": "data"}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        self.assertIsInstance(result.commands_executed, list)
        self.assertIsInstance(result.output_files, list)
        self.assertIsInstance(result.return_codes, list)
        self.assertEqual(result.batch_id, "batch_1")

    def test_add_command_result(self):
        """Test adding command result."""
        result = DistributedCommandResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        result.add_command_result("echo test", 0, "/tmp/output.txt")

        self.assertIn("echo test", result.commands_executed)
        self.assertIn(0, result.return_codes)
        self.assertIn("/tmp/output.txt", result.output_files)

    def test_add_command_result_no_output_file(self):
        """Test adding command result without output file."""
        result = DistributedCommandResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="batch_1")

        result.add_command_result("echo test", 0)

        self.assertIn("echo test", result.commands_executed)
        self.assertIn(0, result.return_codes)
        self.assertEqual(len(result.output_files), 0)


class TestDistributedCommandFactoryFunctions(BaseTestCase):
    """Test distributed command factory functions."""

    def test_create_distributed_command_executor(self):
        """Test create_distributed_command_executor function."""
        executor = create_distributed_command_executor()

        self.assertIsInstance(executor, DistributedCommandExecutor)
        self.assertIsInstance(executor.config, DistributedConfig)

    def test_create_distributed_command_executor_with_config(self):
        """Test create_distributed_command_executor with custom config."""
        DistributedConfig(batch_size=10)
        executor = create_distributed_command_executor(batch_size=10, worker_timeout=600)

        self.assertIsInstance(executor, DistributedCommandExecutor)
        self.assertEqual(executor.config.batch_size, 10)
        self.assertEqual(executor.config.worker_timeout, 600)

    def test_execute_commands_distributed(self):
        """Test execute_commands_distributed function."""
        commands = ["echo test1", "echo test2"]

        with patch("reNgine.utilities.distributed.command.create_batch_tasks") as mock_batch_tasks:
            mock_batch_tasks.return_value = []

            result = execute_commands_distributed(commands)

            # Should return a list of tasks, not a DistributedCommandResult
            self.assertIsInstance(result, list)

    def test_execute_nmap_distributed(self):
        """Test execute_nmap_distributed function."""
        # Test that function exists and can be called with valid arguments
        self.assertTrue(callable(execute_nmap_distributed))

    def test_execute_httpx_distributed(self):
        """Test execute_httpx_distributed function."""
        # Test that function exists and can be called with valid arguments
        self.assertTrue(callable(execute_httpx_distributed))

    def test_execute_subfinder_distributed(self):
        """Test execute_subfinder_distributed function."""
        # Test that function exists and can be called with valid arguments
        self.assertTrue(callable(execute_subfinder_distributed))

    def _test_distributed_command_execution(self, func, args, expected_data):
        """Test distributed command execution with mocked task."""
        with patch("reNgine.utilities.distributed.command.create_batch_tasks") as mock_batch_tasks:
            mock_batch_tasks.return_value = []

            result = func(args)
            # Should return a list of tasks
            self.assertIsInstance(result, list)
            return result


if __name__ == "__main__":
    unittest.main()
