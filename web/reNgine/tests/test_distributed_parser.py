"""
Simplified tests for distributed parser utilities.

This module provides basic unit tests for the distributed parser utilities
focusing on creation and basic functionality.
"""

import unittest

from reNgine.utilities.distributed.base import DistributedConfig
from reNgine.utilities.distributed.parser import (
    DistributedHttpxParser,
    DistributedNmapParser,
    DistributedNucleiParser,
    DistributedParserResult,
    ProcessingStatus,
    create_distributed_httpx_parser,
    create_distributed_nmap_parser,
    create_distributed_nuclei_parser,
    parse_httpx_files_distributed,
    parse_nmap_files_distributed,
    parse_nuclei_files_distributed,
)
from utils.test_base import BaseTestCase


class TestDistributedNmapParser(BaseTestCase):
    """Test DistributedNmapParser class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.config = DistributedConfig()
        self.parser = DistributedNmapParser(self.config)

    def test_nmap_parser_creation(self):
        """Test Nmap parser creation."""
        self.assertEqual(self.parser.config, self.config)
        self.assertEqual(self.parser.get_task_name(), "distributed_nmap_parser")
        self.assertEqual(self.parser.get_queue_name(), "io_queue")
        self.assertIsInstance(self.parser.parsed_hosts, dict)

    def test_nmap_parser_batch_parsing(self):
        """Test Nmap parser batch parsing."""

        # Test that the method exists and can be called
        self.assertTrue(hasattr(self.parser, "parse_nmap_files_batch"))
        self.assertTrue(callable(getattr(self.parser, "parse_nmap_files_batch")))


class TestDistributedNucleiParser(BaseTestCase):
    """Test DistributedNucleiParser class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.config = DistributedConfig()
        self.parser = DistributedNucleiParser(self.config)

    def test_nuclei_parser_creation(self):
        """Test Nuclei parser creation."""
        self.assertEqual(self.parser.config, self.config)
        self.assertEqual(self.parser.get_task_name(), "distributed_nuclei_parser")
        self.assertEqual(self.parser.get_queue_name(), "io_queue")
        self.assertIsInstance(self.parser.parsed_vulnerabilities, dict)

    def test_nuclei_parser_batch_parsing(self):
        """Test Nuclei parser batch parsing."""

        # Test that the method exists and can be called
        self.assertTrue(hasattr(self.parser, "parse_nuclei_files_batch"))
        self.assertTrue(callable(getattr(self.parser, "parse_nuclei_files_batch")))


class TestDistributedHttpxParser(BaseTestCase):
    """Test DistributedHttpxParser class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.config = DistributedConfig()
        self.parser = DistributedHttpxParser(self.config)

    def test_httpx_parser_creation(self):
        """Test Httpx parser creation."""
        self.assertEqual(self.parser.config, self.config)
        self.assertEqual(self.parser.get_task_name(), "distributed_httpx_parser")
        self.assertEqual(self.parser.get_queue_name(), "io_queue")
        self.assertIsInstance(self.parser.parsed_endpoints, dict)

    def test_httpx_parser_batch_parsing(self):
        """Test Httpx parser batch parsing."""

        # Test that the method exists and can be called
        self.assertTrue(hasattr(self.parser, "parse_httpx_files_batch"))
        self.assertTrue(callable(getattr(self.parser, "parse_httpx_files_batch")))


class TestDistributedParserResult(BaseTestCase):
    """Test DistributedParserResult class."""

    def test_parser_result_creation(self):
        """Test parser result creation."""
        data = {"parsed_files": 2, "parsed_items": 10}
        result = DistributedParserResult(data=data, status=ProcessingStatus.COMPLETED, batch_id="test_batch")

        self.assertEqual(result.data, data)
        self.assertEqual(result.status, ProcessingStatus.COMPLETED)
        self.assertEqual(result.batch_id, "test_batch")
        self.assertTrue(result.is_successful)
        self.assertIsInstance(result.parsed_items, list)
        self.assertIsInstance(result.parse_errors, list)
        self.assertIsInstance(result.input_files, list)
        self.assertIsInstance(result.output_files, list)

    def test_parser_result_with_errors(self):
        """Test parser result with errors."""
        data = {}
        errors = ["Parse error occurred"]
        result = DistributedParserResult(
            data=data, status=ProcessingStatus.FAILED, batch_id="test_batch", errors=errors
        )

        self.assertEqual(result.errors, errors)
        self.assertTrue(result.is_failed)

    def test_add_parsed_item(self):
        """Test adding parsed item."""
        result = DistributedParserResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="test_batch")

        result.add_parsed_item({"type": "nmap_port", "port": 80})

        self.assertEqual(len(result.parsed_items), 1)
        self.assertEqual(result.parsed_items[0]["port"], 80)

    def test_add_parse_error(self):
        """Test adding parse error."""
        result = DistributedParserResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="test_batch")

        result.add_parse_error("File not found")

        self.assertEqual(len(result.parse_errors), 1)
        self.assertEqual(result.parse_errors[0], "File not found")

    def test_add_input_file(self):
        """Test adding input file."""
        result = DistributedParserResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="test_batch")

        result.add_input_file("scan.xml")

        self.assertEqual(len(result.input_files), 1)
        self.assertEqual(result.input_files[0], "scan.xml")

    def test_add_output_file(self):
        """Test adding output file."""
        result = DistributedParserResult(data={}, status=ProcessingStatus.COMPLETED, batch_id="test_batch")

        result.add_output_file("parsed.json")

        self.assertEqual(len(result.output_files), 1)
        self.assertEqual(result.output_files[0], "parsed.json")


class TestDistributedParserFactoryFunctions(BaseTestCase):
    """Test distributed parser factory functions."""

    def test_create_distributed_nmap_parser(self):
        """Test create_distributed_nmap_parser function."""
        parser = create_distributed_nmap_parser()

        self.assertIsInstance(parser, DistributedNmapParser)
        self.assertIsInstance(parser.config, DistributedConfig)

    def test_create_distributed_nuclei_parser(self):
        """Test create_distributed_nuclei_parser function."""
        parser = create_distributed_nuclei_parser()

        self.assertIsInstance(parser, DistributedNucleiParser)
        self.assertIsInstance(parser.config, DistributedConfig)

    def test_create_distributed_httpx_parser(self):
        """Test create_distributed_httpx_parser function."""
        parser = create_distributed_httpx_parser()

        self.assertIsInstance(parser, DistributedHttpxParser)
        self.assertIsInstance(parser.config, DistributedConfig)

    def test_parse_nmap_files_distributed(self):
        """Test parse_nmap_files_distributed function."""

        # Test that function exists and can be called
        self.assertTrue(callable(parse_nmap_files_distributed))

    def test_parse_nuclei_files_distributed(self):
        """Test parse_nuclei_files_distributed function."""

        # Test that function exists and can be called
        self.assertTrue(callable(parse_nuclei_files_distributed))

    def test_parse_httpx_files_distributed(self):
        """Test parse_httpx_files_distributed function."""

        # Test that function exists and can be called
        self.assertTrue(callable(parse_httpx_files_distributed))


if __name__ == "__main__":
    unittest.main()
