"""
Unit tests for core utilities.

This module tests the core utility functions for data manipulation,
validation, formatting, network operations, and file operations.
"""

from unittest.mock import patch, mock_open, MagicMock
import tempfile
import os
from pathlib import Path
from ipaddress import IPv4Network, IPv6Network

from utils.test_base import BaseTestCase

from reNgine.utilities.core import (
    is_iterable,
    replace_nulls,
    chunk_list,
    format_duration,
    format_bytes,
    parse_url,
    extract_domain_from_url,
    is_valid_url,
    is_valid_domain,
    is_valid_ip,
    is_valid_port,
    is_valid_cidr,
    read_file_content,
    write_file_content,
    create_temp_file,
    delete_file,
    get_file_size,
    get_file_hash,
    resolve_hostname,
    reverse_dns_lookup,
    get_common_ports,
    get_ip_info,
    geoiplookup,
    get_data_from_post_request,
    safe_int_cast,
    get_ips_from_cidr_range,
)


class TestDataUtilities(BaseTestCase):
    """Test data manipulation utilities."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_is_iterable(self):
        """Test is_iterable function."""
        # Test with various iterable types
        self.assertTrue(is_iterable([1, 2, 3]))
        self.assertTrue(is_iterable((1, 2, 3)))
        self.assertTrue(is_iterable({1, 2, 3}))
        self.assertTrue(is_iterable({'a': 1, 'b': 2}))
        self.assertTrue(is_iterable("hello"))
        self.assertTrue(is_iterable(range(5)))
        
        # Test with non-iterable types
        self.assertFalse(is_iterable(123))
        self.assertFalse(is_iterable(True))
        self.assertFalse(is_iterable(None))

    def test_replace_nulls(self):
        """Test replace_nulls function."""
        # Test with various data types
        self.assertEqual(replace_nulls("hello"), "hello")
        self.assertEqual(replace_nulls(None), "")
        self.assertEqual(replace_nulls(123), 123)
        self.assertEqual(replace_nulls(0), 0)
        self.assertEqual(replace_nulls(""), "")
        
        # Test with custom replacement
        self.assertEqual(replace_nulls(None, "N/A"), "N/A")
        self.assertEqual(replace_nulls("", "empty"), "empty")

    def test_chunk_list(self):
        """Test chunk_list function."""
        # Test normal chunking
        data = list(range(10))
        chunks = list(chunk_list(data, 3))
        expected = [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
        self.assertEqual(chunks, expected)
        
        # Test with empty list
        self.assertEqual(list(chunk_list([], 3)), [])
        
        # Test with chunk size larger than list
        data = [1, 2, 3]
        chunks = list(chunk_list(data, 5))
        self.assertEqual(chunks, [[1, 2, 3]])
        
        # Test with chunk size 1
        data = [1, 2, 3]
        chunks = list(chunk_list(data, 1))
        self.assertEqual(chunks, [[1], [2], [3]])


class TestFormattingUtilities(BaseTestCase):
    """Test formatting utilities."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_format_duration(self):
        """Test format_duration function."""
        # Test various durations
        self.assertEqual(format_duration(0), "0s")
        self.assertEqual(format_duration(30), "30s")
        self.assertEqual(format_duration(60), "1m")
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(format_duration(3600), "1h")
        self.assertEqual(format_duration(3661), "1h 1m 1s")
        self.assertEqual(format_duration(86400), "1d")
        self.assertEqual(format_duration(90061), "1d 1h 1m 1s")

    def test_format_bytes(self):
        """Test format_bytes function."""
        # Test various byte sizes
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024), "1.0 GB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 1024), "1.0 TB")
        
        # Test with decimal places
        self.assertEqual(format_bytes(1536), "1.5 KB")
        self.assertEqual(format_bytes(1536, 2), "1.50 KB")


class TestValidationUtilities(BaseTestCase):
    """Test validation utilities."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_parse_url(self):
        """Test parse_url function."""
        # Test valid URLs
        result = parse_url("https://example.com/path?query=1")
        self.assertEqual(result.scheme, "https")
        self.assertEqual(result.netloc, "example.com")
        self.assertEqual(result.path, "/path")
        self.assertEqual(result.query, "query=1")
        
        # Test invalid URL
        result = parse_url("not-a-url")
        self.assertIsNone(result)

    def test_extract_domain_from_url(self):
        """Test extract_domain_from_url function."""
        # Test various URL formats
        self.assertEqual(extract_domain_from_url("https://example.com/path"), "example.com")
        self.assertEqual(extract_domain_from_url("http://sub.example.com:8080/path"), "sub.example.com")
        self.assertEqual(extract_domain_from_url("ftp://example.com"), "example.com")
        self.assertEqual(extract_domain_from_url("example.com"), "example.com")
        
        # Test invalid URLs
        self.assertIsNone(extract_domain_from_url("not-a-url"))
        self.assertIsNone(extract_domain_from_url(""))

    def test_is_valid_url(self):
        """Test is_valid_url function."""
        # Test valid URLs
        self.assertTrue(is_valid_url("https://example.com"))
        self.assertTrue(is_valid_url("http://example.com/path"))
        self.assertTrue(is_valid_url("ftp://example.com"))
        self.assertTrue(is_valid_url("https://sub.example.com:8080/path?query=1"))
        
        # Test invalid URLs
        self.assertFalse(is_valid_url("not-a-url"))
        self.assertFalse(is_valid_url(""))
        self.assertFalse(is_valid_url("example.com"))  # Missing scheme

    def test_is_valid_domain(self):
        """Test is_valid_domain function."""
        # Test valid domains
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.com"))
        self.assertTrue(is_valid_domain("a.b.c.d.e"))
        self.assertTrue(is_valid_domain("example.co.uk"))
        
        # Test invalid domains
        self.assertFalse(is_valid_domain(""))
        self.assertFalse(is_valid_domain("."))
        self.assertFalse(is_valid_domain("example"))
        self.assertFalse(is_valid_domain("example."))
        self.assertFalse(is_valid_domain(".example.com"))

    def test_is_valid_ip(self):
        """Test is_valid_ip function."""
        # Test valid IPv4 addresses
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))
        
        # Test valid IPv6 addresses
        self.assertTrue(is_valid_ip("2001:db8::1"))
        self.assertTrue(is_valid_ip("::1"))
        self.assertTrue(is_valid_ip("fe80::1"))
        
        # Test invalid IP addresses
        self.assertFalse(is_valid_ip(""))
        self.assertFalse(is_valid_ip("256.256.256.256"))
        self.assertFalse(is_valid_ip("192.168.1"))
        self.assertFalse(is_valid_ip("not-an-ip"))

    def test_is_valid_port(self):
        """Test is_valid_port function."""
        # Test valid ports
        self.assertTrue(is_valid_port(1))
        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port(443))
        self.assertTrue(is_valid_port(65535))
        
        # Test invalid ports
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port(-1))
        self.assertFalse(is_valid_port("80"))

    def test_is_valid_cidr(self):
        """Test is_valid_cidr function."""
        # Test valid CIDR blocks
        self.assertTrue(is_valid_cidr("192.168.1.0/24"))
        self.assertTrue(is_valid_cidr("10.0.0.0/8"))
        self.assertTrue(is_valid_cidr("172.16.0.0/12"))
        self.assertTrue(is_valid_cidr("2001:db8::/32"))
        
        # Test invalid CIDR blocks
        self.assertFalse(is_valid_cidr(""))
        self.assertFalse(is_valid_cidr("192.168.1.1"))
        self.assertFalse(is_valid_cidr("192.168.1.0/33"))
        self.assertFalse(is_valid_cidr("not-a-cidr"))


class TestFileUtilities(BaseTestCase):
    """Test file operation utilities."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_content = "Hello, World!\nThis is a test file."

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        super().tearDown()

    def test_read_file_content(self):
        """Test read_file_content function."""
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_content)
        
        # Test reading file
        content = read_file_content(self.test_file)
        self.assertEqual(content, self.test_content)
        
        # Test reading non-existent file
        content = read_file_content("non-existent.txt")
        self.assertEqual(content, "")

    def test_write_file_content(self):
        """Test write_file_content function."""
        # Test writing file
        result = write_file_content(self.test_file, self.test_content)
        self.assertTrue(result)
        
        # Verify content
        with open(self.test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, self.test_content)
        
        # Test writing to invalid path
        result = write_file_content("/invalid/path/file.txt", "content")
        self.assertFalse(result)

    def test_create_temp_file(self):
        """Test create_temp_file function."""
        # Test creating temp file
        temp_file = create_temp_file(self.test_content)
        self.assertIsNotNone(temp_file)
        self.assertTrue(os.path.exists(temp_file))
        
        # Verify content
        with open(temp_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, self.test_content)
        
        # Clean up
        os.unlink(temp_file)

    def test_delete_file(self):
        """Test delete_file function."""
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_content)
        
        # Test deleting file
        result = delete_file(self.test_file)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_file))
        
        # Test deleting non-existent file
        result = delete_file("non-existent.txt")
        self.assertFalse(result)

    def test_get_file_size(self):
        """Test get_file_size function."""
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_content)
        
        # Test getting file size
        size = get_file_size(self.test_file)
        self.assertEqual(size, len(self.test_content.encode('utf-8')))
        
        # Test getting size of non-existent file
        size = get_file_size("non-existent.txt")
        self.assertEqual(size, 0)

    @patch('hashlib.new')
    def test_get_file_hash(self, mock_new):
        """Test get_file_hash function."""
        # Create test file
        with open(self.test_file, 'w') as f:
            f.write(self.test_content)
        
        # Mock hash
        mock_hash = MagicMock()
        mock_hash.hexdigest.return_value = "test-hash"
        mock_new.return_value = mock_hash
        
        # Test getting file hash
        file_hash = get_file_hash(self.test_file)
        self.assertEqual(file_hash, "test-hash")
        
        # Test getting hash of non-existent file
        file_hash = get_file_hash("non-existent.txt")
        self.assertEqual(file_hash, "")


class TestNetworkUtilities(BaseTestCase):
    """Test network operation utilities."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch('socket.gethostbyname_ex')
    def test_resolve_hostname(self, mock_gethostbyname_ex):
        """Test resolve_hostname function."""
        # Test successful resolution
        mock_gethostbyname_ex.return_value = ("example.com", [], ["192.168.1.1"])
        ip = resolve_hostname("example.com")
        self.assertEqual(ip, ["192.168.1.1"])
        
        # Test failed resolution
        import socket
        mock_gethostbyname_ex.side_effect = socket.gaierror("Resolution failed")
        ip = resolve_hostname("invalid-domain.com")
        self.assertEqual(ip, [])

    @patch('socket.gethostbyaddr')
    def test_reverse_dns_lookup(self, mock_gethostbyaddr):
        """Test reverse_dns_lookup function."""
        # Test successful reverse lookup
        mock_gethostbyaddr.return_value = ("example.com", [], ["192.168.1.1"])
        hostname = reverse_dns_lookup("192.168.1.1")
        self.assertEqual(hostname, "example.com")
        
        # Test failed reverse lookup
        import socket
        mock_gethostbyaddr.side_effect = socket.herror("Reverse lookup failed")
        hostname = reverse_dns_lookup("192.168.1.1")
        self.assertIsNone(hostname)

    def test_get_common_ports(self):
        """Test get_common_ports function."""
        # Test getting common ports
        ports = get_common_ports()
        self.assertIsInstance(ports, list)
        self.assertGreater(len(ports), 0)
        
        # Test that all ports are valid
        for port in ports:
            self.assertIsInstance(port, int)
            self.assertGreaterEqual(port, 1)
            self.assertLessEqual(port, 65535)
        
        # Test getting specific number of ports
        ports = get_common_ports(5)
        self.assertEqual(len(ports), 5)

    def test_get_ip_info(self):
        """Test get_ip_info function."""
        # Test IPv4 address
        ip_info = get_ip_info("192.168.1.1")
        self.assertIsNotNone(ip_info)
        self.assertEqual(str(ip_info), "192.168.1.1")
        
        # Test IPv6 address
        ip_info = get_ip_info("2001:db8::1")
        self.assertIsNotNone(ip_info)
        self.assertEqual(str(ip_info), "2001:db8::1")
        
        # Test invalid IP
        ip_info = get_ip_info("invalid-ip")
        self.assertIsNone(ip_info)

    @patch('subprocess.run')
    def test_geoiplookup(self, mock_run):
        """Test geoiplookup function."""
        # Mock successful geoiplookup
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "GeoIP Country Edition: US, United States"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, country_iso, country_name, error = geoiplookup("8.8.8.8")
        self.assertTrue(success)
        self.assertEqual(country_iso, "US")
        self.assertEqual(country_name, "United States")
        self.assertIsNone(error)
        
        # Test failed geoiplookup
        mock_result.returncode = 1
        mock_result.stderr = "geoiplookup failed"
        mock_run.return_value = mock_result
        
        success, country_iso, country_name, error = geoiplookup("8.8.8.8")
        self.assertFalse(success)
        self.assertIsNone(country_iso)
        self.assertIsNone(country_name)
        self.assertIsNotNone(error)

    def test_get_data_from_post_request(self):
        """Test get_data_from_post_request function."""
        # Mock request with getlist method
        mock_request = MagicMock()
        mock_request.data.getlist.return_value = ["value1", "value2"]
        
        result = get_data_from_post_request(mock_request, "field")
        self.assertEqual(result, ["value1", "value2"])
        
        # Mock request without getlist method
        mock_request = MagicMock()
        mock_request.data.get.return_value = "single_value"
        del mock_request.data.getlist
        
        result = get_data_from_post_request(mock_request, "field")
        self.assertEqual(result, "single_value")

    def test_safe_int_cast(self):
        """Test safe_int_cast function."""
        # Test valid integers
        self.assertEqual(safe_int_cast("123"), 123)
        self.assertEqual(safe_int_cast(456), 456)
        
        # Test invalid values
        self.assertIsNone(safe_int_cast("invalid"))
        self.assertIsNone(safe_int_cast(None))
        self.assertEqual(safe_int_cast("invalid", 0), 0)
        
        # Test with lists
        result = safe_int_cast(["123", "456", "invalid"])
        self.assertEqual(result, [123, 456, None])

    def test_get_ips_from_cidr_range(self):
        """Test get_ips_from_cidr_range function."""
        # Test valid CIDR
        ips = get_ips_from_cidr_range("192.168.1.0/30")
        expected_ips = ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]
        self.assertEqual(ips, expected_ips)
        
        # Test invalid CIDR
        ips = get_ips_from_cidr_range("invalid-cidr")
        self.assertEqual(ips, [])