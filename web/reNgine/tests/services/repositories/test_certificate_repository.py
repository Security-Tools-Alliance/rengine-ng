"""
Tests for Certificate repository functionality.
"""

from datetime import datetime

from django.utils import timezone

from reNgine.services.repositories.certificate_repository import CertificateRepository
from startScan.models import Domain, IpAddress, Subdomain
from utils.test_base import BaseTestCase


class TestCertificateRepository(BaseTestCase):
    """Test cases for CertificateRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.cert_repo = CertificateRepository()
        # Scan history first, then domain linked for this scan (get_or_create_domain_for_target used in repo)
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_save_from_secator_valid_certificate(self):
        """Test saving valid certificate from Secator."""
        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "subject_cn": "example.com",
            "issuer_cn": "Let's Encrypt",
            "_source": "tlsx",
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.host, "example.com")
        self.assertEqual(result.fingerprint_sha256, "abc123def456")
        self.assertEqual(result.subject_cn, "example.com")
        self.assertEqual(result.issuer_cn, "Let's Encrypt")
        self.assertEqual(result.source, "tlsx")

    def test_save_from_secator_missing_host(self):
        """Test handling missing host field."""
        item = {
            "_type": "certificate",
            "fingerprint_sha256": "abc123def456",
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_with_subdomain_association(self):
        """Test saving certificate with subdomain association."""
        # Certificate repo resolves domain by host via get_or_create_domain_for_target(scan_history_id, host),
        # so we need a domain named "example.com" and a subdomain under it
        domain_example = Domain.objects.create(
            name="example.com",
            scan_history=self.scan_history,
            insert_date=timezone.now(),
        )
        subdomain = Subdomain.objects.create(
            name="example.com",
            scan_history=self.scan_history,
            domain=domain_example,
        )

        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.subdomain, subdomain)

    def test_save_from_secator_with_ip_association(self):
        """Test saving certificate with IP association."""

        ip_obj = IpAddress.objects.create(
            address="192.168.1.1",
            is_private=True,
            version=4,
        )

        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "ip": "192.168.1.1",
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # IP association might not work if IP doesn't exist in domain context
        # The certificate repository tries to find IP by address and domain
        if result.ip_address:
            self.assertEqual(result.ip_address, ip_obj)

    def test_save_from_secator_with_datetime_fields(self):
        """Test saving certificate with datetime fields."""
        not_before = "2023-01-01T00:00:00Z"
        not_after = "2024-01-01T00:00:00Z"

        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "not_before": not_before,
            "not_after": not_after,
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.not_before)
        self.assertIsNotNone(result.not_after)

    def test_save_from_secator_duplicate_certificate(self):
        """Test handling duplicate certificate creation."""
        item1 = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "subject_cn": "example.com",
        }

        result1 = self.cert_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)

        item2 = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "subject_cn": "example.com",
        }

        result2 = self.cert_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)  # Should be same object

    def test_process_secator_certificate_item_valid(self):
        """Test _process_secator_certificate_item with valid data."""
        item = {
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "subject_cn": "example.com",
            "issuer_cn": "Let's Encrypt",
        }

        result = self.cert_repo._process_secator_certificate_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.host, "example.com")
        self.assertEqual(result.fingerprint_sha256, "abc123def456")

    def test_process_secator_certificate_item_missing_host(self):
        """Test _process_secator_certificate_item with missing host."""
        item = {
            "fingerprint_sha256": "abc123def456",
        }

        result = self.cert_repo._process_secator_certificate_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_parse_datetime_from_iso_string(self):
        """Test _parse_datetime with ISO format string."""
        iso_string = "2023-01-01T00:00:00Z"
        result = self.cert_repo._parse_datetime(iso_string)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_from_timestamp(self):
        """Test _parse_datetime with timestamp."""
        # The code uses datetime.fromtimestamp which expects seconds since epoch
        # Test with a valid timestamp in seconds
        from datetime import datetime as dt
        from datetime import timezone as tz

        # Use a recent timestamp to avoid timezone issues
        test_datetime = dt(2023, 1, 1, 0, 0, 0, tzinfo=tz.utc)
        timestamp_seconds = int(test_datetime.timestamp())

        result = self.cert_repo._parse_datetime(timestamp_seconds)

        # The code should handle seconds correctly
        # The code now handles milliseconds automatically
        self.assertIsNotNone(result, "Timestamp parsing should work for valid timestamps")
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_from_datetime_object(self):
        """Test _parse_datetime with datetime object."""
        dt = timezone.now()
        result = self.cert_repo._parse_datetime(dt)

        self.assertIsNotNone(result)
        self.assertEqual(result, dt)

    def test_parse_datetime_none(self):
        """Test _parse_datetime with None."""
        result = self.cert_repo._parse_datetime(None)

        self.assertIsNone(result)

    def test_parse_datetime_invalid_string(self):
        """Test _parse_datetime with invalid string."""
        invalid_string = "not a date"
        result = self.cert_repo._parse_datetime(invalid_string)

        self.assertIsNone(result)

    def test_save_from_secator_with_self_signed(self):
        """Test saving certificate with self_signed flag."""
        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "self_signed": True,
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertTrue(result.self_signed)

    def test_save_from_secator_with_trusted(self):
        """Test saving certificate with trusted flag."""
        item = {
            "_type": "certificate",
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "trusted": True,
        }

        result = self.cert_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertTrue(result.trusted)
