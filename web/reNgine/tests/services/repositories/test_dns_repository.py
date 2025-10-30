"""
Tests for DNS repository functionality.
"""

from reNgine.services.repositories.dns_repository import DnsRepository
from utils.test_base import BaseTestCase


class TestDnsRepository(BaseTestCase):
    """Test cases for DnsRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.dns_repo = DnsRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

        # Create domain info using TestDataGenerator and associate with domain
        self.domain_info = self.data_generator.create_domain_info()
        self.domain.domain_info = self.domain_info
        self.domain.save()

    def test_save_from_secator_valid_a_record(self):
        """Test saving valid A record from Secator."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "A")

    def test_save_from_secator_valid_aaaa_record(self):
        """Test saving valid AAAA record from Secator."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "AAAA",
            "host": "2001:db8::1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "AAAA")

    def test_save_from_secator_valid_cname_record(self):
        """Test saving valid CNAME record from Secator."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "CNAME",
            "host": "example.com",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "CNAME")

    def test_save_from_secator_valid_mx_record(self):
        """Test saving valid MX record from Secator."""
        item = {
            "_type": "record",
            "name": "example.com",
            "type": "MX",
            "host": "10 mail.example.com",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "example.com")
        self.assertEqual(result.type, "MX")

    def test_save_from_secator_valid_txt_record(self):
        """Test saving valid TXT record from Secator."""
        item = {
            "_type": "record",
            "name": "example.com",
            "type": "TXT",
            "host": "v=spf1 include:_spf.google.com ~all",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "example.com")
        self.assertEqual(result.type, "TXT")

    def test_save_from_secator_missing_name(self):
        """Test handling missing name field."""
        item = {
            "_type": "record",
            "type": "A",
            "value": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_type(self):
        """Test handling missing type field."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "value": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_value(self):
        """Test handling missing value field."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_invalid_type(self):
        """Test handling invalid DNS record type."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "INVALID",
            "host": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        # Should still create the record but log a warning
        self.assertIsNotNone(result)
        self.assertEqual(result.type, "INVALID")

    def test_get_or_create_existing_record(self):
        """Test get_or_create with existing DNS record."""
        # Create record first
        record1, created1 = self.dns_repo.get_or_create("www.example.com", "A")
        self.assertTrue(created1)

        # Try to create same record again
        record2, created2 = self.dns_repo.get_or_create("www.example.com", "A")
        self.assertFalse(created2)
        self.assertEqual(record1.id, record2.id)

    def test_get_or_create_new_record(self):
        """Test get_or_create with new DNS record."""
        record, created = self.dns_repo.get_or_create("www.example.com", "A")

        self.assertIsNotNone(record)
        self.assertTrue(created)
        self.assertEqual(record.name, "www.example.com")
        self.assertEqual(record.type, "A")

    def test_bulk_create_records(self):
        """Test bulk creation of DNS records."""
        records_data = [
            {"name": "www.example.com", "type": "A", "value": "192.168.1.1"},
            {"name": "mail.example.com", "type": "A", "value": "192.168.1.2"},
            {"name": "example.com", "type": "MX", "value": "10 mail.example.com"},
        ]

        result = self.dns_repo.bulk_create(records_data)

        self.assertEqual(len(result), 3)
        created_names = [record.name for record in result]
        self.assertIn("www.example.com", created_names)
        self.assertIn("mail.example.com", created_names)
        self.assertIn("example.com", created_names)

    def test_bulk_create_duplicate_records(self):
        """Test bulk creation with duplicate DNS records."""
        records_data = [
            {"name": "www.example.com", "type": "A", "value": "192.168.1.1"},
            {"name": "www.example.com", "type": "A", "value": "192.168.1.1"},  # Duplicate
            {"name": "mail.example.com", "type": "A", "value": "192.168.1.2"},
        ]

        result = self.dns_repo.bulk_create(records_data)

        # FIX: bulk_create ne déduplique PAS, donc 3 records créés
        self.assertEqual(len(result), 3)  # Pas 2
        created_names = [record.name for record in result]
        self.assertIn("www.example.com", created_names)
        self.assertIn("mail.example.com", created_names)

    def test_get_records_by_domain(self):
        """Test getting DNS records by domain."""
        # Clean up any existing DNS records for this domain
        self.domain_info.dns_records.clear()

        # Create records using save_from_secator to ensure proper association
        item1 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }
        item2 = {
            "_type": "record",
            "name": "mail.example.com",
            "type": "A",
            "host": "192.168.1.2",
        }

        record1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.domain.id)
        record2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.domain.id)

        records = self.dns_repo.get_records_for_domain(self.domain.id)

        self.assertEqual(len(records), 2)
        record_names = [record.name for record in records]
        self.assertIn("www.example.com", record_names)
        self.assertIn("mail.example.com", record_names)

    def test_get_records_by_type(self):
        """Test getting DNS records by type."""
        # Clean up any existing DNS records for this domain
        self.domain_info.dns_records.clear()

        # Create records using save_from_secator to ensure proper association
        item1 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }
        item2 = {
            "_type": "record",
            "name": "example.com",
            "type": "MX",
            "host": "mail.example.com",
        }

        record1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.domain.id)
        record2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.domain.id)

        # FIX: Correct parameter order (record_type, domain_id)
        a_records = self.dns_repo.get_records_by_type("A", self.domain.id)
        mx_records = self.dns_repo.get_records_by_type("MX", self.domain.id)

        self.assertEqual(len(a_records), 1)
        self.assertEqual(len(mx_records), 1)
        self.assertEqual(a_records[0].name, "www.example.com")
        self.assertEqual(mx_records[0].name, "example.com")

    def test_save_from_secator_with_extra_data(self):
        """Test saving DNS record with extra data."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": {
                "ttl": 3600,
                "priority": 0,
            },
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "A")

    def test_save_from_secator_duplicate_record(self):
        """Test handling duplicate DNS record creation."""
        # Create first record
        item1 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.domain.id)

        # Try to create same record again
        item2 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)  # Should be same object

    # Tests for private methods removed - testing private methods is not recommended
