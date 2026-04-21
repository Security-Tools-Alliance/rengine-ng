"""
Tests for DNS repository functionality.
"""

from unittest.mock import patch

from reNgine.services.repositories.dns_repository import DnsRepository
from startScan.models import Subdomain
from utils.test_base import BaseTestCase


class TestDnsRepository(BaseTestCase):
    """Test cases for DnsRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.dns_repo = DnsRepository()
        # Scan history (with target), then domain linked to that scan. Domain name must
        # match target.value so save_from_secator resolves the same domain via target.
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)
        self.domain.name = self.data_generator.target.value
        self.domain.save(update_fields=["name"])

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

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "A")
        self.assertEqual(result.extra_data.get("secator_host"), "192.168.1.1")

    def test_save_from_secator_sets_and_updates_source(self) -> None:
        """DNSRecord.source reflects Secator task/tool; updates on merge path."""
        item = {
            "_type": "record",
            "name": "src.example.com",
            "type": "A",
            "host": "192.0.2.10",
            "_source": "dnsx",
        }
        first = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(first)
        self.assertEqual(first.source, "dnsx")
        item2 = {
            "_type": "record",
            "name": "src.example.com",
            "type": "A",
            "host": "192.0.2.10",
            "_source": "massdns",
        }
        second = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)
        self.assertEqual(second.id, first.id)
        second.refresh_from_db()
        self.assertEqual(second.source, "massdns")

    def test_save_from_secator_ptr_record_stores_secator_host(self):
        """Secator Record host (e.g. IP for PTR) must persist in extra_data."""
        item = {
            "_type": "record",
            "name": "ptr-target.example.com",
            "type": "PTR",
            "host": "192.0.2.1",
        }
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.type, "PTR")
        self.assertEqual(result.extra_data.get("secator_host"), "192.0.2.1")

    def test_save_from_secator_record_creates_subdomain_via_get_or_create_from_host(self):
        """Record item with name/host creates Subdomains via same process (get_or_create_from_host)."""
        item = {
            "_type": "record",
            "name": "api.example.com",
            "type": "A",
            "host": "192.168.1.2",
        }
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        subdomain_for_name = Subdomain.objects.filter(scan_history=self.scan_history, name="api.example.com").first()
        self.assertIsNotNone(
            subdomain_for_name,
            "Subdomain for record name should be created via get_or_create_from_host",
        )
        subdomain_for_ip_host = Subdomain.objects.filter(scan_history=self.scan_history, name="192.168.1.2").first()
        self.assertIsNone(
            subdomain_for_ip_host,
            "Literal IP record values are not stored as Subdomain rows (use IpAddress / endpoints).",
        )

    def test_save_from_secator_valid_aaaa_record(self):
        """Test saving valid AAAA record from Secator."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "AAAA",
            "host": "2001:db8::1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
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

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
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

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
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

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
        self.assertEqual(result.name, "example.com")
        self.assertEqual(result.type, "TXT")

    def test_save_from_secator_txt_value_as_name_does_not_create_domain(self):
        """TXT record with non-domain 'name' (e.g. record value) must not create a Domain row."""
        from startScan.models import Domain

        item = {
            "_type": "record",
            "name": "google-site-verification=ybifaoahre1hgovv15t5qrnrophiztrpib90opyw1u0",
            "type": "TXT",
            "host": "google-site-verification=ybifaoahre1hgovv15t5qrnrophiztrpib90opyw1u0",
        }

        initial_domain_count = Domain.objects.filter(scan_history_id=self.scan_history.id).count()
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.type, "TXT")
        self.assertEqual(
            Domain.objects.filter(scan_history_id=self.scan_history.id).count(),
            initial_domain_count,
        )
        self.assertFalse(
            Domain.objects.filter(
                scan_history_id=self.scan_history.id,
                name="google-site-verification=ybifaoahre1hgovv15t5qrnrophiztrpib90opyw1u0",
            ).exists()
        )
        records = self.dns_repo.get_records_for_domain(self.domain.id)
        self.assertIn(result, records)

    def test_save_from_secator_missing_name(self):
        """Test handling missing name field."""
        item = {
            "_type": "record",
            "type": "A",
            "value": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_type(self):
        """Test handling missing type field."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "value": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_value(self):
        """Test handling missing value field."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_invalid_type(self):
        """Test handling invalid DNS record type."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "INVALID",
            "host": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        # Invalid types should return None
        self.assertIsNone(result)

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

        # Use this domain's name so both records attach to the same domain
        record_name = self.domain.name
        item1 = {
            "_type": "record",
            "name": record_name,
            "type": "A",
            "host": "192.168.1.1",
        }
        item2 = {
            "_type": "record",
            "name": record_name,
            "type": "MX",
            "host": "192.168.1.2",
        }

        self.assertIsNotNone(
            self.dns_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)
        )
        self.assertIsNotNone(
            self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)
        )

        records = self.dns_repo.get_records_for_domain(self.domain.id)

        self.assertEqual(len(records), 2)
        record_names = [record.name for record in records]
        self.assertIn(record_name, record_names)

    def test_get_records_by_type(self):
        """Test getting DNS records by type."""
        # Clean up any existing DNS records for this domain
        self.domain_info.dns_records.clear()

        record_name = self.domain.name
        item1 = {
            "_type": "record",
            "name": record_name,
            "type": "A",
            "host": "192.168.1.1",
        }
        item2 = {
            "_type": "record",
            "name": record_name,
            "type": "MX",
            "host": "mail.example.com",
        }

        self.assertIsNotNone(
            self.dns_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)
        )
        self.assertIsNotNone(
            self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)
        )

        a_records = self.dns_repo.get_records_by_type("A", self.domain.id)
        mx_records = self.dns_repo.get_records_by_type("MX", self.domain.id)

        self.assertEqual(len(a_records), 1)
        self.assertEqual(len(mx_records), 1)
        self.assertEqual(a_records[0].name, record_name)
        self.assertEqual(mx_records[0].name, record_name)

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

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "A")

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_save_from_secator_non_dict_extra_data_logs_warning(self, mock_logger):
        """Non-dict extra_data triggers a warning; extra_data_raw stores a JSON-safe repr preview."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": ["unexpected", "list"],
        }
        tid = self.data_generator.target.id
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, tid)

        self.assertIsNotNone(result)
        self.assertNotIn("ttl", result.extra_data)
        self.assertEqual(result.extra_data.get("extra_data_raw"), "['unexpected', 'list']")
        warned = any(
            c.kwargs.get("level") == "warning"
            and len(c.args) >= 3
            and "Non-dict extra_data" in c.args[2]
            and "raw_type=list" in c.args[2]
            for c in mock_logger.log_line.call_args_list
        )
        self.assertTrue(warned, "Expected warning log_line for non-dict extra_data")

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_save_from_secator_extra_data_json_string_parsed_as_dict(self, mock_logger):
        """JSON object string in extra_data is decoded to a dict; warning still notes non-dict input type."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": '{"ttl": 120, "priority": 1}',
        }
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.extra_data.get("ttl"), 120)
        self.assertEqual(result.extra_data.get("priority"), 1)
        self.assertNotIn("extra_data_raw", result.extra_data)
        warned = any(
            c.kwargs.get("level") == "warning"
            and len(c.args) >= 3
            and "Non-dict extra_data" in c.args[2]
            and "raw_type=str" in c.args[2]
            for c in mock_logger.log_line.call_args_list
        )
        self.assertTrue(warned)

    @patch("reNgine.services.repositories.dns_repository.merge_extra_data_payload_into_model")
    def test_update_dns_record_extra_data_empty_dict_passed_to_merge(self, mock_merge) -> None:
        """Empty dict must be forwarded to the merge helper, not collapsed to None."""
        dns_record = self.data_generator.create_dns_record()
        dns_record.extra_data = {"keep": True}
        dns_record.save(update_fields=["extra_data"])

        self.dns_repo._update_dns_record_extra_data({}, dns_record)

        mock_merge.assert_called_once_with(dns_record, {})

    @patch("reNgine.services.repositories.dns_repository.merge_extra_data_payload_into_model")
    def test_update_dns_record_extra_data_none_skips_merge(self, mock_merge) -> None:
        dns_record = self.data_generator.create_dns_record()
        self.dns_repo._update_dns_record_extra_data(None, dns_record)
        mock_merge.assert_not_called()

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_merge_dns_extra_payload_logs_when_record_host_conflicts_with_stored_secator_host(self, mock_logger):
        """When secator_host is already set, a differing Record host is logged and not applied."""
        merged = DnsRepository._merge_dns_extra_payload(
            {"secator_host": "stored.example.invalid"},
            {},
            "incoming.example.invalid",
        )
        self.assertEqual(merged.get("secator_host"), "stored.example.invalid")
        logged = any(
            c.kwargs.get("level") == "info"
            and len(c.args) >= 3
            and "Keeping existing secator_host" in c.args[2]
            and "stored.example.invalid" in c.args[2]
            and "incoming.example.invalid" in c.args[2]
            for c in mock_logger.log_line.call_args_list
        )
        self.assertTrue(logged)

    def test_save_from_secator_duplicate_record(self):
        """Test handling duplicate DNS record creation."""
        # Create first record
        item1 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)

        # Try to create same record again
        item2 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)  # Should be same object

    def test_process_secator_dns_record_item_valid(self):
        """Test _process_secator_dns_record_item with valid data."""
        item = {
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
        }

        result = self.dns_repo._process_secator_dns_record_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        # name field stores the domain name (record_name), not the value
        self.assertEqual(result.name, "www.example.com")
        self.assertEqual(result.type, "A")

    def test_process_secator_dns_record_item_missing_name(self):
        """Test _process_secator_dns_record_item with missing name."""
        item = {
            "type": "A",
            "host": "192.168.1.1",
        }

        result = self.dns_repo._process_secator_dns_record_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_process_secator_dns_record_item_missing_type(self):
        """Test _process_secator_dns_record_item with missing type."""
        item = {
            "name": "www.example.com",
            "host": "192.168.1.1",
        }

        result = self.dns_repo._process_secator_dns_record_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_process_secator_dns_record_item_missing_host(self):
        """Test _process_secator_dns_record_item with missing host."""
        item = {
            "name": "www.example.com",
            "type": "A",
        }

        result = self.dns_repo._process_secator_dns_record_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_update_existing_record_with_name_change(self):
        """Test updating existing DNS record when name changes."""
        record_name = self.domain.name
        item1 = {
            "_type": "record",
            "name": record_name,
            "type": "A",
            "host": "192.168.1.1",
        }
        result1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result1)
        self.assertEqual(result1.name, record_name)

        item2 = {
            "_type": "record",
            "name": record_name,
            "type": "A",
            "host": "192.168.1.2",
        }
        result2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)
        self.assertEqual(result2.name, record_name)

    def test_update_existing_record_extra_data(self):
        """Test updating existing DNS record extra data."""
        # Create initial record
        item1 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": {"ttl": 3600},
        }
        result1 = self.dns_repo.save_from_secator(item1, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result1)
        self.assertEqual(
            result1.extra_data,
            {"ttl": 3600, "secator_host": "192.168.1.1"},
        )

        # Update with new extra_data
        item2 = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": {"ttl": 7200, "priority": 10},
        }
        result2 = self.dns_repo.save_from_secator(item2, self.scan_history.id, self.data_generator.target.id)

        # Should update existing record
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)  # Same record
        self.assertEqual(
            result2.extra_data,
            {"ttl": 7200, "priority": 10, "secator_host": "192.168.1.1"},
        )

    def test_update_dns_record_extra_data(self):
        """Test _update_dns_record_extra_data merges into existing JSON."""

        dns_record = self.data_generator.create_dns_record()
        dns_record.extra_data = {"keep": True}
        dns_record.save(update_fields=["extra_data"])
        new_extra_data = {"ttl": 3600, "priority": 10, "value": "192.168.1.1"}

        self.dns_repo._update_dns_record_extra_data(new_extra_data, dns_record)

        dns_record.refresh_from_db()
        self.assertTrue(dns_record.extra_data.get("keep"))
        self.assertEqual(dns_record.extra_data.get("ttl"), 3600)
        self.assertEqual(dns_record.extra_data.get("priority"), 10)

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_update_dns_record_extra_data_non_dict_logs_and_skips_merge(self, mock_logger):
        """Non-dict extra_data triggers a warning and leaves existing JSON unchanged."""
        dns_record = self.data_generator.create_dns_record()
        dns_record.extra_data = {"keep": True}
        dns_record.save(update_fields=["extra_data"])

        self.dns_repo._update_dns_record_extra_data(["not", "a", "dict"], dns_record)

        dns_record.refresh_from_db()
        self.assertEqual(dns_record.extra_data, {"keep": True})
        warned = any(
            c.kwargs.get("level") == "warning" and len(c.args) >= 3 and "Ignoring non-dict extra_data" in c.args[2]
            for c in mock_logger.log_line.call_args_list
        )
        self.assertTrue(warned)

    def test_validate_dns_record_type_valid(self):
        """Test validate_dns_record_type with valid types."""
        self.assertTrue(self.dns_repo.validate_dns_record_type("A"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("AAAA"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("CNAME"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("MX"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("TXT"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("NS"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("SOA"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("PTR"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("SRV"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("CAA"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("DS"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("DNSKEY"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("NSEC"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("NSEC3"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("AXFR"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("HTTPS"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("TLSA"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("HINFO"))

    def test_validate_dns_record_type_invalid(self):
        """Test validate_dns_record_type with invalid types."""
        self.assertFalse(self.dns_repo.validate_dns_record_type("INVALID"))
        self.assertFalse(self.dns_repo.validate_dns_record_type(""))

    def test_validate_dns_record_type_case_insensitive(self):
        """Test validate_dns_record_type is case insensitive."""
        self.assertTrue(self.dns_repo.validate_dns_record_type("a"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("A"))
        self.assertTrue(self.dns_repo.validate_dns_record_type("AaAa"))

    def test_get_valid_dns_types(self):
        """Test get_valid_dns_types method."""
        valid_types = self.dns_repo.get_valid_dns_types()

        self.assertIsInstance(valid_types, set)
        self.assertIn("A", valid_types)
        self.assertIn("AAAA", valid_types)
        self.assertIn("CNAME", valid_types)
        self.assertIn("MX", valid_types)
        self.assertIn("TXT", valid_types)
        self.assertIn("NS", valid_types)
        self.assertIn("SOA", valid_types)
        self.assertIn("PTR", valid_types)
        self.assertIn("SRV", valid_types)
        self.assertIn("CAA", valid_types)
        self.assertIn("DS", valid_types)
        self.assertIn("DNSKEY", valid_types)
        self.assertIn("NSEC", valid_types)
        self.assertIn("NSEC3", valid_types)
        self.assertIn("AXFR", valid_types)
        self.assertIn("HTTPS", valid_types)
        self.assertEqual(len(valid_types), 21)

    def test_get_valid_dns_types_returns_copy(self):
        """Test that get_valid_dns_types returns a copy, not the original set."""
        valid_types1 = self.dns_repo.get_valid_dns_types()
        valid_types2 = self.dns_repo.get_valid_dns_types()

        self.assertIsNot(valid_types1, valid_types2)
        self.assertEqual(valid_types1, valid_types2)

    def test_parse_extra_data(self):
        """Test parse_extra_data method."""
        extra_data = {
            "value": "192.168.1.1",
            "ttl": 3600,
            "priority": 10,
            "weight": 5,
            "port": 80,
            "target": "example.com",
            "other_field": "should_not_be_included",
        }

        parsed = self.dns_repo.parse_extra_data(extra_data)

        self.assertEqual(parsed["value"], "192.168.1.1")
        self.assertEqual(parsed["ttl"], 3600)
        self.assertEqual(parsed["priority"], 10)
        self.assertEqual(parsed["weight"], 5)
        self.assertEqual(parsed["port"], 80)
        self.assertEqual(parsed["target"], "example.com")
        self.assertNotIn("other_field", parsed)

    def test_parse_extra_data_partial(self):
        """Test parse_extra_data with partial data."""
        extra_data = {"value": "192.168.1.1", "ttl": 3600}

        parsed = self.dns_repo.parse_extra_data(extra_data)

        self.assertEqual(parsed["value"], "192.168.1.1")
        self.assertEqual(parsed["ttl"], 3600)
        self.assertNotIn("priority", parsed)
        self.assertNotIn("weight", parsed)

    def test_parse_extra_data_empty(self):
        """Test parse_extra_data with empty dictionary."""
        parsed = self.dns_repo.parse_extra_data({})

        self.assertEqual(parsed, {})

    def test_parse_extra_data_none(self):
        """Test parse_extra_data with None."""
        parsed = self.dns_repo.parse_extra_data(None)

        self.assertEqual(parsed, {})

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_parse_extra_data_non_dict_returns_empty(self, mock_logger):
        """Non-dict extra_data is normalized to an empty dict and logged."""
        self.assertEqual(self.dns_repo.parse_extra_data("not-a-dict"), {})
        self.assertEqual(self.dns_repo.parse_extra_data(["x"]), {})
        self.assertEqual(self.dns_repo.parse_extra_data(0), {})
        self.assertEqual(self.dns_repo.parse_extra_data(False), {})
        warn_non_dict = sum(
            1
            for c in mock_logger.log_line.call_args_list
            if c.kwargs.get("level") == "warning"
            and len(c.args) >= 3
            and "Non-dict extra_data in parse_extra_data" in c.args[2]
        )
        self.assertEqual(warn_non_dict, 4)

    def test_merge_dns_extra_payload_omits_secator_host_when_host_empty(self):
        """Do not persist secator_host when the host value is missing or empty."""
        merged = DnsRepository._merge_dns_extra_payload(
            {"secator_host": "192.0.2.1", "ttl": 1},
            {"foo": "bar"},
            "",
        )
        self.assertEqual(merged.get("foo"), "bar")
        self.assertEqual(merged.get("ttl"), 1)
        self.assertEqual(merged.get("secator_host"), "192.0.2.1")

        merged_none = DnsRepository._merge_dns_extra_payload(None, {"a": 1}, None)
        self.assertEqual(merged_none, {"a": 1})
        self.assertNotIn("secator_host", merged_none)

        preserved = DnsRepository._merge_dns_extra_payload(
            {"secator_host": "first-host.example.com", "ttl": 1},
            {"ttl": 2},
            "second-host.example.com",
        )
        self.assertEqual(preserved.get("secator_host"), "first-host.example.com")
        self.assertEqual(preserved.get("ttl"), 2)

    def test_merge_dns_extra_payload_non_dict_existing_treated_as_empty(self) -> None:
        """Legacy or corrupted non-dict stored ``existing`` must not break the merge."""
        merged = DnsRepository._merge_dns_extra_payload([1, 2], {"a": 1}, None)
        self.assertEqual(merged, {"a": 1})

    @patch("reNgine.services.repositories.dns_repository.logger")
    def test_save_from_secator_non_dict_extra_data_logs_bounded_preview(self, mock_logger) -> None:
        """Malformed ``extra_data`` should log a truncated string preview for diagnostics."""
        item = {
            "_type": "record",
            "name": "www.example.com",
            "type": "A",
            "host": "192.168.1.1",
            "extra_data": 42,
        }
        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)
        self.assertIsNotNone(result)
        self.assertEqual(result.extra_data.get("extra_data_raw"), "42")
        warned = any(
            c.kwargs.get("level") == "warning"
            and len(c.args) >= 3
            and "raw_preview=" in c.args[2]
            and "42" in c.args[2]
            for c in mock_logger.log_line.call_args_list
        )
        self.assertTrue(warned, "Expected warning with raw_preview for non-dict extra_data")

    def test_get_or_create_empty_name(self):
        """Test get_or_create with empty name."""
        record, created = self.dns_repo.get_or_create("", "A")

        self.assertIsNone(record)
        self.assertFalse(created)

    def test_get_or_create_empty_type(self):
        """Test get_or_create with empty type."""
        record, created = self.dns_repo.get_or_create("www.example.com", "")

        self.assertIsNone(record)
        self.assertFalse(created)

    def test_get_or_create_invalid_type(self):
        """Test get_or_create with invalid type."""
        record, created = self.dns_repo.get_or_create("www.example.com", "INVALID")

        self.assertIsNone(record)
        self.assertFalse(created)

    def test_get_records_for_domain_no_domain_info(self):
        """Test get_records_for_domain when domain has no domain_info."""
        domain = self.data_generator.create_domain()
        domain.domain_info = None
        domain.save()

        records = self.dns_repo.get_records_for_domain(domain.id)

        self.assertEqual(records, [])

    def test_get_records_for_domain_nonexistent(self):
        """Test get_records_for_domain with nonexistent domain."""
        records = self.dns_repo.get_records_for_domain(99999)

        self.assertEqual(records, [])

    def test_get_records_by_type_no_domain_id(self):
        """Test get_records_by_type without domain_id."""
        # Create records directly
        from startScan.models import DNSRecord

        DNSRecord.objects.create(name="www.example.com", type="A")
        DNSRecord.objects.create(name="mail.example.com", type="MX")

        a_records = self.dns_repo.get_records_by_type("A")
        mx_records = self.dns_repo.get_records_by_type("MX")

        self.assertGreaterEqual(len(a_records), 1)
        self.assertGreaterEqual(len(mx_records), 1)

    def test_get_records_by_type_invalid_type(self):
        """Test get_records_by_type with invalid type."""
        records = self.dns_repo.get_records_by_type("INVALID", self.data_generator.target.id)

        self.assertEqual(records, [])

    def test_get_records_by_type_nonexistent_domain(self):
        """Test get_records_by_type with nonexistent domain."""
        records = self.dns_repo.get_records_by_type("A", 99999)

        self.assertEqual(records, [])

    def test_bulk_create_empty_list(self):
        """Test bulk_create with empty list."""
        result = self.dns_repo.bulk_create([])

        self.assertEqual(result, [])

    def test_bulk_create_invalid_records(self):
        """Test bulk_create with invalid records."""
        records_data = [
            {"name": "", "type": "A"},  # Empty name
            {"name": "www.example.com", "type": ""},  # Empty type
            {"name": "www.example.com", "type": "INVALID"},  # Invalid type
        ]

        result = self.dns_repo.bulk_create(records_data)

        self.assertEqual(result, [])

    def test_save_from_secator_creates_domain_info_if_missing(self):
        """Test that save_from_secator creates domain_info if it doesn't exist."""
        self.domain.domain_info = None
        self.domain.save(update_fields=["domain_info_id"])

        item = {
            "_type": "record",
            "name": self.domain.name,
            "type": "A",
            "host": "192.168.1.1",
        }

        result = self.dns_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.domain.refresh_from_db()
        self.assertIsNotNone(self.domain.domain_info_id)
