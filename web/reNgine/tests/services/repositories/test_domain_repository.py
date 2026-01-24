"""
Tests for Domain repository functionality.
"""

from reNgine.services.repositories.domain_repository import DomainRepository
from utils.test_base import BaseTestCase


class TestDomainRepository(BaseTestCase):
    """Test cases for DomainRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.domain_repo = DomainRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def _build_whois_payload(
        self,
        *,
        primary_server: str = "whois.example.com",
        registrar_name: str = "Example Registrar Ltd",
        registrar_details: dict | None = None,
        updated_date: str = "2025-01-01 00:00:00",
        statuses: list[str] | None = None,
        name_servers: list[str] | None = None,
        emails: list[str] | None = None,
        raw_by_server: dict | None = None,
        nic_hdl: dict | None = None,
        admin_handle: str = "",
        tech_handle: str = "",
        jswhois_full: dict | None = None,
        dnssec: dict | None = None,
    ) -> dict:
        registrar_details = registrar_details or {}
        statuses = statuses or []
        name_servers = name_servers or []
        emails = emails or []
        raw_by_server = raw_by_server or {primary_server: "raw"}
        nic_hdl = nic_hdl or {}
        dnssec = dnssec or {"dnssec": "unsigned", "dnssec_keys": []}
        jswhois_full = jswhois_full or {"chain": [primary_server], primary_server: {}}

        return {
            "query": self.domain.name,
            "chain": ["whois.iana.org", primary_server],
            "servers": {"primary": primary_server, "used": [primary_server]},
            "iana": {"status": "ACTIVE"},
            "registry_ids": {
                "registry_domain_id": "",
                "registry_registrant_id": "",
                "registry_admin_id": "",
                "registry_tech_id": "",
                "registrar_iana_id": "",
            },
            "domain": {
                "name": self.domain.name,
                "registrar": registrar_name,
                "creation_date": "2020-01-15 10:30:00",
                "expiration_date": "2026-01-15 10:30:00",
                "updated_date": updated_date,
                "statuses": statuses,
                "name_servers": name_servers,
                "dnssec": dnssec,
            },
            "registrar": {
                "name": registrar_name,
                "iana_id": "",
                "url": registrar_details.get("website", ""),
                "whois_server": primary_server,
                "details": registrar_details,
            },
            "contacts": {
                "registrant": {},
                "admin": {"handle": admin_handle},
                "tech": {"handle": tech_handle},
                "extra": {"registrant": {}, "admin": {}, "tech": {}},
            },
            "emails": emails,
            "fragments": {
                "domain_info": {},
                "nic_hdl": nic_hdl,
                "nserver": {"nserver": name_servers},
            },
            "raw": {"by_server": raw_by_server},
            "jswhois": {"structured_no_raw": jswhois_full},
        }

    def test_save_from_secator_valid_domain(self):
        """Test saving valid domain info from Secator."""
        whois = self._build_whois_payload(
            statuses=["ACTIVE", "clientTransferProhibited"],
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrar": "Example Registrar Ltd",
            "registrant": "Test Organization",
            "creation_date": "2020-01-15 10:30:00",
            "expiration_date": "2026-01-15 10:30:00",
            "alive": False,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.domain.refresh_from_db()
        self.assertIsNotNone(self.domain.domain_info)
        self.assertEqual(self.domain.domain_info.id, result.id)

    def test_save_from_secator_with_whois_v2_schema(self):
        """Secator WHOIS v2 payload should be stored and processed."""
        whois = self._build_whois_payload(
            primary_server="whois.nic.uk",
            statuses=["ACTIVE"],
            name_servers=["ns1.example.com"],
            emails=["test@example.com"],
            raw_by_server={"whois.nic.uk": "raw"},
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrar": "Example Registrar Ltd",
            "registrant": "Test Organization",
            "alive": True,
            "extra_data": {"whois": whois},
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.extra_data)
        self.assertIn("whois", result.extra_data)
        self.assertEqual(result.extra_data["whois"], whois)
        self.assertEqual(result.whois_server, "whois.nic.uk")
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.domain_info.whois_server, "whois.nic.uk")

    def test_save_from_secator_with_registrar(self):
        """Test saving domain info with registrar."""
        registrar_details = {
            "phone": "+44.2071234567",
            "e-mail": "admin@exampleregistrar.co.uk",
            "website": "https://www.exampleregistrar.co.uk",
            "address": ["123 Example Street", "London SW1A 1AA"],
            "country": "GB",
            "fax-no": "+44.2071234568",
        }
        whois = self._build_whois_payload(
            registrar_details=registrar_details,
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrar": "Example Registrar Ltd",
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.registrar)
        self.assertEqual(result.registrar.name, "Example Registrar Ltd")
        self.assertEqual(result.registrar.phone, "+44.2071234567")
        self.assertEqual(result.registrar.email, "admin@exampleregistrar.co.uk")
        self.assertIn("123 Example Street", result.registrar.address)
        self.assertEqual(result.registrar.country, "GB")
        self.assertEqual(result.registrar.fax, "+44.2071234568")

    def test_save_from_secator_with_registrant(self):
        """Test saving domain info with registrant."""
        nic_hdl = {
            "contact": "John Smith",
            "type": "ORGANIZATION",
            "e-mail": "contact@testorganization.co.uk",
            "phone": "+44.2076543210",
            "country": "GB",
            "address": ["456 Test Avenue", "Manchester M1 1AA"],
            "fax-no": "+44.2076543211",
            "nic-hdl": "TEST123-GB",
        }
        whois = self._build_whois_payload(
            nic_hdl=nic_hdl,
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrant": "Test Organization Ltd",
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.registrant)
        self.assertEqual(result.registrant.name, "Test Organization Ltd")
        self.assertEqual(result.registrant.organization, "Test Organization Ltd")
        self.assertEqual(result.registrant.contact, "John Smith")
        self.assertEqual(result.registrant.type, "ORGANIZATION")
        self.assertEqual(result.registrant.country, "GB")
        self.assertEqual(result.registrant.fax, "+44.2076543211")
        self.assertEqual(result.registrant.id_str, "TEST123-GB")

    def test_get_or_create_registrant_with_id_str_prevents_merging(self):
        """Test that registrants with same name but different id_str are not merged."""

        # Create first registrant with id_str
        extra_data1 = {
            "nic_hdl": {
                "nic-hdl": "REG123-GB",
                "contact": "John Doe",
                "e-mail": "john@example.com",
            }
        }
        registrant1 = self.domain_repo._get_or_create_registrant("Test Company", extra_data1)

        # Create second registrant with same name but different id_str
        extra_data2 = {
            "nic_hdl": {
                "nic-hdl": "REG456-GB",
                "contact": "Jane Smith",
                "e-mail": "jane@example.com",
            }
        }
        registrant2 = self.domain_repo._get_or_create_registrant("Test Company", extra_data2)

        # Verify they are different objects
        self.assertNotEqual(registrant1.id, registrant2.id)
        self.assertEqual(registrant1.id_str, "REG123-GB")
        self.assertEqual(registrant2.id_str, "REG456-GB")
        self.assertEqual(registrant1.name, "Test Company")
        self.assertEqual(registrant2.name, "Test Company")

    def test_get_or_create_registrant_fallback_to_name(self):
        """Test that registrant creation falls back to name when id_str is unavailable."""
        extra_data = {
            "nic_hdl": {
                "contact": "John Doe",
                "e-mail": "john@example.com",
                # No nic-hdl/id_str
            }
        }
        registrant = self.domain_repo._get_or_create_registrant("Test Company", extra_data)

        self.assertIsNotNone(registrant)
        self.assertEqual(registrant.name, "Test Company")
        self.assertFalse(registrant.id_str)  # Should be empty string or None

    def test_save_from_secator_with_name_servers(self):
        """Test saving domain info with name servers."""
        whois = self._build_whois_payload(
            name_servers=["ns1.example-dns.co.uk", "ns2.example-dns.co.uk", "ns3.example-dns.co.uk"],
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        name_servers = list(result.name_servers.all())
        self.assertEqual(len(name_servers), 3)
        ns_names = [ns.name for ns in name_servers]
        self.assertIn("ns1.example-dns.co.uk", ns_names)
        self.assertIn("ns2.example-dns.co.uk", ns_names)
        self.assertIn("ns3.example-dns.co.uk", ns_names)

    def test_save_from_secator_with_status(self):
        """Test saving domain info with status."""
        whois = self._build_whois_payload(
            statuses=["ACTIVE", "clientTransferProhibited"],
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        statuses = list(result.status.all())
        self.assertEqual(len(statuses), 2)
        status_names = [s.name for s in statuses]
        self.assertIn("ACTIVE", status_names)
        self.assertIn("clientTransferProhibited", status_names)

    def test_save_from_secator_with_dnssec(self):
        """Test saving domain info with DNSSEC."""
        whois = self._build_whois_payload(
            dnssec={
                "dnssec": "signed",
                "dnssec_keys": [{"key_tag": "2456", "algorithm": "13 [ECDSAP256SHA256]"}],
            },
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertTrue(result.dnssec)

    def test_save_from_secator_with_dates(self):
        """Test saving domain info with dates."""
        whois = self._build_whois_payload()
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "creation_date": "2020-09-24 09:16:34",
            "expiration_date": "2026-09-24 09:16:34",
            "extra_data": {"whois": whois},
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.created)
        self.assertIsNotNone(result.expires)

    def test_save_from_secator_with_whois_server(self):
        """Test saving domain info with whois server."""
        whois = self._build_whois_payload(primary_server="whois.nic.uk")
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.whois_server, "whois.nic.uk")
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.domain_info.whois_server, "whois.nic.uk")

    def test_save_from_secator_with_extra_data(self):
        """Test saving domain info with extra data."""
        whois = self._build_whois_payload(
            primary_server="whois.nic.uk",
            emails=["test@example.com"],
            raw_by_server={"whois.nic.uk": "%% This is a test Whois server..."},
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.extra_data)
        self.assertIn("whois", result.extra_data)
        self.assertIn("chain", result.extra_data)
        self.assertIn("raw", result.extra_data)
        self.assertIn("emails", result.extra_data)

    def test_save_from_secator_domain_name_mismatch(self):
        """Test handling domain name mismatch."""
        whois = self._build_whois_payload()
        item = {
            "_type": "domain",
            "domain": "different-domain.co.uk",
            "registrar": "Example Registrar Ltd",
            "extra_data": {"whois": whois},
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_domain_name_case_insensitive_match(self):
        """Domain name comparison should be case-insensitive."""
        whois = self._build_whois_payload()
        item = {
            "_type": "domain",
            "domain": self.domain.name.upper(),
            "registrar": "Example Registrar Ltd",
            "extra_data": {"whois": whois},
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)

    def test_save_from_secator_missing_domain(self):
        """Test handling missing domain field."""
        item = {
            "_type": "domain",
            "registrar": "Example Registrar Ltd",
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_updates_existing_domain_info(self):
        """Test updating existing domain info."""
        # Create initial domain info
        from targetApp.models import DomainInfo

        initial_domain_info = DomainInfo()
        initial_domain_info.save()
        self.domain.domain_info = initial_domain_info
        self.domain.save()

        # Update with new data
        whois = self._build_whois_payload(registrar_name="New Registrar Ltd")
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrar": "New Registrar Ltd",
            "expiration_date": "2027-01-01 00:00:00",
            "extra_data": {"whois": whois},
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.id, initial_domain_info.id)
        self.assertIsNotNone(result.registrar)
        self.assertEqual(result.registrar.name, "New Registrar Ltd")

    def test_parse_datetime_iso_format(self):
        """Test parsing datetime in ISO format."""
        from datetime import datetime

        result = self.domain_repo._parse_datetime("2020-09-24T09:16:34Z")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_string_format(self):
        """Test parsing datetime in string format."""
        from datetime import datetime

        result = self.domain_repo._parse_datetime("2020-09-24 09:16:34")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_timestamp(self):
        """Test parsing datetime from timestamp."""
        from datetime import datetime
        import time

        timestamp = time.time()
        result = self.domain_repo._parse_datetime(timestamp)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_none(self):
        """Test parsing None datetime."""
        result = self.domain_repo._parse_datetime(None)
        self.assertIsNone(result)

    def test_save_from_secator_with_admin_tech(self):
        """Test saving domain info with admin and tech contacts."""
        jswhois_full = {
            "chain": ["whois.iana.org", "whois.nic.uk"],
            "whois.nic.uk": {
                "nic-hdl": [
                    {
                        "nic-hdl": "ADMIN456-GB",
                        "contact": "Jane Doe",
                        "type": "ORGANIZATION",
                        "e-mail": "admin@testorganization.co.uk",
                        "phone": "+44.2071111111",
                        "country": "GB",
                        "address": ["789 Admin Road", "Birmingham B1 1AA"],
                    },
                    {
                        "nic-hdl": "TECH789-GB",
                        "contact": "Tech Contact",
                        "type": "ORGANIZATION",
                        "e-mail": "tech@testorganization.co.uk",
                        "phone": "+44.2071111112",
                        "country": "GB",
                        "address": ["789 Tech Road", "Birmingham B1 1AA"],
                    },
                ],
            },
        }
        whois = self._build_whois_payload(
            primary_server="whois.nic.uk",
            admin_handle="ADMIN456-GB",
            tech_handle="TECH789-GB",
            jswhois_full=jswhois_full,
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "registrant": "Test Organization Ltd",
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.admin)
        self.assertIsNotNone(result.tech)
        self.assertEqual(result.admin.id_str, "ADMIN456-GB")
        self.assertEqual(result.tech.id_str, "TECH789-GB")
        self.assertEqual(result.admin.contact, "Jane Doe")
        self.assertEqual(result.tech.contact, "Tech Contact")

    def test_save_from_secator_with_last_update(self):
        """Test saving domain info with last-update."""
        whois = self._build_whois_payload(updated_date="2025-09-22 14:09:03")
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.updated)
        from datetime import datetime

        self.assertIsInstance(result.updated, datetime)

    def test_get_or_create_admin_tech(self):
        """Test _get_or_create_admin_tech method."""
        extra_data = {
            "jswhois_full": {
                "chain": ["whois.nic.uk"],
                "whois.nic.uk": {
                    "nic-hdl": [
                        {
                            "nic-hdl": "ADMIN123-GB",
                            "contact": "Robert Johnson",
                            "type": "PERSON",
                            "e-mail": "admin@testcompany.co.uk",
                            "phone": "+44.2072222222",
                            "country": "GB",
                            "address": ["321 Admin Street", "Leeds LS1 1AA"],
                        }
                    ],
                },
            },
        }

        admin = self.domain_repo._get_or_create_admin_tech("ADMIN123-GB", extra_data, "admin", self.domain)

        self.assertIsNotNone(admin)
        self.assertEqual(admin.id_str, "ADMIN123-GB")
        self.assertEqual(admin.contact, "Robert Johnson")
        self.assertEqual(admin.type, "PERSON")
        self.assertEqual(admin.email, "admin@testcompany.co.uk")

    def test_parse_registrar_address_list(self):
        """Test _parse_registrar_address with list."""
        address = ["123 Street", "City", "Country"]
        result = self.domain_repo._parse_registrar_address(address)

        self.assertEqual(result, "123 Street, City, Country")

    def test_parse_registrar_address_string(self):
        """Test _parse_registrar_address with string."""
        address = "123 Street, City, Country"
        result = self.domain_repo._parse_registrar_address(address)

        self.assertEqual(result, "123 Street, City, Country")

    def test_parse_registrar_address_empty_list(self):
        """Test _parse_registrar_address with empty list."""
        result = self.domain_repo._parse_registrar_address([])

        self.assertEqual(result, "")

    def test_parse_registrar_address_none(self):
        """Test _parse_registrar_address with None."""
        result = self.domain_repo._parse_registrar_address(None)

        self.assertEqual(result, "")

    def test_build_registrar_defaults(self):
        """Test _build_registrar_defaults method."""
        registrar_info = {
            "phone": "+44.2071234567",
            "e-mail": "admin@example.com",
            "website": "https://example.com",
            "address": ["123 Street", "City"],
            "country": "GB",
            "fax-no": "+44.2071234568",
        }
        defaults = self.domain_repo._build_registrar_defaults(registrar_info, "Test Registrar")

        self.assertEqual(defaults["name"], "Test Registrar")
        self.assertEqual(defaults["phone"], "+44.2071234567")
        self.assertEqual(defaults["email"], "admin@example.com")
        self.assertEqual(defaults["url"], "https://example.com")
        self.assertEqual(defaults["address"], "123 Street, City")
        self.assertEqual(defaults["country"], "GB")
        self.assertEqual(defaults["fax"], "+44.2071234568")

    def test_update_registrar(self):
        """Test _update_registrar method."""
        from targetApp.models import Registrar

        registrar = Registrar.objects.create(name="Test Registrar")
        registrar_info = {
            "phone": "+44.2071234567",
            "e-mail": "admin@example.com",
            "website": "https://example.com",
            "country": "GB",
            "fax-no": "+44.2071234568",
        }
        address = "123 Street, City"

        updated = self.domain_repo._update_registrar(registrar, registrar_info, address)

        self.assertTrue(updated)
        registrar.refresh_from_db()
        self.assertEqual(registrar.phone, "+44.2071234567")
        self.assertEqual(registrar.email, "admin@example.com")
        self.assertEqual(registrar.url, "https://example.com")
        self.assertEqual(registrar.address, "123 Street, City")
        self.assertEqual(registrar.country, "GB")
        self.assertEqual(registrar.fax, "+44.2071234568")

    def test_update_registrar_no_updates_when_fields_exist(self):
        """Test _update_registrar doesn't update when fields already have values."""
        from targetApp.models import Registrar

        registrar = Registrar.objects.create(name="Test Registrar", phone="existing", email="existing@example.com")
        registrar_info = {"phone": "+44.2071234567", "e-mail": "new@example.com"}
        address = ""

        self.domain_repo._update_registrar(registrar, registrar_info, address)

        registrar.refresh_from_db()
        self.assertEqual(registrar.phone, "existing")
        self.assertEqual(registrar.email, "existing@example.com")

    def test_extract_nic_hdl_id(self):
        """Test _extract_nic_hdl_id method."""
        nic_hdl = {"nic-hdl": "TEST123-GB"}
        result = self.domain_repo._extract_nic_hdl_id(nic_hdl)

        self.assertEqual(result, "TEST123-GB")

    def test_extract_nic_hdl_id_fallback(self):
        """Test _extract_nic_hdl_id with fallback keys."""
        nic_hdl = {"id_str": "TEST123-GB"}
        result = self.domain_repo._extract_nic_hdl_id(nic_hdl)

        self.assertEqual(result, "TEST123-GB")

        nic_hdl2 = {"id": "TEST456-GB"}
        result2 = self.domain_repo._extract_nic_hdl_id(nic_hdl2)

        self.assertEqual(result2, "TEST456-GB")

        nic_hdl3 = {"nic_hdl": "TEST789-GB"}
        result3 = self.domain_repo._extract_nic_hdl_id(nic_hdl3)

        self.assertEqual(result3, "TEST789-GB")

    def test_extract_nic_hdl_id_none(self):
        """Test _extract_nic_hdl_id with no matching keys."""
        nic_hdl = {}
        result = self.domain_repo._extract_nic_hdl_id(nic_hdl)

        self.assertIsNone(result)

    def test_parse_address_list(self):
        """Test _parse_address with list."""
        address = ["123 Street", "City", "12345"]
        result = self.domain_repo._parse_address(address)

        self.assertEqual(result["address"], "123 Street")
        self.assertEqual(result["city"], "City")
        self.assertEqual(result["zip_code"], "12345")

    def test_parse_address_list_with_state(self):
        """Test _parse_address with list containing state."""
        address = ["123 Street", "City", "State"]
        result = self.domain_repo._parse_address(address)

        self.assertEqual(result["address"], "123 Street")
        self.assertEqual(result["city"], "City")
        self.assertEqual(result["state"], "State")

    def test_parse_address_string(self):
        """Test _parse_address with string."""
        address = "123 Street"
        result = self.domain_repo._parse_address(address)

        self.assertEqual(result["address"], "123 Street")

    def test_parse_address_empty(self):
        """Test _parse_address with empty list."""
        result = self.domain_repo._parse_address([])

        self.assertEqual(result, {})

    def test_build_domain_registration_defaults(self):
        """Test _build_domain_registration_defaults method."""
        nic_hdl = {
            "contact": "John Doe",
            "type": "PERSON",
            "e-mail": "john@example.com",
            "phone": "+44.2071234567",
            "country": "GB",
            "address": ["123 Street", "City", "12345"],
            "fax-no": "+44.2071234568",
            "nic-hdl": "TEST123-GB",
        }
        defaults = self.domain_repo._build_domain_registration_defaults(
            nic_hdl, "John Doe", "Organization", "TEST123-GB"
        )

        self.assertEqual(defaults["name"], "John Doe")
        self.assertEqual(defaults["organization"], "Organization")
        self.assertEqual(defaults["contact"], "John Doe")
        self.assertEqual(defaults["type"], "PERSON")
        self.assertEqual(defaults["email"], "john@example.com")
        self.assertEqual(defaults["phone"], "+44.2071234567")
        self.assertEqual(defaults["country"], "GB")
        self.assertEqual(defaults["id_str"], "TEST123-GB")
        self.assertEqual(defaults["fax"], "+44.2071234568")
        self.assertEqual(defaults["address"], "123 Street")
        self.assertEqual(defaults["city"], "City")
        self.assertEqual(defaults["zip_code"], "12345")

    def test_update_domain_registration(self):
        """Test _update_domain_registration method."""
        from targetApp.models import DomainRegistration

        registration = DomainRegistration.objects.create(name="", organization="")
        nic_hdl = {
            "contact": "John Doe",
            "type": "PERSON",
            "e-mail": "john@example.com",
            "phone": "+44.2071234567",
            "country": "GB",
            "fax-no": "+44.2071234568",
        }

        updated = self.domain_repo._update_domain_registration(registration, nic_hdl, "John Doe", "TEST123-GB")

        self.assertTrue(updated)
        registration.refresh_from_db()
        self.assertEqual(registration.name, "John Doe")
        self.assertEqual(registration.organization, "John Doe")
        self.assertEqual(registration.id_str, "TEST123-GB")
        self.assertEqual(registration.contact, "John Doe")
        self.assertEqual(registration.type, "PERSON")
        self.assertEqual(registration.email, "john@example.com")
        self.assertEqual(registration.phone, "+44.2071234567")
        self.assertEqual(registration.country, "GB")
        self.assertEqual(registration.fax, "+44.2071234568")

    def test_update_object_fields_if_empty(self):
        """Test _update_object_fields_if_empty method."""
        from targetApp.models import Registrar

        registrar = Registrar.objects.create(name="Test Registrar")
        field_mappings = {
            "phone": "+44.2071234567",
            "email": "admin@example.com",
        }

        updated = self.domain_repo._update_object_fields_if_empty(field_mappings, registrar, False)

        self.assertTrue(updated)
        registrar.refresh_from_db()
        self.assertEqual(registrar.phone, "+44.2071234567")
        self.assertEqual(registrar.email, "admin@example.com")

    def test_update_object_fields_if_empty_no_updates(self):
        """Test _update_object_fields_if_empty doesn't update when fields exist."""
        from targetApp.models import Registrar

        registrar = Registrar.objects.create(name="Test Registrar", phone="existing")
        field_mappings = {"phone": "+44.2071234567"}

        updated = self.domain_repo._update_object_fields_if_empty(field_mappings, registrar, False)

        self.assertFalse(updated)
        registrar.refresh_from_db()
        self.assertEqual(registrar.phone, "existing")

    def test_find_nic_hdl_in_jswhois(self):
        """Test _find_nic_hdl_in_jswhois method."""
        jswhois_full = {
            "chain": ["whois.nic.uk"],
            "whois.nic.uk": {
                "nic-hdl": {
                    "nic-hdl": "TEST123-GB",
                    "contact": "John Doe",
                }
            },
        }

        result = self.domain_repo._find_nic_hdl_in_jswhois(jswhois_full, "TEST123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result["nic-hdl"], "TEST123-GB")

    def test_find_nic_hdl_in_jswhois_list(self):
        """Test _find_nic_hdl_in_jswhois with list of nic-hdl."""
        jswhois_full = {
            "chain": ["whois.nic.uk"],
            "whois.nic.uk": {
                "nic-hdl": [
                    {"nic-hdl": "TEST123-GB", "contact": "John Doe"},
                    {"nic-hdl": "TEST456-GB", "contact": "Jane Doe"},
                ]
            },
        }

        result = self.domain_repo._find_nic_hdl_in_jswhois(jswhois_full, "TEST123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result["nic-hdl"], "TEST123-GB")

    def test_find_nic_hdl_in_jswhois_not_found(self):
        """Test _find_nic_hdl_in_jswhois when not found."""
        jswhois_full = {
            "chain": ["whois.nic.uk"],
            "whois.nic.uk": {"nic-hdl": {"nic-hdl": "OTHER123-GB", "contact": "John Doe"}},
        }

        result = self.domain_repo._find_nic_hdl_in_jswhois(jswhois_full, "TEST123-GB")

        self.assertIsNone(result)

    def test_find_nic_hdl_in_extra_data(self):
        """Test _find_nic_hdl_in_extra_data method."""
        extra_data = {
            "jswhois_full": {
                "chain": ["whois.nic.uk"],
                "whois.nic.uk": {"nic-hdl": {"nic-hdl": "TEST123-GB", "contact": "John Doe"}},
            }
        }

        result = self.domain_repo._find_nic_hdl_in_extra_data(extra_data, "TEST123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result["nic-hdl"], "TEST123-GB")

    def test_find_nic_hdl_in_extra_data_fallback(self):
        """Test _find_nic_hdl_in_extra_data with fallback to nic_hdl."""
        extra_data = {"nic_hdl": {"nic-hdl": "TEST123-GB", "contact": "John Doe"}}

        result = self.domain_repo._find_nic_hdl_in_extra_data(extra_data, "TEST123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result["nic-hdl"], "TEST123-GB")

    def test_find_existing_contact(self):
        """Test _find_existing_contact method."""
        from targetApp.models import DomainInfo, DomainRegistration

        admin_contact = DomainRegistration.objects.create(name="Admin Contact", id_str="ADMIN123-GB")
        domain_info = DomainInfo.objects.create()
        domain_info.admin = admin_contact
        domain_info.save()
        self.domain.domain_info = domain_info
        self.domain.save()

        result = self.domain_repo._find_existing_contact(self.domain, "admin", "ADMIN123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result.id, admin_contact.id)

    def test_find_existing_contact_by_id_str(self):
        """Test _find_existing_contact by id_str when not in domain_info."""
        from targetApp.models import DomainRegistration

        contact = DomainRegistration.objects.create(name="Tech Contact", id_str="TECH123-GB")

        result = self.domain_repo._find_existing_contact(self.domain, "tech", "TECH123-GB")

        self.assertIsNotNone(result)
        self.assertEqual(result.id, contact.id)

    def test_find_existing_contact_not_found(self):
        """Test _find_existing_contact when contact not found."""
        result = self.domain_repo._find_existing_contact(self.domain, "admin", "NONEXISTENT-GB")

        self.assertIsNone(result)

    def test_create_contact(self):
        """Test _create_contact method."""
        nic_hdl = {
            "contact": "John Doe",
            "type": "PERSON",
            "e-mail": "john@example.com",
        }
        defaults = {
            "name": "John Doe",
            "organization": "Test Org",
            "contact": "John Doe",
            "type": "PERSON",
            "email": "john@example.com",
        }

        result = self.domain_repo._create_contact(nic_hdl, "John Doe", "TEST123-GB", defaults, "admin")

        self.assertIsNotNone(result)
        self.assertEqual(result.id_str, "TEST123-GB")
        self.assertEqual(result.name, "John Doe")

    def test_create_contact_without_id_str(self):
        """Test _create_contact without id_str."""
        nic_hdl = {"contact": "John Doe", "type": "PERSON"}
        defaults = {
            "organization": "Test Org",
            "contact": "John Doe",
            "type": "PERSON",
        }

        result = self.domain_repo._create_contact(nic_hdl, "John Doe", "", defaults, "admin")

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "John Doe")

    def test_process_basic_fields(self):
        """Test _process_basic_fields method."""

        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {
            "last_update": "2025-09-22 14:09:03",
            "whois_server": "whois.example.com",
        }

        self.domain_repo._process_basic_fields(domain_info, extra_data)

        self.assertIsNotNone(domain_info.updated)
        self.assertEqual(domain_info.whois_server, "whois.example.com")

    def test_process_basic_fields_no_update_when_updated_exists(self):
        """Test _process_basic_fields doesn't update when updated already exists."""
        from django.utils import timezone

        from targetApp.models import DomainInfo

        existing_date = timezone.now()
        domain_info = DomainInfo.objects.create(updated=existing_date)
        extra_data = {"last_update": "2025-09-22 14:09:03"}

        self.domain_repo._process_basic_fields(domain_info, extra_data)

        domain_info.refresh_from_db()
        self.assertEqual(domain_info.updated, existing_date)

    def test_add_status_to_domain_info(self):
        """Test _add_status_to_domain_info method."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()

        self.domain_repo._add_status_to_domain_info(domain_info, "clientTransferProhibited")

        statuses = list(domain_info.status.all())
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].name, "clientTransferProhibited")

    def test_process_status_value_string(self):
        """Test _process_status_value with string."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()

        self.domain_repo._process_status_value(domain_info, "clientTransferProhibited")

        statuses = list(domain_info.status.all())
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].name, "clientTransferProhibited")

    def test_process_status_value_list(self):
        """Test _process_status_value with list."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()

        self.domain_repo._process_status_value(domain_info, ["clientTransferProhibited", "clientDeleteProhibited"])

        statuses = list(domain_info.status.all())
        self.assertEqual(len(statuses), 2)
        status_names = [s.name for s in statuses]
        self.assertIn("clientTransferProhibited", status_names)
        self.assertIn("clientDeleteProhibited", status_names)

    def test_process_status_fields(self):
        """Test _process_status_fields method."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {
            "status": "ACTIVE",
            "eppstatus": ["clientTransferProhibited", "clientDeleteProhibited"],
            "nic_hdl": {"eppstatus": "clientRenewProhibited"},
        }

        self.domain_repo._process_status_fields(domain_info, extra_data)

        statuses = list(domain_info.status.all())
        self.assertEqual(len(statuses), 4)
        status_names = [s.name for s in statuses]
        self.assertIn("ACTIVE", status_names)
        self.assertIn("clientTransferProhibited", status_names)
        self.assertIn("clientDeleteProhibited", status_names)
        self.assertIn("clientRenewProhibited", status_names)

    def test_add_name_server(self):
        """Test _add_name_server method."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()

        self.domain_repo._add_name_server(domain_info, "ns1.example.com")

        name_servers = list(domain_info.name_servers.all())
        self.assertEqual(len(name_servers), 1)
        self.assertEqual(name_servers[0].name, "ns1.example.com")

    def test_process_name_servers_dict(self):
        """Test _process_name_servers with dict format."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {"nserver": {"nserver": ["ns1.example.com", "ns2.example.com"]}}

        self.domain_repo._process_name_servers(domain_info, extra_data)

        name_servers = list(domain_info.name_servers.all())
        self.assertEqual(len(name_servers), 2)
        ns_names = [ns.name for ns in name_servers]
        self.assertIn("ns1.example.com", ns_names)
        self.assertIn("ns2.example.com", ns_names)

    def test_process_name_servers_list(self):
        """Test _process_name_servers with list format."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {"nserver": ["ns1.example.com", "ns2.example.com"]}

        self.domain_repo._process_name_servers(domain_info, extra_data)

        name_servers = list(domain_info.name_servers.all())
        self.assertEqual(len(name_servers), 2)
        ns_names = [ns.name for ns in name_servers]
        self.assertIn("ns1.example.com", ns_names)
        self.assertIn("ns2.example.com", ns_names)

    def test_process_dnssec(self):
        """Test _process_dnssec method."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {"key1-tag": {"key1-tag": "2456"}}

        self.domain_repo._process_dnssec(domain_info, extra_data)

        self.assertTrue(domain_info.dnssec)

    def test_process_dnssec_no_key(self):
        """Test _process_dnssec when key1-tag is not present."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {}

        self.domain_repo._process_dnssec(domain_info, extra_data)

        self.assertFalse(domain_info.dnssec)

    def test_store_remaining_data(self):
        """Test _store_remaining_data method."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create()
        extra_data = {
            "chain": ["whois.iana.org", "whois.nic.uk"],
            "raw": "%% Test raw data",
            "emails": ["test@example.com"],
            "key1-tag": {"key1-tag": "2456"},
        }

        self.domain_repo._store_remaining_data(domain_info, extra_data)

        self.assertIsNotNone(domain_info.extra_data)
        self.assertEqual(domain_info.extra_data["chain"], ["whois.iana.org", "whois.nic.uk"])
        self.assertEqual(domain_info.extra_data["raw"], "%% Test raw data")
        self.assertEqual(domain_info.extra_data["emails"], ["test@example.com"])
        self.assertEqual(domain_info.extra_data["key1-tag"], {"key1-tag": "2456"})

    def test_store_remaining_data_merge(self):
        """Test _store_remaining_data merges with existing data."""
        from targetApp.models import DomainInfo

        domain_info = DomainInfo.objects.create(extra_data={"existing": "data"})
        extra_data = {"chain": ["whois.iana.org"]}

        self.domain_repo._store_remaining_data(domain_info, extra_data)

        self.assertEqual(domain_info.extra_data["existing"], "data")
        self.assertEqual(domain_info.extra_data["chain"], ["whois.iana.org"])

    def test_parse_datetime_milliseconds_timestamp(self):
        """Test _parse_datetime with milliseconds timestamp."""
        from datetime import datetime

        timestamp_ms = 1600000000000  # Milliseconds
        result = self.domain_repo._parse_datetime(timestamp_ms)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_seconds_timestamp(self):
        """Test _parse_datetime with seconds timestamp."""
        from datetime import datetime

        timestamp_s = 1600000000  # Seconds
        result = self.domain_repo._parse_datetime(timestamp_s)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_datetime_object(self):
        """Test _parse_datetime with datetime object."""
        from datetime import datetime

        dt = datetime(2020, 9, 24, 9, 16, 34)
        result = self.domain_repo._parse_datetime(dt)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, datetime)

    def test_parse_datetime_invalid_string(self):
        """Test _parse_datetime with invalid string format."""
        result = self.domain_repo._parse_datetime("invalid date string")

        self.assertIsNone(result)

    def test_save_from_secator_with_eppstatus_list(self):
        """Test saving domain info with eppstatus as list."""
        whois = self._build_whois_payload(
            statuses=["clientTransferProhibited", "clientDeleteProhibited"],
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        statuses = list(result.status.all())
        self.assertEqual(len(statuses), 2)
        status_names = [s.name for s in statuses]
        self.assertIn("clientTransferProhibited", status_names)
        self.assertIn("clientDeleteProhibited", status_names)

    def test_save_from_secator_with_nserver_list(self):
        """Test saving domain info with nserver as list."""
        whois = self._build_whois_payload(
            name_servers=["ns1.example.com", "ns2.example.com"],
        )
        item = {
            "_type": "domain",
            "domain": self.domain.name,
            "extra_data": {
                "whois": whois,
            },
        }

        result = self.domain_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        name_servers = list(result.name_servers.all())
        self.assertEqual(len(name_servers), 2)
        ns_names = [ns.name for ns in name_servers]
        self.assertIn("ns1.example.com", ns_names)
        self.assertIn("ns2.example.com", ns_names)
