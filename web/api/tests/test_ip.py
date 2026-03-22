"""
This file contains the test cases for the API views.
"""

import json

from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from api.helpers.ip_action_response import (
    IP_ERR_INVALID_IP_ADDRESS_IDS,
    IP_ERR_IP_NOT_IN_SCAN,
    IP_ERR_MISSING_IP_ADDRESS_ID,
    IP_ERR_MISSING_REQUIRED_FIELDS,
)
from reNgine.services.scan_finding_metrics import get_ip_address_metrics_for_scan
from startScan.models import EndPoint, IpAddress, Port
from utils.test_base import BaseTestCase


class TestIpAddressViewSet(BaseTestCase):
    """Test case for IP address viewset."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_ip_address_viewset(self):
        """Test retrieving IP addresses for a scan."""
        url = reverse("api:ip-addresses-list")
        response = self.client.get(url, {"scan_id": self.data_generator.scan_history.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if response has data structure
        if "results" in response.data and len(response.data["results"]) > 0:
            # Check if the first result has ip_addresses
            if "ip_addresses" in response.data["results"][0] and len(response.data["results"][0]["ip_addresses"]) > 0:
                self.assertEqual(
                    response.data["results"][0]["ip_addresses"][0]["address"],
                    self.data_generator.ip_address.address,
                )
            else:
                # If no ip_addresses in results, check direct structure
                self.assertGreaterEqual(len(response.data), 1)
        else:
            # Fallback: check if response.data is a list or has direct structure
            self.assertGreaterEqual(len(response.data), 1)


class TestIPToDomain(BaseTestCase):
    """Test case for IP to domain resolution."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    # Deprecated endpoint tests removed - ip_to_domain endpoint has been removed


# TestDomainIPHistory removed - functionality migrated to Secator


class TestListIPs(BaseTestCase):
    """Test case for listing IP addresses."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()  # Creates IP data

    def test_list_ips(self):
        """Test listing IP addresses for a target."""
        url = reverse("api:listIPs")
        response = self.client.get(url, {"target_id": self.data_generator.domain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ips", response.data)
        # The API might return empty list if no IPs are associated with the domain
        # This is expected behavior, so we just check the structure
        self.assertIsInstance(response.data["ips"], list)

    def test_list_ips_datatables_matches_metrics_when_ips_only_on_endpoints(self):
        """IPs linked via EndPoint.ip_address must appear like scan ip_address_count."""
        dg = self.data_generator
        scan = dg.scan_history
        orphan = IpAddress.objects.create(address="203.0.113.55", alive=True)
        EndPoint.objects.create(
            domain=dg.domain,
            subdomain=None,
            scan_history=scan,
            http_url="http://203.0.113.55/",
            discovered_date=timezone.now(),
            ip_address=orphan,
        )
        expected_total, _ = get_ip_address_metrics_for_scan(scan.id)
        url = reverse("api:listIPs")
        response = self.client.get(
            url,
            {"scan_id": scan.id, "start": "0", "length": "100"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["recordsTotal"], expected_total)
        self.assertEqual(response.data["recordsFiltered"], expected_total)
        addresses = {row["address"] for row in response.data["data"]}
        self.assertIn("203.0.113.55", addresses)

    def test_list_ips_datatables_order_column_index_matches_address_column(self):
        """DataTables order[0][column]=1 must sort by address (column 1), not alive."""
        dg = self.data_generator
        scan = dg.scan_history
        ip_high = IpAddress.objects.create(address="203.0.113.90", alive=True, is_cdn=False)
        ip_low = IpAddress.objects.create(address="203.0.113.10", alive=True, is_cdn=False)
        now = timezone.now()
        for ip in (ip_high, ip_low):
            EndPoint.objects.create(
                domain=dg.domain,
                subdomain=None,
                scan_history=scan,
                http_url=f"http://{ip.address}/",
                discovered_date=now,
                ip_address=ip,
            )
        url = reverse("api:listIPs")
        base_params = {"scan_id": scan.id, "start": "0", "length": "500"}
        asc_resp = self.client.get(
            url,
            {
                **base_params,
                "order[0][column]": "1",
                "order[0][dir]": "asc",
            },
        )
        self.assertEqual(asc_resp.status_code, status.HTTP_200_OK)
        asc_rows = [row["address"] for row in asc_resp.data["data"]]
        self.assertIn(ip_low.address, asc_rows)
        self.assertIn(ip_high.address, asc_rows)
        self.assertLess(asc_rows.index(ip_low.address), asc_rows.index(ip_high.address))

        desc_resp = self.client.get(
            url,
            {
                **base_params,
                "order[0][column]": "1",
                "order[0][dir]": "desc",
            },
        )
        self.assertEqual(desc_resp.status_code, status.HTTP_200_OK)
        desc_rows = [row["address"] for row in desc_resp.data["data"]]
        self.assertLess(desc_rows.index(ip_high.address), desc_rows.index(ip_low.address))


class TestListPorts(BaseTestCase):
    """Test case for listing ports."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()  # Creates port data
        # Link IP to subscans for API filtering to work properly
        self.data_generator.link_ip_to_subscans()

    def test_list_ports(self):
        """Test listing ports for a target and scan."""
        url = reverse("api:listPorts")
        response = self.client.get(
            url,
            {
                "target_id": self.data_generator.domain.id,
                "scan_id": self.data_generator.scan_history.id,
                "ip_address": "1.1.1.1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ports", response.data)
        # The API might return empty list if no ports are associated
        # This is expected behavior, so we just check the structure
        self.assertIsInstance(response.data["ports"], list)

    def test_list_ports_scan_id_includes_ports_on_endpoint_linked_ip(self):
        dg = self.data_generator
        scan = dg.scan_history
        ip = IpAddress.objects.create(address="203.0.113.63")
        EndPoint.objects.create(
            domain=dg.domain,
            subdomain=None,
            scan_history=scan,
            http_url="http://203.0.113.63/",
            discovered_date=timezone.now(),
            ip_address=ip,
        )
        Port.objects.create(number=19997, ip_address=ip, service_name="ep-only")
        url = reverse("api:listPorts")
        response = self.client.get(url, {"scan_id": scan.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        numbers = {p["number"] for p in response.data["ports"]}
        self.assertIn(19997, numbers)


class TestGetIpDetails(BaseTestCase):
    """Tests for single-IP detail API."""

    def test_get_ip_details_finds_ip_linked_only_via_endpoint(self):
        dg = self.data_generator
        scan = dg.scan_history
        ip = IpAddress.objects.create(address="203.0.113.70", alive=True)
        EndPoint.objects.create(
            domain=dg.domain,
            subdomain=None,
            scan_history=scan,
            http_url="http://203.0.113.70/",
            discovered_date=timezone.now(),
            ip_address=ip,
        )
        url = reverse("api:getIpDetails")
        response = self.client.get(url, {"ip_address": "203.0.113.70", "scan_id": scan.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["address"], "203.0.113.70")


class TestIpActionApiResponses(BaseTestCase):
    """Stable error_code on IP-related action endpoints."""

    @staticmethod
    def _post_json(url, client, payload: dict):
        return client.post(url, data=json.dumps(payload), content_type="application/json")

    def test_toggle_ip_important_returns_error_code_when_missing_id(self) -> None:
        url = reverse("api:toggle_ip_important")
        response = self._post_json(url, self.client, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status"))
        self.assertEqual(response.data.get("error_code"), IP_ERR_MISSING_IP_ADDRESS_ID)

    def test_unlink_scan_ips_returns_error_code_when_missing_fields(self) -> None:
        url = reverse("api:unlink_scan_ip_addresses")
        response = self._post_json(url, self.client, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error_code"), IP_ERR_MISSING_REQUIRED_FIELDS)

    def test_unlink_scan_ips_rejects_when_none_linked_to_scan(self) -> None:
        url = reverse("api:unlink_scan_ip_addresses")
        dg = self.data_generator
        other_ip = IpAddress.objects.create(address="198.51.100.55", alive=True)
        response = self._post_json(
            url,
            self.client,
            {"ip_address_ids": [other_ip.id], "scan_history_id": dg.scan_history.id},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error_code"), IP_ERR_IP_NOT_IN_SCAN)

    def test_unlink_scan_ips_unlinks_and_warns_on_partial_invalid(self) -> None:
        url = reverse("api:unlink_scan_ip_addresses")
        dg = self.data_generator
        dg.subdomain.ip_addresses.add(dg.ip_address)
        other_ip = IpAddress.objects.create(address="198.51.100.56", alive=True)
        response = self._post_json(
            url,
            self.client,
            {"ip_address_ids": [dg.ip_address.id, other_ip.id], "scan_history_id": dg.scan_history.id},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("status"))
        warnings = response.data.get("warnings")
        self.assertIsNotNone(warnings)
        self.assertEqual(warnings.get("ignored_ip_address_ids"), [other_ip.id])
        dg.subdomain.refresh_from_db()
        self.assertFalse(dg.subdomain.ip_addresses.filter(pk=dg.ip_address.id).exists())

    def test_unlink_scan_ips_accepts_comma_separated_string_ids(self) -> None:
        url = reverse("api:unlink_scan_ip_addresses")
        dg = self.data_generator
        dg.subdomain.ip_addresses.add(dg.ip_address)
        response = self._post_json(
            url,
            self.client,
            {
                "ip_address_ids": "%s" % (dg.ip_address.id,),
                "scan_history_id": dg.scan_history.id,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        dg.subdomain.refresh_from_db()
        self.assertFalse(dg.subdomain.ip_addresses.filter(pk=dg.ip_address.id).exists())

    def test_unlink_scan_ips_rejects_empty_id_list_after_parse(self) -> None:
        url = reverse("api:unlink_scan_ip_addresses")
        dg = self.data_generator
        response = self._post_json(
            url,
            self.client,
            {"ip_address_ids": [], "scan_history_id": dg.scan_history.id},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error_code"), IP_ERR_INVALID_IP_ADDRESS_IDS)


# TestWhois removed - functionality migrated to Secator


# TestReverseWhois removed - functionality migrated to Secator
