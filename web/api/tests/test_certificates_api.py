"""
Tests for certificates list API (ListCertificates).
"""

from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from startScan.models import Certificate
from utils.test_base import BaseTestCase


class ListCertificatesTest(BaseTestCase):
    """Test cases for GET api/certificates/?subdomain_id=."""

    def setUp(self):
        super().setUp()
        self.url = reverse("api:certificates_list")
        self.subdomain = self.data_generator.create_subdomain()

    def test_missing_subdomain_id_returns_400(self):
        """Request without subdomain_id returns 400."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)
        self.assertIn("subdomain_id", response.data["detail"].lower())

    def test_empty_list_when_no_certificates(self):
        """Returns empty certificates list when subdomain has no certificates."""
        response = self.client.get(self.url, {"subdomain_id": self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("certificates", response.data)
        self.assertEqual(response.data["certificates"], [])

    def test_returns_certificates_for_subdomain(self):
        """Returns certificates linked to the given subdomain."""
        cert1 = Certificate.objects.create(
            host="host1.example.com",
            subdomain=self.subdomain,
            scan_history=self.subdomain.scan_history,
            fingerprint_sha256="a" * 64,
            subject_cn="host1.example.com",
            not_before=timezone.now(),
            not_after=timezone.now(),
        )
        cert2 = Certificate.objects.create(
            host="host2.example.com",
            subdomain=self.subdomain,
            scan_history=self.subdomain.scan_history,
            fingerprint_sha256="b" * 64,
            subject_cn="host2.example.com",
        )
        response = self.client.get(self.url, {"subdomain_id": self.subdomain.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        certs = response.data["certificates"]
        self.assertEqual(len(certs), 2)
        ids = {c["id"] for c in certs}
        self.assertEqual(ids, {cert1.id, cert2.id})
        for c in certs:
            self.assertIn("host", c)
            self.assertIn("subject_cn", c)
            self.assertIn("issuer_cn", c)
            self.assertIn("not_before", c)
            self.assertIn("not_after", c)
            self.assertIn("fingerprint_sha256", c)

    def test_filter_by_scan_id(self):
        """When scan_id is provided, only certificates for that scan are returned."""
        cert = Certificate.objects.create(
            host="host.example.com",
            subdomain=self.subdomain,
            scan_history=self.subdomain.scan_history,
            fingerprint_sha256="a" * 64,
        )
        response = self.client.get(
            self.url,
            {"subdomain_id": self.subdomain.id, "scan_id": self.subdomain.scan_history_id},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["certificates"]), 1)
        self.assertEqual(response.data["certificates"][0]["id"], cert.id)

        response_wrong_scan = self.client.get(
            self.url,
            {"subdomain_id": self.subdomain.id, "scan_id": 99999},
        )
        self.assertEqual(response_wrong_scan.status_code, status.HTTP_200_OK)
        self.assertEqual(response_wrong_scan.data["certificates"], [])
