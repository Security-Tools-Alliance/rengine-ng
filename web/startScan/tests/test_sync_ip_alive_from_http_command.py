"""
Tests for sync_ip_alive_from_http management command.
"""

from io import StringIO

from django.core.management import call_command

from reNgine.services.repositories.ip_repository import IpRepository
from utils.test_base import BaseTestCase


class TestSyncIpAliveFromHttpCommand(BaseTestCase):
    """Exercise backfill of IpAddress.alive from HTTP evidence."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_command_no_ips_linked_warns(self):
        out = StringIO()
        call_command("sync_ip_alive_from_http", "--scan-history", str(self.scan_history.id), stdout=out)
        self.assertIn("No IP addresses linked", out.getvalue())

    def test_command_sets_alive_from_subdomain_http(self):
        subdomain = self.data_generator.create_subdomain(
            name="cmd-sync.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )
        ip_repo = IpRepository()
        ip_obj, _ = ip_repo.get_or_create_for_scan(
            self.scan_history.id,
            self.data_generator.target.id,
            "203.0.113.70",
            alive=False,
        )
        subdomain.ip_addresses.add(ip_obj)
        subdomain.http_status = 200
        subdomain.save(update_fields=["http_status"])
        ip_obj.alive = False
        ip_obj.save(update_fields=["alive"])

        out = StringIO()
        call_command("sync_ip_alive_from_http", "--scan-history", str(self.scan_history.id), stdout=out)
        ip_obj.refresh_from_db()
        self.assertTrue(ip_obj.alive)
        self.assertIn("set alive=True for 1 row", out.getvalue())

    def test_command_global_runs_without_scan_history(self):
        """Omitting --scan-history processes every scan that has linked IPs."""
        subdomain = self.data_generator.create_subdomain(
            name="cmd-global.example.com",
            scan_history=self.scan_history,
            domain=self.domain,
        )
        ip_repo = IpRepository()
        ip_obj, _ = ip_repo.get_or_create_for_scan(
            self.scan_history.id,
            self.data_generator.target.id,
            "203.0.113.71",
            alive=False,
        )
        subdomain.ip_addresses.add(ip_obj)
        subdomain.http_status = 200
        subdomain.save(update_fields=["http_status"])
        ip_obj.alive = False
        ip_obj.save(update_fields=["alive"])

        out = StringIO()
        call_command("sync_ip_alive_from_http", stdout=out)
        ip_obj.refresh_from_db()
        self.assertTrue(ip_obj.alive)
        out_txt = out.getvalue()
        self.assertIn("linked IPs", out_txt)
        self.assertIn("set alive=True for 1 row", out_txt)
