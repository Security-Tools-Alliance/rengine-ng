"""Tests for IpAddress.get_project_timeline (dashboard sparkline)."""

from datetime import timedelta

from django.utils import timezone

from startScan.models import IpAddress
from utils.test_base import BaseTestCase, TestDataGenerator


class IpAddressProjectTimelineTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.data_gen = TestDataGenerator()

    def test_get_project_timeline_empty_returns_seven_zeros(self) -> None:
        self.data_gen.create_project()
        last_week = timezone.now() - timedelta(days=7)
        date_range = [last_week + timedelta(days=i) for i in range(7)]
        out = IpAddress.get_project_timeline(self.data_gen.project, date_range)
        self.assertEqual(len(out), 7)
        self.assertEqual(sum(out), 0)

    def test_get_project_timeline_counts_distinct_ip_per_discovery_day(self) -> None:
        self.data_gen.create_engine_type()
        self.data_gen.create_project()
        self.data_gen.create_target()
        self.data_gen.create_domain()
        self.data_gen.create_scan_history()
        now = timezone.now()
        self.data_gen.create_subdomain(discovered_date=now)
        self.data_gen.create_ip_address(address="203.0.113.10")
        self.data_gen.subdomain.ip_addresses.add(self.data_gen.ip_address)

        # Include the calendar day of `now` so TruncDay(discovered_date) matches an entry in date_range.
        week_start = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        date_range = [week_start + timedelta(days=i) for i in range(7)]
        out = IpAddress.get_project_timeline(self.data_gen.project, date_range)
        self.assertEqual(len(out), 7)
        self.assertGreaterEqual(sum(out), 1)
