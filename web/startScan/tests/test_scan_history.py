"""
Unit tests for scan_history view and its annotated count subqueries.
"""

from django.urls import reverse

from reNgine.utilities.db import count_subquery
from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
from utils.test_base import BaseTestCase


class TestScanHistoryCountAnnotations(BaseTestCase):
    """Test that scan_history queryset annotations return correct counts via subqueries."""

    def test_scan_history_annotated_counts_match_related_counts(self):
        """Annotated subdomain_count, endpoint_count, vuln_*_count match actual related counts."""
        gen = self.data_generator
        slug = gen.project.slug
        sh = gen.scan_history
        domain = gen.domain
        subdomain = gen.subdomain
        endpoint = gen.endpoint
        # One subdomain, one endpoint, one vulnerability (severity=1) already created by create_project_full
        Subdomain.objects.create(name="second.example.com", target_domain=domain, scan_history=sh)
        EndPoint.objects.create(
            target_domain=domain,
            subdomain=subdomain,
            scan_history=sh,
            discovered_date=gen.scan_history.start_scan_date,
            http_url="https://admin.example.com/other",
        )
        Vulnerability.objects.create(
            name="Medium Vuln",
            severity=2,
            discovered_date=sh.start_scan_date,
            target_domain=domain,
            subdomain=subdomain,
            scan_history=sh,
            endpoint=endpoint,
        )
        Vulnerability.objects.create(
            name="Critical Vuln",
            severity=4,
            discovered_date=sh.start_scan_date,
            target_domain=domain,
            subdomain=subdomain,
            scan_history=sh,
            endpoint=endpoint,
        )
        # Now we have: 2 subdomains, 2 endpoints, 3 vulnerabilities (severity 1, 2, 4)
        queryset = (
            ScanHistory.objects.filter(domain__project__slug=slug)
            .order_by("-start_scan_date")
            .annotate(
                subdomain_count=count_subquery(Subdomain, "scan_history_id"),
                endpoint_count=count_subquery(EndPoint, "scan_history_id"),
                vuln_count=count_subquery(Vulnerability, "scan_history_id"),
                vuln_critical_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 4}),
                vuln_high_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 3}),
                vuln_medium_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 2}),
            )
        )
        row = queryset.get(id=sh.id)
        self.assertEqual(row.subdomain_count, 2)
        self.assertEqual(row.endpoint_count, 2)
        self.assertEqual(row.vuln_count, 3)
        self.assertEqual(row.vuln_critical_count, 1)
        self.assertEqual(row.vuln_high_count, 0)
        self.assertEqual(row.vuln_medium_count, 1)


class TestScanHistoryView(BaseTestCase):
    """Test scan_history view returns 200 and context."""

    def test_scan_history_view_returns_200_and_context(self):
        """scan_history view returns 200 and context contains scan_history queryset."""
        response = self.client.get(reverse("scan_history", kwargs={"slug": self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertIn("scan_history", response.context)
        self.assertIn("scan_history_active", response.context)
        self.assertEqual(response.context["scan_history_active"], "active")
