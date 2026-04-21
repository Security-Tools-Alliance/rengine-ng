"""Tests for vulnerability open/resolved toggle view."""

from django.urls import reverse

from utils.test_base import BaseTestCase


class ChangeVulnStatusViewTest(BaseTestCase):
    """POST change_vuln_status toggles Vulnerability.open_status."""

    def _change_vuln_status_url(self, vuln_id: int) -> str:
        return reverse(
            "change_vuln_status",
            kwargs={"slug": self.data_generator.project.slug, "id": vuln_id},
        )

    def test_post_toggles_open_status(self) -> None:
        vuln = self.data_generator.vulnerabilities[0]
        self.assertTrue(vuln.open_status)
        url = self._change_vuln_status_url(vuln.id)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        vuln.refresh_from_db()
        self.assertFalse(vuln.open_status)
        response2 = self.client.post(url)
        self.assertEqual(response2.status_code, 200)
        vuln.refresh_from_db()
        self.assertTrue(vuln.open_status)

    def test_get_does_not_toggle(self) -> None:
        vuln = self.data_generator.vulnerabilities[0]
        initial = vuln.open_status
        url = self._change_vuln_status_url(vuln.id)
        self.client.get(url)
        vuln.refresh_from_db()
        self.assertEqual(vuln.open_status, initial)
