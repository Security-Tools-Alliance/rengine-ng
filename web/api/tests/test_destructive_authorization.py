from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rolepermissions.roles import assign_role
from rest_framework import status

from dashboard.models import Project
from startScan.models import ScanHistory, SubScan, Subdomain, Vulnerability
from targetApp.models import Domain
from utils.test_base import BaseTestCase


class TestDestructiveAuthorization(BaseTestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.mutation_user = User.objects.create_user(username="mutation")
        self.project_a = self.data_generator.project
        self.project_a.users.add(self.mutation_user)
        assign_role(self.mutation_user, "penetration_tester")

        self.project_b = Project.objects.create(
            name="Project B", slug="project-b", insert_date=timezone.now()
        )
        self.data_generator.project = self.project_b
        self.data_generator.domain = Domain.objects.create(
            name="other.example.com",
            project=self.project_b,
            insert_date=timezone.now(),
        )
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain("other.example.com")
        self.data_generator.create_endpoint()
        self.data_generator.create_subscan()
        self.data_generator.create_vulnerability()

        self.project_a_subdomain = Subdomain.objects.filter(
            target_domain__project=self.project_a
        ).first()
        self.project_a_vulnerability = Vulnerability.objects.filter(
            target_domain__project=self.project_a
        ).first()
        self.project_a_subscan = SubScan.objects.filter(
            scan_history__domain__project=self.project_a
        ).first()
        self.project_a_subscan_2 = SubScan.objects.create(
            start_scan_date=timezone.now(),
            scan_history=ScanHistory.objects.filter(domain__project=self.project_a).first(),
            subdomain=Subdomain.objects.filter(target_domain__project=self.project_a).first(),
            status=1,
        )
        self.project_b_subdomain = Subdomain.objects.filter(
            target_domain__project=self.project_b
        ).first()
        self.project_b_vulnerability = Vulnerability.objects.filter(
            target_domain__project=self.project_b
        ).first()
        self.project_b_subscan = SubScan.objects.filter(
            scan_history__domain__project=self.project_b
        ).first()

    def _login_as_mutation_user(self):
        self.client.force_login(self.mutation_user)

    def test_project_scoped_deletes_and_non_enumerating_denials(self):
        self._login_as_mutation_user()
        cases = (
            ("delete_subdomain", "subdomain_ids", self.project_b_subdomain.id),
            ("delete_vulnerability", "vulnerability_ids", self.project_b_vulnerability.id),
        )
        for endpoint, field, object_id in cases:
            response = self.client.post(reverse(f"api:{endpoint}"), {field: [object_id]})
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            self.assertTrue(
                type(self.project_b_subdomain if field == "subdomain_ids" else self.project_b_vulnerability)
                .objects.filter(id=object_id).exists()
            )
            response = self.client.post(reverse(f"api:{endpoint}"), {field: [999999999]})
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_authorized_deletes_and_atomic_batches(self):
        self._login_as_mutation_user()
        response = self.client.post(
            reverse("api:delete_rows"),
            {
                "type": "subscan",
                "rows": [self.project_a_subscan.id, self.project_a_subscan_2.id],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(SubScan.objects.filter(id=self.project_a_subscan.id).exists())
        self.assertFalse(SubScan.objects.filter(id=self.project_a_subscan_2.id).exists())

        response = self.client.post(
            reverse("api:delete_vulnerability"),
            {"vulnerability_ids": [self.project_a_vulnerability.id]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Vulnerability.objects.filter(id=self.project_a_vulnerability.id).exists())

        response = self.client.post(
            reverse("api:delete_subdomain"),
            {"subdomain_ids": [self.project_a_subdomain.id]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Subdomain.objects.filter(id=self.project_a_subdomain.id).exists())

    def test_mixed_project_batch_is_atomic(self):
        self._login_as_mutation_user()
        response = self.client.post(
            reverse("api:delete_rows"),
            {
                "type": "subscan",
                "rows": [self.project_a_subscan.id, self.project_b_subscan.id],
            },
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(SubScan.objects.filter(id=self.project_a_subscan.id).exists())
        self.assertTrue(SubScan.objects.filter(id=self.project_b_subscan.id).exists())

    def test_invalid_or_missing_rows_are_safe(self):
        self._login_as_mutation_user()
        response = self.client.post(
            reverse("api:delete_rows"),
            {"type": "subscan", "rows": ["invalid", self.project_a_subscan.id]},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(SubScan.objects.filter(id=self.project_a_subscan.id).exists())

        response = self.client.post(
            reverse("api:delete_rows"),
            {"type": "subscan", "rows": [999999999]},
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(SubScan.objects.filter(id=self.project_a_subscan.id).exists())

    def test_auditor_and_anonymous_are_denied(self):
        auditor = get_user_model().objects.create_user(username="auditor")
        self.project_a.users.add(auditor)
        assign_role(auditor, "auditor")
        self.client.force_login(auditor)
        response = self.client.post(
            reverse("api:delete_subdomain"),
            {"subdomain_ids": [self.project_a_subdomain.id]},
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(Subdomain.objects.filter(id=self.project_a_subdomain.id).exists())

        self.client = self.client_class()
        response = self.client.post(
            reverse("api:delete_subdomain"),
            {"subdomain_ids": [self.project_a_subdomain.id]},
        )
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_302_FOUND))
        self.assertTrue(Subdomain.objects.filter(id=self.project_a_subdomain.id).exists())

    def test_system_administrator_can_delete(self):
        response = self.client.post(
            reverse("api:delete_subdomain"),
            {"subdomain_ids": [self.project_a_subdomain.id]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Subdomain.objects.filter(id=self.project_a_subdomain.id).exists())
