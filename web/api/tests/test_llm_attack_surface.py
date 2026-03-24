"""API tests for LLM attack-surface endpoint (aggregate entities and XOR validation)."""

from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from dashboard.models import Project
from reNgine.llm.attack_surface_storage import UNSPECIFIED_LLM_MODEL_KEY
from startScan.models import LlmAttackSurfaceAnalysis
from targetApp.models import Target
from utils.test_base import BaseTestCase


class LLMAttackSurfaceApiTests(BaseTestCase):
    def test_get_without_entity_id_returns_400(self) -> None:
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status", True))

    def test_get_with_two_entity_ids_returns_400(self) -> None:
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {"target_id": self.data_generator.target.id, "scope_id": 99999},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_with_non_positive_target_id_and_valid_organization_returns_400(self) -> None:
        url = reverse("api:llm_get_possible_attacks")
        oid = self.data_generator.organization.id
        response = self.client.get(url, {"target_id": "0", "organization_id": oid})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status", True))
        self.assertIn("target_id", (response.data.get("error") or "").lower())

    def test_get_target_check_only_without_cache(self) -> None:
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {
                "target_id": self.data_generator.target.id,
                "check_only": "true",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIsNone(response.data.get("description"))

    @patch("reNgine.llm.llm.LLMAttackSuggestionGenerator.get_attack_suggestion")
    def test_get_target_force_regenerate_calls_llm(self, mock_llm) -> None:
        mock_llm.return_value = {
            "status": True,
            "description": "Synthetic aggregate analysis",
            "input": "",
            "model_name": None,
        }
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {
                "target_id": self.data_generator.target.id,
                "llm_model": "unit-test-model",
                "force_regenerate": "true",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        mock_llm.assert_called_once()
        self.assertIn("Synthetic aggregate analysis", response.data.get("description", ""))

    @patch("reNgine.llm.llm.LLMAttackSuggestionGenerator.get_attack_suggestion")
    def test_get_target_persists_llm_row_when_llm_model_omitted(self, mock_llm) -> None:
        mock_llm.return_value = {
            "status": True,
            "description": "Analysis body",
            "input": "",
            "model_name": None,
        }
        url = reverse("api:llm_get_possible_attacks")
        tid = self.data_generator.target.id
        response = self.client.get(url, {"target_id": tid, "force_regenerate": "true"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ct = ContentType.objects.get_for_model(Target)
        rows = LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=tid)
        self.assertEqual(rows.count(), 1)
        row = rows.first()
        self.assertEqual(row.llm_model, UNSPECIFIED_LLM_MODEL_KEY)
        self.assertEqual(row.body_markdown.strip(), "Analysis body")
        self.assertEqual(response.data.get("selected_analysis_id"), row.id)

    def test_get_target_check_only_with_saved_analyses_returns_list_without_description(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model=UNSPECIFIED_LLM_MODEL_KEY,
            body_markdown="Cached body",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {"target_id": tid, "check_only": "true"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertIsNone(response.data.get("description"))
        saved = response.data.get("saved_analyses") or []
        self.assertEqual(len(saved), 1)
        self.assertIn("id", saved[0])
        self.assertIsNotNone(response.data.get("selected_analysis_id"))

    def test_get_target_with_attack_surface_analysis_id_returns_matching_body(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        older = LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="unit-test-model-a",
            body_markdown="Older unique marker xyz111",
        )
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="unit-test-model-b",
            body_markdown="Newer unique marker xyz222",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {
                "target_id": tid,
                "attack_surface_analysis_id": older.pk,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        desc = response.data.get("description") or ""
        self.assertIn("xyz111", desc)
        self.assertNotIn("xyz222", desc)
        self.assertEqual(response.data.get("selected_analysis_id"), older.pk)

    def test_get_target_unknown_attack_surface_analysis_id_returns_404(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model=UNSPECIFIED_LLM_MODEL_KEY,
            body_markdown="Only one",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {"target_id": tid, "attack_surface_analysis_id": 999999999},
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data.get("status", True))

    def test_get_target_attack_surface_analysis_id_zero_returns_400(self) -> None:
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(
            url,
            {
                "target_id": self.data_generator.target.id,
                "attack_surface_analysis_id": "0",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status", True))
        self.assertIn("attack_surface_analysis_id", (response.data.get("error") or "").lower())

    def test_delete_one_analysis_sets_remaining_true_when_others_exist(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        first = LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="del-a",
            body_markdown="A",
        )
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="del-b",
            body_markdown="B",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.delete("%s?target_id=%s&attack_surface_analysis_id=%s" % (url, tid, first.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertTrue(response.data.get("remaining_analyses"))
        self.assertEqual(
            LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=tid).count(),
            1,
        )

    def test_delete_non_numeric_attack_surface_analysis_id_returns_400(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="keep-me",
            body_markdown="Must remain",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.delete(
            "%s?target_id=%s&attack_surface_analysis_id=notanint" % (url, tid),
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data.get("status", True))
        self.assertIn("attack_surface_analysis_id", (response.data.get("error") or "").lower())
        self.assertEqual(
            LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=tid).count(),
            1,
        )

    def test_delete_without_analysis_id_clears_all(self) -> None:
        tid = self.data_generator.target.id
        ct = ContentType.objects.get_for_model(Target)
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="x1",
            body_markdown="A",
        )
        LlmAttackSurfaceAnalysis.objects.create(
            content_type=ct,
            object_id=tid,
            llm_model="x2",
            body_markdown="B",
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.delete("%s?target_id=%s" % (url, tid))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertFalse(response.data.get("remaining_analyses"))
        self.assertEqual(
            LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=tid).count(),
            0,
        )

    def test_get_target_from_other_project_returns_404(self) -> None:
        # BaseTestCase user is a superuser; project filter is skipped for superusers.
        self.user.is_superuser = False
        self.user.save(update_fields=["is_superuser"])
        other = Project.objects.create(
            name="Isolated Project LLM AS",
            slug="isolated-proj-llm-as",
            insert_date=timezone.now(),
        )
        alien = Target.objects.create(
            project=other,
            value="isolated.anon.example.test",
            target_type="host",
            insert_date=timezone.now(),
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.get(url, {"target_id": alien.pk})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_target_from_other_project_returns_404(self) -> None:
        self.user.is_superuser = False
        self.user.save(update_fields=["is_superuser"])
        other = Project.objects.create(
            name="Isolated Project LLM AS Del",
            slug="isolated-proj-llm-as-del",
            insert_date=timezone.now(),
        )
        alien = Target.objects.create(
            project=other,
            value="isolated-del.anon.example.test",
            target_type="host",
            insert_date=timezone.now(),
        )
        url = reverse("api:llm_get_possible_attacks")
        response = self.client.delete("%s?target_id=%s" % (url, alien.pk))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
