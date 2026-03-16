"""
Security-focused tests for ServeScanFile view and get_project_for_scan_file_path helper.
Covers edge cases: endpoints without projects, mixed EndPoint/Technology references,
and attempts to access another project's file.
"""

from pathlib import Path
import tempfile
from unittest.mock import patch
import uuid

from django.urls import reverse
from rest_framework import status

from api.scan_file import ServeScanFile, build_scan_file_url, get_project_for_scan_file_path
from startScan.models import Technology
from utils.test_base import BaseTestCase
from utils.test_utils import TestDataGenerator


class GetProjectForScanFilePathTestCase(BaseTestCase):
    """Unit tests for get_project_for_scan_file_path helper."""

    def test_returns_project_when_path_matches_endpoint_screenshot_path(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "workspace/domain/screenshots/%s.png" % uuid.uuid4().hex
        self.data_generator.create_endpoint(screenshot_path=rel_path)
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)

    def test_returns_project_when_path_matches_endpoint_stored_response_path(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "workspace/domain/responses/%s.html" % uuid.uuid4().hex
        self.data_generator.create_endpoint(stored_response_path=rel_path)
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)

    def test_returns_none_when_endpoint_has_no_scan_history(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "orphan/screenshot.png"
        endpoint = self.data_generator.create_endpoint(screenshot_path=rel_path)
        endpoint.scan_history_id = None
        endpoint.save(update_fields=["scan_history_id"])
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNone(result)

    def test_returns_none_when_path_matches_no_endpoint_nor_technology(self):
        self.data_generator.create_project_full()
        result = get_project_for_scan_file_path("nonexistent/path/file.png")
        self.assertIsNone(result)

    def test_returns_project_when_path_matches_technology_stored_response_path(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        self.data_generator.create_technology()
        rel_path = "workspace/domain/tech_response_%s.html" % uuid.uuid4().hex
        self.data_generator.technology.stored_response_path = rel_path
        self.data_generator.technology.save(update_fields=["stored_response_path"])
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)

    def test_returns_project_via_technology_domain_when_no_scan_history(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        subdomain = self.data_generator.create_subdomain(scan_history=None)
        rel_path = "tech/response_%s.html" % uuid.uuid4().hex
        tech = Technology.objects.create(name="TechNoScan", stored_response_path=rel_path)
        subdomain.technologies.add(tech)
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)

    def test_endpoint_takes_precedence_over_technology_for_same_path(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "shared/path/file_%s.txt" % uuid.uuid4().hex
        self.data_generator.create_endpoint(stored_response_path=rel_path)
        tech = Technology.objects.create(name="OtherTech", stored_response_path=rel_path)
        self.data_generator.subdomain.technologies.add(tech)
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)

    def test_returns_project_when_path_normalizes_and_endpoint_has_absolute_path_stored(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_target()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "example/domain/screenshot_%s.png" % uuid.uuid4().hex
        absolute_path = "/home/secator/.secator/reports/" + rel_path
        self.data_generator.create_endpoint(screenshot_path=absolute_path)
        result = get_project_for_scan_file_path(rel_path)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.data_generator.project.id)


class ServeScanFileViewTestCase(BaseTestCase):
    """Security tests for ServeScanFile API view."""

    def _url(self, relative_path: str) -> str:
        return build_scan_file_url(relative_path) or ""

    def test_rejects_empty_path(self):
        from django.contrib.sessions.middleware import SessionMiddleware
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        request = factory.get("/api/scan-files/")
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()
        request.user = self.user
        response = ServeScanFile.as_view()(request, relative_path="")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error"), "Invalid path")

    def test_rejects_path_with_traversal(self):
        response = self.client.get(self._url("a/../b/file.png"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error"), "Invalid path")

    def test_rejects_absolute_path(self):
        url = reverse("api:serve_scan_file", kwargs={"relative_path": "/etc/passwd"})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error"), "Invalid path")

    def test_returns_404_when_file_does_not_exist(self):
        response = self.client.get(self._url("nonexistent/workspace/domain/screenshot.png"))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data.get("error"), "Not found")

    def test_returns_403_when_path_has_no_project_in_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            secret_file = base / "secret.txt"
            secret_file.write_text("secret")
            with patch("api.scan_file.RENGINE_RESULTS", str(base)):
                response = self.client.get(self._url("secret.txt"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("error"), "Forbidden")

    def test_returns_403_when_authenticated_user_has_no_access_to_project(self):
        from django.contrib.auth import get_user_model

        user_model = get_user_model()
        limited_user = user_model.objects.create_user(
            username="limiteduser",
            email="limited@test.com",
            password="testpass123",
            is_superuser=False,
        )
        gen = TestDataGenerator()
        gen.create_engine_type()
        gen.create_project()
        gen.create_domain()
        gen.create_scan_history()
        gen.create_subdomain()
        rel_path = "other/screenshot.png"
        gen.create_endpoint(screenshot_path=rel_path)
        member_only_project = self.data_generator.project
        member_only_project.users.add(limited_user)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "other").mkdir(exist_ok=True)
            (base / "other" / "screenshot.png").write_text("data")
            with patch("api.scan_file.RENGINE_RESULTS", str(base)):
                self.client.force_login(limited_user)
                response = self.client.get(self._url(rel_path))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("error"), "Forbidden")

    def test_returns_403_when_path_resolves_outside_base_via_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            outside = base.parent / "outside_dir"
            outside.mkdir(exist_ok=True)
            (outside / "leak.txt").write_text("leak")
            link_inside = base / "link"
            link_inside.symlink_to(outside)
            with patch("api.scan_file.RENGINE_RESULTS", str(base)):
                response = self.client.get(self._url("link/leak.txt"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("error"), "Forbidden")

    def test_returns_200_when_file_exists_and_user_has_project_access(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "allowed/screenshot.png"
        self.data_generator.create_endpoint(screenshot_path=rel_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "allowed").mkdir(exist_ok=True)
            (base / "allowed" / "screenshot.png").write_text("image data")
            with patch("api.scan_file.RENGINE_RESULTS", str(base)):
                response = self.client.get(self._url(rel_path))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("Content-Type"), "image/png")
        content = b"".join(response.streaming_content)
        self.assertEqual(content, b"image data")

    def test_build_scan_file_url_returns_relative_url_for_absolute_stored_path(self):
        with patch("reNgine.secator.path_utils.to_relative_scan_path") as mock_norm:
            mock_norm.return_value = "example/domain/file.png"
            url = build_scan_file_url("/home/secator/.secator/reports/example/domain/file.png")
        self.assertIsNotNone(url)
        self.assertIn("example/domain/file.png", url)
        self.assertNotIn("/home/", url)

    def test_returns_200_when_legacy_absolute_path_in_url_and_file_exists(self):
        self.data_generator.create_engine_type()
        self.data_generator.create_project()
        self.data_generator.create_domain()
        self.data_generator.create_scan_history()
        self.data_generator.create_subdomain()
        rel_path = "legacy/screenshot.png"
        absolute_stored = "/home/secator/.secator/reports/" + rel_path
        self.data_generator.create_endpoint(screenshot_path=absolute_stored)

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "legacy").mkdir(exist_ok=True)
            (base / "legacy" / "screenshot.png").write_text("image data")
            with patch("api.scan_file.RENGINE_RESULTS", str(base)):
                url = reverse("api:serve_scan_file", kwargs={"relative_path": absolute_stored})
                response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        content = b"".join(response.streaming_content)
        self.assertEqual(content, b"image data")
