"""
TestScanReconNoteViews contains unit tests for the scan recon note functionality within the application.
It verifies the behavior of the API endpoints related to adding, listing, and deleting recon notes.

Methods:
    setUp: Initializes the test environment by creating a base project and a test TodoNote.
    test_add_recon_note_success: Tests the successful addition of a recon note.
    test_add_recon_note_missing_data: Tests the addition of a recon note with missing required data.
    test_list_recon_notes: Tests the retrieval of all recon notes associated with a project.
    test_delete_recon_note_success: Tests the successful deletion of a recon note.
    test_delete_recon_note_not_found: Tests the deletion of a recon note that does not exist.
    test_delete_recon_note_wrong_project_slug_returns_404: Slug-scoped URL must not affect other projects' notes.
    test_flip_todo_status_wrong_project_slug_returns_404: Slug-scoped flip todo must reject foreign notes.
    test_flip_important_status_wrong_project_slug_returns_404: Slug-scoped flip important must reject foreign notes.
"""

import json

from django.urls import reverse
from rest_framework import status

from recon_note.models import TodoNote
from utils.test_base import BaseTestCase


class TestScanReconNoteViews(BaseTestCase):
    """Test case for the Scan Recon Note views."""

    def setUp(self):
        """Set up the test environment."""
        super().setUp()
        self.todo_note = self.data_generator.create_todo_note()  # Create a test TodoNote

    def test_add_recon_note_success(self):
        """Test adding a recon note successfully."""
        api_url = reverse("api:addReconNote")
        data = {
            "subdomain_id": self.data_generator.subdomain.id,
            "scan_history_id": self.data_generator.scan_history.id,
            "title": "New Recon Note",
            "description": "This is a new recon note",
            "project": self.data_generator.project.slug,
        }
        response = self.client.post(api_url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.json()["status"])

    def test_add_recon_note_missing_data(self):
        """Test adding a recon note with missing data."""
        api_url = reverse("api:addReconNote")
        data = {
            "title": "Incomplete Note",
            "slug": self.data_generator.project.slug,
        }
        response = self.client.post(api_url, data, content_type="application/json")
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST])
        self.assertFalse(response.json()["status"])
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "Project is required.")

    def test_list_recon_notes(self):
        """Test listing all recon notes."""
        api_url = reverse("list_note", kwargs={"slug": self.data_generator.project.slug})
        response = self.client.get(api_url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_recon_note_success(self):
        """Test deleting a recon note successfully."""
        api_url = reverse("delete_note")
        data = {"id": self.todo_note.id}
        response = self.client.post(api_url, data, content_type="application/json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.json()["status"])
        self.assertFalse(TodoNote.objects.filter(id=self.todo_note.id).exists())

    def test_delete_recon_note_not_found(self):
        """Test deleting a recon note that does not exist."""
        api_url = reverse("delete_note")
        data = {"id": 99999}  # Non-existent ID
        response = self.client.post(api_url, data, content_type="application/json")
        self.assertIn(response.status_code, [status.HTTP_404_NOT_FOUND])
        self.assertFalse(response.json()["status"])

    def test_delete_recon_note_wrong_project_slug_returns_404(self):
        """Slug-prefixed delete must not delete a note that belongs to another project."""
        note_id = self.todo_note.id
        self.data_generator.create_project()
        wrong_slug = self.data_generator.project.slug
        api_url = reverse("delete_note", kwargs={"slug": wrong_slug})
        response = self.client.post(
            api_url,
            json.dumps({"id": note_id}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.json()["status"])
        self.assertTrue(TodoNote.objects.filter(id=note_id).exists())

    def test_flip_todo_status_wrong_project_slug_returns_404(self):
        """Slug-prefixed flip todo must not toggle a note from another project."""
        note_id = self.todo_note.id
        self.data_generator.create_project()
        wrong_slug = self.data_generator.project.slug
        api_url = reverse("flip_todo_status", kwargs={"slug": wrong_slug})
        response = self.client.post(
            api_url,
            json.dumps({"id": note_id}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.json()["status"])
        self.todo_note.refresh_from_db()
        self.assertFalse(self.todo_note.is_done)

    def test_flip_important_status_wrong_project_slug_returns_404(self):
        """Slug-prefixed flip important must not toggle a note from another project."""
        note_id = self.todo_note.id
        self.data_generator.create_project()
        wrong_slug = self.data_generator.project.slug
        api_url = reverse("flip_important_status", kwargs={"slug": wrong_slug})
        response = self.client.post(
            api_url,
            json.dumps({"id": note_id}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.json()["status"])
        self.todo_note.refresh_from_db()
        self.assertFalse(self.todo_note.is_important)
