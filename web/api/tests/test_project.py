"""
This file contains the test cases for the API views.
"""

from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from utils.test_base import BaseTestCase

__all__ = [
    'TestCreateProjectApi',
    'TestAddReconNote',
    'TestListTodoNotes',
]

class TestCreateProjectApi(BaseTestCase):
    """Tests for the Create Project API."""

    def test_create_project_success(self):
        """Test successful project creation."""
        api_url = reverse("api:create_project")
        response = self.client.get(
            api_url,
            {
                "name": "New Project",
                "insert_date": timezone.now(),
                "slug": "new-project",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])
        self.assertEqual(response.data["project_name"], "New Project")

    def test_create_project_failure(self):
        """Test project creation failure when no name is provided."""
        api_url = reverse("api:create_project")
        response = self.client.get(api_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])

class TestAddReconNote(BaseTestCase):
    """Test case for the Add Recon Note API."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_base()

    def test_add_recon_note(self):
        """Test adding a recon note."""
        api_url = reverse("api:addReconNote")
        data = {
            "subdomain_id": self.data_generator.subdomain.id,
            "scan_history_id": self.data_generator.scan_history.id,
            "title": "Test Note",
            "description": "This is a test note",
            "project": self.data_generator.project.slug,
        }
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["status"])

    def test_add_recon_note_missing_data(self):
        """Test adding a recon note with missing data."""
        api_url = reverse("api:addReconNote")
        data = {"title": "Test Note", "slug": "test-project"}
        response = self.client.post(api_url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["status"])

class TestListTodoNotes(BaseTestCase):
    """Test case for listing todo notes."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()
        self.data_generator.create_todo_note()

    def test_list_todo_notes(self):
        """Test listing todo notes for a project."""
        url = reverse("api:listTodoNotes")
        response = self.client.get(url, {"project": self.data_generator.project.slug})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data["notes"]), 1)
        self.assertEqual(
            response.data["notes"][0]["id"], self.data_generator.todo_note.id
        )
        self.assertEqual(
            response.data["notes"][0]["title"], self.data_generator.todo_note.title
        )
        self.assertEqual(
            response.data["notes"][0]["description"],
            self.data_generator.todo_note.description,
        )
        self.assertEqual(
            response.data["notes"][0]["project"],
            self.data_generator.todo_note.project.id,
        )
        self.assertEqual(
            response.data["notes"][0]["subdomain"],
            self.data_generator.todo_note.subdomain.id,
        )
        self.assertEqual(
            response.data["notes"][0]["scan_history"],
            self.data_generator.todo_note.scan_history.id,
        )

