"""
Unit tests for on_delete constraints in recon_note models.

Tests verify that CASCADE constraints work correctly,
ensuring no orphaned data remains and no deletion blocks occur.
"""

from recon_note.models import TodoNote
from utils.test_base import BaseTestCase


class TestTodoNoteCascadeDeletion(BaseTestCase):
    """Test that deleting ScanHistory or Subdomain cascades to TodoNote."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.use_minimal_setup = True
        self.data_generator.create_project_base()

    def test_delete_scan_history_cascades_to_todo_notes(self):
        """Test that deleting a scan_history deletes all associated todo notes."""
        scan_history = self.data_generator.scan_history
        todo_note = self.data_generator.create_todo_note()

        todo_note_id = todo_note.id

        # Verify todo_note exists
        self.assertTrue(TodoNote.objects.filter(id=todo_note_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify todo_note was deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note_id).exists())

    def test_delete_subdomain_cascades_to_todo_notes(self):
        """Test that deleting a subdomain deletes all associated todo notes."""
        subdomain = self.data_generator.create_subdomain()
        todo_note = TodoNote.objects.create(
            title="Test Note",
            description="Test Description",
            project=self.data_generator.project,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )

        todo_note_id = todo_note.id

        # Verify todo_note exists
        self.assertTrue(TodoNote.objects.filter(id=todo_note_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify todo_note was deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note_id).exists())

    def test_delete_scan_history_with_multiple_todo_notes(self):
        """Test that deleting a scan_history deletes all associated todo notes."""
        scan_history = self.data_generator.scan_history

        # Create multiple todo notes
        todo_note1 = TodoNote.objects.create(
            title="Test Note 1",
            description="Test Description 1",
            project=self.data_generator.project,
            subdomain=self.data_generator.subdomain,
            scan_history=scan_history,
        )
        todo_note2 = TodoNote.objects.create(
            title="Test Note 2",
            description="Test Description 2",
            project=self.data_generator.project,
            subdomain=self.data_generator.subdomain,
            scan_history=scan_history,
        )

        todo_note1_id = todo_note1.id
        todo_note2_id = todo_note2.id

        # Verify todo notes exist
        self.assertTrue(TodoNote.objects.filter(id=todo_note1_id).exists())
        self.assertTrue(TodoNote.objects.filter(id=todo_note2_id).exists())

        # Delete scan_history
        scan_history.delete()

        # Verify all todo notes were deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note1_id).exists())
        self.assertFalse(TodoNote.objects.filter(id=todo_note2_id).exists())

    def test_delete_subdomain_with_multiple_todo_notes(self):
        """Test that deleting a subdomain deletes all associated todo notes."""
        subdomain = self.data_generator.create_subdomain()

        # Create multiple todo notes
        todo_note1 = TodoNote.objects.create(
            title="Test Note 1",
            description="Test Description 1",
            project=self.data_generator.project,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )
        todo_note2 = TodoNote.objects.create(
            title="Test Note 2",
            description="Test Description 2",
            project=self.data_generator.project,
            subdomain=subdomain,
            scan_history=self.data_generator.scan_history,
        )

        todo_note1_id = todo_note1.id
        todo_note2_id = todo_note2.id

        # Verify todo notes exist
        self.assertTrue(TodoNote.objects.filter(id=todo_note1_id).exists())
        self.assertTrue(TodoNote.objects.filter(id=todo_note2_id).exists())

        # Delete subdomain
        subdomain.delete()

        # Verify all todo notes were deleted
        self.assertFalse(TodoNote.objects.filter(id=todo_note1_id).exists())
        self.assertFalse(TodoNote.objects.filter(id=todo_note2_id).exists())
