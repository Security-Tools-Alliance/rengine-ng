"""
Tests for scan repository progress functionality.
"""
import unittest

from reNgine.services.repositories.scan_repository import ScanRepository


class TestScanRepositoryProgress(unittest.TestCase):
    """Test cases for ScanRepository progress methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.scan_repo = ScanRepository()

    def test_update_progress_method_exists(self):
        """Test that update_progress method exists."""
        self.assertTrue(hasattr(self.scan_repo, 'update_progress'))


if __name__ == '__main__':
    unittest.main()