"""
Tests for Secator tasks functionality.
"""

import unittest

from reNgine.tasks.secator_tasks import initiate_secator_scan


class TestSecatorTasks(unittest.TestCase):
    """Test cases for Secator tasks."""

    def test_initiate_secator_scan_exists(self):
        """Test that initiate_secator_scan function exists."""
        self.assertTrue(callable(initiate_secator_scan))


if __name__ == "__main__":
    unittest.main()
