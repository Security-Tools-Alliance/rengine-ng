"""
Tests for reNgine.definitions constants.

Status helpers live in reNgine.utilities.status; see reNgine.tests.utilities.test_status.
"""

from reNgine.definitions import (
    SCAN_STATUS_VALUES,
    TASK_STATUS_VALUES,
)
from utils.test_base import BaseTestCase


class DefinitionsConstantsTestCase(BaseTestCase):
    """Sanity checks for status value sets in definitions."""

    def test_scan_status_values_derived_from_display_map_keys(self):
        self.assertIsInstance(SCAN_STATUS_VALUES, frozenset)
        self.assertIn(-1, SCAN_STATUS_VALUES)
        self.assertIn(0, SCAN_STATUS_VALUES)

    def test_task_status_values_derived_from_task_map_keys(self):
        self.assertIsInstance(TASK_STATUS_VALUES, frozenset)
        self.assertIn(-1, TASK_STATUS_VALUES)
        self.assertIn(0, TASK_STATUS_VALUES)
