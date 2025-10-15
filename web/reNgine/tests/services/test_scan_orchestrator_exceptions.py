"""
Tests for scan orchestrator exception handling.
"""

import unittest

from reNgine.services.scan.scan_orchestrator import ScanOrchestrator


class TestScanOrchestratorExceptions(unittest.TestCase):
    """Test cases for ScanOrchestrator exception handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.orchestrator = ScanOrchestrator()

    def test_execute_scan_method_exists(self):
        """Test that execute_scan method exists."""
        self.assertTrue(hasattr(self.orchestrator, "execute_scan"))


if __name__ == "__main__":
    unittest.main()
