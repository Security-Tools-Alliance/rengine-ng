"""
Tests for BaseLogger utility.
"""

from unittest.mock import patch

from reNgine.utilities.logger.base import BaseLogger
from utils.test_base import BaseTestCase


class TestBaseLogger(BaseTestCase):
    """Test cases for BaseLogger."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

        class ConcreteLogger(BaseLogger):
            """Concrete implementation for testing."""

            PREFIX = "[TEST]"

            def _get_prefix_color(self, prefix: str) -> str:
                """Get color for prefix."""
                return self.COLOR_CYAN

        self.logger = ConcreteLogger()
        # Capture log output
        self.log_capture = []
        self.original_log = self.logger._logger.info

        def capture_log(*args, **kwargs):
            self.log_capture.append((args, kwargs))
            return self.original_log(*args, **kwargs)

        self.logger._logger.info = capture_log
        self.logger._logger.debug = capture_log
        self.logger._logger.warning = capture_log
        self.logger._logger.error = capture_log

    def test_colorize_with_colors_enabled(self):
        """Test colorization when colors are enabled."""
        with patch.object(self.logger, "_use_colors", True):
            result = self.logger._colorize("test", self.logger.COLOR_GREEN)
            self.assertIn(self.logger.COLOR_GREEN, result)
            self.assertIn(self.logger.COLOR_RESET, result)

    def test_colorize_with_colors_disabled(self):
        """Test colorization when colors are disabled."""
        with patch.object(self.logger, "_use_colors", False):
            result = self.logger._colorize("test", self.logger.COLOR_GREEN)
            self.assertEqual(result, "test")

    def test_format_info_line(self):
        """Test formatting info line."""
        details = {"type": "test", "name": "test_name", "id": 123}
        result = self.logger._format_info_line(
            self.logger.PREFIX, "CREATE", details, "SUCCESS", self.logger.COLOR_GREEN
        )
        self.assertIn("CREATE", result)
        self.assertIn("test", result)
        self.assertIn("SUCCESS", result)

    def test_format_info_message(self):
        """Test formatting info message."""
        result = self.logger._format_info_message(self.logger.PREFIX, "CREATE", "Test message")
        self.assertIn("CREATE", result)
        self.assertIn("Test message", result)

    def test_format_debug_message(self):
        """Test formatting debug message."""
        result = self.logger._format_debug_message(self.logger.PREFIX, "DEBUG", "Test debug message")
        self.assertIn("DEBUG", result)
        self.assertIn("Test debug message", result)

    def test_log_error(self):
        """Test logging error."""
        error = ValueError("Test error")
        context = {"prefix": self.logger.PREFIX, "action": "CREATE", "id": "123"}
        self.logger.log_error(error, context, exc_info=False)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("ERROR", str(self.log_capture[0][0]))

    def test_log_warning(self):
        """Test logging warning (formatted line may not include literal WARNING)."""
        self.logger.log_warning("Test warning", {"prefix": self.logger.PREFIX, "action": "CREATE"})
        self.assertGreaterEqual(len(self.log_capture), 1)
        self.assertIn("Test warning", str(self.log_capture))

    def test_log_debug(self):
        """Test logging debug message."""
        self.logger.log_debug(self.logger.PREFIX, "DEBUG", "Test debug")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("DEBUG", str(self.log_capture[0][0]))

    def test_log_data_structure(self):
        """Test logging data structure."""
        data = {"key1": "value1", "key2": "value2"}
        self.logger.log_data_structure(data, self.logger.PREFIX, "test_type")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("STRUCTURE", str(self.log_capture[0][0]))
