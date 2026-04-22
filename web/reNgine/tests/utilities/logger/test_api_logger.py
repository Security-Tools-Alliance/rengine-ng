"""
Tests for SecatorAPILogger utility.
"""

from unittest.mock import MagicMock, patch

from reNgine.utilities.logger import SecatorAPILogger, get_secator_api_logger
from utils.test_base import BaseTestCase


class TestSecatorAPILogger(BaseTestCase):
    """Test cases for SecatorAPILogger."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.logger = SecatorAPILogger()
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

    def test_singleton_pattern(self):
        """Test that get_secator_api_logger returns singleton instance."""
        logger1 = get_secator_api_logger()
        logger2 = get_secator_api_logger()
        self.assertIs(logger1, logger2)

    def test_log_request_body_size_with_content_length(self):
        """Test logging request body size when Content-Length is present."""
        self.logger.log_request_body_size("PUT", "/api/secator/runner/123", "1048576")
        self.assertEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture[0][0])
        self.assertIn("1048576", all_msgs)
        self.assertIn("1.00 MB", all_msgs)
        self.assertIn("PUT", all_msgs)

    def test_log_request_body_size_without_content_length(self):
        """Test logging request body size when Content-Length is absent."""
        self.logger.log_request_body_size("POST", "/api/secator/runners", None)
        self.assertEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture[0][0])
        self.assertIn("unknown", all_msgs)
        self.assertIn("chunked", all_msgs)

    def test_log_request_body_size_small_body(self):
        """Test logging request body size for small payload (bytes)."""
        self.logger.log_request_body_size("PUT", "/api/secator/runner/1", "512")
        self.assertEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture[0][0])
        self.assertIn("512", all_msgs)
        self.assertIn("bytes", all_msgs)

    def test_log_request_body_size_invalid_content_length(self):
        """Test logging when Content-Length is present but non-numeric."""
        self.logger.log_request_body_size("PATCH", "/api/secator/runner/1", "invalid")
        self.assertEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture[0][0])
        self.assertIn("invalid", all_msgs)

    def test_log_runner_api_call(self):
        """Test logging runner API call."""
        runner_data = {
            "config": {"type": "workflow", "name": "test_workflow"},
            "context": {"scan_history_id": 123, "domain_id": 1},
        }
        self.logger.log_runner_api_call("CREATE", runner_data)
        self.assertGreaterEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture)
        self.assertIn("CREATE", all_msgs)

    def test_log_finding_api_call(self):
        """Test logging finding API call."""
        finding_data = {
            "_type": "subdomain",
            "_context": {"scan_history_id": 123, "domain_id": 1},
            "name": "test.example.com",
        }
        self.logger.log_finding_api_call("CREATE", finding_data)
        self.assertGreater(len(self.log_capture), 0)

    def test_log_runner_sync(self):
        """Test logging runner synchronization."""
        self.logger.log_runner_sync("SYNC", "test_runner", "workflow", "RUNNING", 123)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("SYNC", str(self.log_capture[0][0]))

    def test_log_finding_save_success(self):
        """Test logging successful finding save."""
        mock_object = MagicMock()
        mock_object.id = 456
        self.logger.log_finding_save("CREATE", "subdomain", mock_object, 123, 1, success=True)
        self.assertGreaterEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture)
        self.assertIn("SAVED", all_msgs)

    def test_log_finding_save_failure(self):
        """Test logging failed finding save."""
        self.logger.log_finding_save("CREATE", "subdomain", None, 123, 1, success=False, error_message="Test error")
        self.assertGreaterEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture)
        self.assertIn("FAILED", all_msgs)

    def test_log_runner_field_extraction(self):
        """Test logging runner field extraction."""
        self.logger.log_runner_field_extraction("celery_id", "test-id-123", "runner-456")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("celery_id", str(self.log_capture[0][0]))

    def test_log_metadata_ignored(self):
        """Test logging metadata type ignored."""
        self.logger.log_metadata_ignored("warning", "finding-123")
        self.assertEqual(len(self.log_capture), 2)  # INFO and DEBUG
        self.assertIn("IGNORED", str(self.log_capture[0][0]))

    def test_log_unknown_type(self):
        """Test logging unknown type."""
        self.logger.log_unknown_type("finding", "unknown_type", "id-123")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("UNKNOWN", str(self.log_capture[0][0]))

    def test_log_error(self):
        """Test logging error."""
        error = ValueError("Test error")
        context = {"prefix": self.logger.PREFIX_RUNNER, "action": "CREATE", "id": "123"}
        self.logger.log_error(error, context, exc_info=False)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("ERROR", str(self.log_capture[0][0]))

    def test_log_warning(self):
        """Test logging warning (formatted line may not include literal WARNING)."""
        self.logger.log_warning("Test warning", {"prefix": self.logger.PREFIX_RUNNER, "action": "CREATE"})
        self.assertGreaterEqual(len(self.log_capture), 1)
        all_msgs = str(self.log_capture)
        self.assertIn("Test warning", all_msgs)

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
        details = {"type": "workflow", "name": "test", "scan_id": 123}
        result = self.logger._format_info_line(
            self.logger.PREFIX_RUNNER, "CREATE", details, "SUCCESS", self.logger.COLOR_GREEN
        )
        self.assertIn("CREATE", result)
        self.assertIn("workflow", result)
        self.assertIn("SUCCESS", result)

    def test_get_prefix_color(self):
        """Test getting prefix color."""
        runner_color = self.logger._get_prefix_color(self.logger.PREFIX_RUNNER)
        finding_color = self.logger._get_prefix_color(self.logger.PREFIX_FINDING)
        sync_color = self.logger._get_prefix_color(self.logger.PREFIX_SYNC)

        self.assertEqual(runner_color, self.logger.PREFIX_RUNNER_COLOR)
        self.assertEqual(finding_color, self.logger.PREFIX_FINDING_COLOR)
        self.assertEqual(sync_color, self.logger.PREFIX_SYNC_COLOR)
