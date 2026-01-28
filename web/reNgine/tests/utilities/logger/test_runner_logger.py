"""
Tests for RunnerLogger utility.
"""

from unittest.mock import MagicMock

from reNgine.utilities.logger import RunnerLogger, get_runner_logger
from utils.test_base import BaseTestCase


class TestRunnerLogger(BaseTestCase):
    """Test cases for RunnerLogger."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.logger = RunnerLogger()
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
        """Test that get_runner_logger returns singleton instance."""
        logger1 = get_runner_logger()
        logger2 = get_runner_logger()
        self.assertIs(logger1, logger2)

    def test_log_runner_creation(self):
        """Test logging runner creation."""
        self.logger.log_runner_creation(
            runner_type="Workflow",
            runner_name="test_workflow",
            targets=["example.com"],
            scan_history_id=123,
            domain_id=1,
        )
        self.assertGreater(len(self.log_capture), 0)
        self.assertIn("CREATE", str(self.log_capture[0][0]))

    def test_log_config_preparation(self):
        """Test logging config preparation."""
        base_config = {"sync": False, "global": {"timeout": 300}}
        merged_config = {"sync": False, "global": {"timeout": 300, "concurrency": 20}}
        profiles = {"speed": "fast"}
        self.logger.log_config_preparation(base_config, merged_config, profiles)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("PREPARE", str(self.log_capture[0][0]))

    def test_log_targets(self):
        """Test logging targets."""
        self.logger.log_targets(["example.com", "test.com"], "Workflow")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("TARGETS", str(self.log_capture[0][0]))

    def test_log_run_opts(self):
        """Test logging run options."""
        run_opts = {"sync": False, "timeout": 300}
        self.logger.log_run_opts(run_opts)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("OPTS", str(self.log_capture[0][0]))

    def test_log_context(self):
        """Test logging context."""
        context = {"scan_history_id": 123, "domain_id": 1}
        self.logger.log_context(context)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("CONTEXT", str(self.log_capture[0][0]))

    def test_log_hooks(self):
        """Test logging hooks."""
        hooks = {"on_runner_start": MagicMock()}
        self.logger.log_hooks(hooks)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("HOOKS", str(self.log_capture[0][0]))

    def test_log_runner_execution_start(self):
        """Test logging runner execution start."""
        self.logger.log_runner_execution_start("Workflow", "test_workflow")
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("EXECUTE", str(self.log_capture[0][0]))
        self.assertIn("STARTED", str(self.log_capture[0][0]))

    def test_log_runner_execution_end_success(self):
        """Test logging runner execution end with success."""
        self.logger.log_runner_execution_end("Workflow", "test_workflow", "success", {"result": "ok"})
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("EXECUTE", str(self.log_capture[0][0]))
        self.assertIn("COMPLETED", str(self.log_capture[0][0]))

    def test_log_runner_execution_end_error(self):
        """Test logging runner execution end with error."""
        self.logger.log_runner_execution_end("Workflow", "test_workflow", "error", None)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("EXECUTE", str(self.log_capture[0][0]))
        self.assertIn("FAILED", str(self.log_capture[0][0]))

    def test_log_runner_error(self):
        """Test logging runner error."""
        error = ValueError("Test error")
        context = {"runner_name": "test_workflow"}
        self.logger.log_runner_error("Workflow", error, context)
        self.assertEqual(len(self.log_capture), 1)
        self.assertIn("ERROR", str(self.log_capture[0][0]))

    def test_get_prefix_color(self):
        """Test getting prefix color."""
        color = self.logger._get_prefix_color(self.logger.PREFIX)
        self.assertEqual(color, self.logger.PREFIX_COLOR)
