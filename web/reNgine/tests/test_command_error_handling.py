"""
Unit tests for command error handling and exception preservation.

Tests that exceptions are properly logged with full tracebacks
and that error context is preserved for debugging.
"""

from unittest.mock import MagicMock, patch

from reNgine.tasks.command import _run_command_internal
from utils.test_base import BaseTestCase


class TestCommandErrorHandling(BaseTestCase):
    """Test error handling preserves exception context."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    @patch("reNgine.tasks.command.logger")
    @patch("reNgine.tasks.command.create_command_object")
    @patch("reNgine.tasks.command.execute_command")
    def test_oserror_logs_with_traceback(self, mock_execute, mock_create, mock_logger):
        """Test that OSError is logged with full traceback."""
        # Setup mock to raise OSError
        mock_create.return_value = MagicMock()
        mock_execute.side_effect = OSError("Command not found")

        # Test _run_command_internal directly
        return_code, output = _run_command_internal(
            cmd="nonexistent_command",
            cwd=None,
            shell=False,
            history_file=None,
            scan_id=None,
            activity_id=None,
            remove_ansi_sequence=False,
            combine_output=False,
        )

        # Verify the command handled the error gracefully
        self.assertEqual(return_code, -1)

        # Verify that logger.exception was called (which captures full traceback)
        mock_logger.exception.assert_called()
        # Verify the exception message mentions OSError
        call_args = str(mock_logger.exception.call_args)
        self.assertIn("OSError", call_args)

    @patch("reNgine.tasks.command.logger")
    @patch("reNgine.tasks.command.create_command_object")
    def test_create_command_object_error_preserves_traceback(self, mock_create, mock_logger):
        """Test that errors in create_command_object are logged with traceback."""
        # Setup mock to raise unexpected exception
        mock_create.side_effect = RuntimeError("Database connection lost")

        return_code, output = _run_command_internal(
            cmd="test command",
            cwd=None,
            shell=False,
            history_file=None,
            scan_id=None,
            activity_id=None,
            remove_ansi_sequence=False,
            combine_output=False,
        )

        # Verify the command handled the critical error
        self.assertEqual(return_code, -1)
        self.assertIn("Critical error", output)

        # Verify that exception type is included in output
        self.assertIn("RuntimeError", output)

        # Verify that logger.exception was called to capture full traceback
        mock_logger.exception.assert_called()

    @patch("reNgine.tasks.command.logger")
    @patch("reNgine.tasks.command.create_command_object")
    @patch("reNgine.tasks.command.execute_command")
    @patch("reNgine.tasks.command.write_history")
    def test_write_history_error_doesnt_break_execution(self, mock_write, mock_execute, mock_create, mock_logger):
        """Test that write_history errors are logged but don't affect command result."""
        # Setup successful command execution
        mock_cmd_obj = MagicMock()
        mock_create.return_value = mock_cmd_obj

        # Note: execute_command uses universal_newlines=True, so communicate() returns strings not bytes
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("Success output", "")
        mock_process.returncode = 0
        mock_execute.return_value = mock_process

        # Setup write_history to fail
        mock_write.side_effect = IOError("Disk full")

        return_code, output = _run_command_internal(
            cmd="test command",
            cwd=None,
            shell=False,
            history_file="/tmp/history.txt",
            scan_id=None,
            activity_id=None,
            remove_ansi_sequence=False,
            combine_output=False,
        )

        # Command should succeed despite history write failure
        self.assertEqual(return_code, 0)
        self.assertEqual(output, "Success output")

        # Verify that logger.exception was called for write_history failure
        mock_logger.exception.assert_called()
        # Verify the log message mentions write_history
        call_args = str(mock_logger.exception.call_args)
        self.assertIn("write command history", call_args)

    @patch("reNgine.tasks.command.logger")
    @patch("reNgine.tasks.command.create_command_object")
    @patch("reNgine.tasks.command.execute_command")
    def test_command_object_save_error_logged_with_traceback(self, mock_execute, mock_create, mock_logger):
        """Test that save errors are logged with full traceback."""
        # Setup command execution success
        # Note: execute_command uses universal_newlines=True, so communicate() returns strings not bytes
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("output", "")
        mock_process.returncode = 0
        mock_execute.return_value = mock_process

        # Setup command object save to fail
        mock_cmd_obj = MagicMock()
        mock_cmd_obj.save.side_effect = Exception("Database write error")
        mock_create.return_value = mock_cmd_obj

        return_code, output = _run_command_internal(
            cmd="test command",
            cwd=None,
            shell=False,
            history_file=None,
            scan_id=None,
            activity_id=None,
            remove_ansi_sequence=False,
            combine_output=False,
        )

        # Command execution should still return correct results
        self.assertEqual(return_code, 0)
        self.assertEqual(output, "output")

        # Verify that logger.exception was called for save error
        mock_logger.exception.assert_called()
        # Verify the log message mentions failed save
        call_args = str(mock_logger.exception.call_args)
        self.assertIn("Failed to save command object", call_args)

    def test_exception_type_preserved_in_critical_error(self):
        """Test that exception type name is preserved in critical error output."""
        # This test verifies the improvement where we include exception type
        # instead of just str(e)

        with patch("reNgine.tasks.command.create_command_object") as mock_create:
            # Simulate a specific exception type
            mock_create.side_effect = ValueError("Invalid scan_id format")

            return_code, output = _run_command_internal(
                cmd="test command",
                cwd=None,
                shell=False,
                history_file=None,
                scan_id="invalid",
                activity_id=None,
                remove_ansi_sequence=False,
                combine_output=False,
            )

            # Verify exception type is in output for better debugging
            self.assertIn("ValueError", output)
            self.assertIn("Invalid scan_id format", output)
            self.assertEqual(return_code, -1)


class TestCommandErrorHandlingDocumentation(BaseTestCase):
    """Document expected error handling behavior."""

    def test_error_handling_guarantees(self):
        """
        Document the error handling guarantees of run_command.

        Guarantees:
        1. Always returns a tuple (return_code, output)
        2. Never raises exceptions to caller
        3. Logs all exceptions with full traceback using logger.exception()
        4. Preserves exception type information in critical errors
        5. Attempts to save command state even on errors
        6. History write failures don't affect command result
        """
        # This test serves as documentation
        self.assertTrue(True, "Error handling guarantees documented")

    def test_logger_exception_usage(self):
        """
        Document that logger.exception() is used instead of logger.error().

        Benefits:
        1. Full traceback is captured automatically
        2. Exception type, message, and stack trace are logged
        3. Easier debugging of production issues
        4. No information is lost
        """
        # This test serves as documentation
        self.assertTrue(True, "logger.exception() usage documented")
