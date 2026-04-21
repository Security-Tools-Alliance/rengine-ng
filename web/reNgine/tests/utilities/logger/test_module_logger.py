"""
Tests for module_logger (format_exception_for_log, get_module_logger, ModuleLogger).
"""

from reNgine.utilities.logger import (
    ModuleLogger,
    format_exception_for_log,
    get_module_logger,
)
from utils.test_base import BaseTestCase


class TestFormatExceptionForLog(BaseTestCase):
    """Test cases for format_exception_for_log."""

    def test_exception_with_message(self) -> None:
        """Exception with non-empty message returns type and message."""
        exc = ValueError("invalid host")
        result = format_exception_for_log(exc)
        self.assertEqual(result, "ValueError: invalid host")

    def test_exception_without_message(self) -> None:
        """Exception with no message returns type and (no message)."""
        exc = ValueError()
        result = format_exception_for_log(exc)
        self.assertEqual(result, "ValueError: (no message)")

    def test_exception_with_empty_string_message(self) -> None:
        """Exception with empty string message returns type and (no message)."""
        exc = ValueError("")
        result = format_exception_for_log(exc)
        self.assertEqual(result, "ValueError: (no message)")

    def test_exception_with_whitespace_only_message(self) -> None:
        """Exception with whitespace-only message returns type and (no message)."""
        exc = ValueError("   ")
        result = format_exception_for_log(exc)
        self.assertEqual(result, "ValueError: (no message)")

    def test_result_is_non_empty(self) -> None:
        """Result is never empty for common exception types."""
        for exc in [ValueError(), TypeError(""), RuntimeError("err")]:
            result = format_exception_for_log(exc)
            self.assertTrue(len(result) > 0, "format_exception_for_log must never return empty string")
            self.assertIn(":", result)


class TestGetModuleLogger(BaseTestCase):
    """Test cases for get_module_logger."""

    def test_returns_module_logger_instance(self) -> None:
        """get_module_logger returns a ModuleLogger instance."""
        logger = get_module_logger("test.module")
        self.assertIsInstance(logger, ModuleLogger)

    def test_uses_given_name(self) -> None:
        """Logger uses the given module name for its underlying logger."""
        logger = get_module_logger("reNgine.services.foo")
        self.assertEqual(logger._logger.name, "reNgine.services.foo")


class TestModuleLoggerLogLine(BaseTestCase):
    """Test cases for ModuleLogger.log_line."""

    def setUp(self) -> None:
        super().setUp()
        self.logger = get_module_logger("test.module_logger")
        self.log_capture: list = []

        def capture(level: str):
            def fn(*args: object, **kwargs: object) -> None:
                self.log_capture.append((level, args, kwargs))

            return fn

        self.logger._logger.debug = capture("debug")
        self.logger._logger.info = capture("info")
        self.logger._logger.warning = capture("warning")
        self.logger._logger.error = capture("error")

    def test_log_line_info_level(self) -> None:
        """log_line with level info calls _logger.info and includes prefix, action, message."""
        self.logger.log_line("[PREFIX]", "ACTION", "message", level="info")
        self.assertEqual(len(self.log_capture), 1)
        level, args, _ = self.log_capture[0]
        self.assertEqual(level, "info")
        self.assertIn("[PREFIX]", str(args[0]))
        self.assertIn("ACTION", str(args[0]))
        self.assertIn("message", str(args[0]))

    def test_log_line_debug_level(self) -> None:
        """log_line with level debug calls _logger.debug."""
        self.logger.log_line("[P]", "A", "msg", level="debug")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "debug")

    def test_log_line_warning_level(self) -> None:
        """log_line with level warning calls _logger.warning."""
        self.logger.log_line("[P]", "A", "msg", level="warning")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "warning")

    def test_log_line_error_level(self) -> None:
        """log_line with level error calls _logger.error."""
        self.logger.log_line("[P]", "A", "msg", level="error")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "error")

    def test_log_line_invalid_level_raises(self) -> None:
        """log_line with invalid level raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.logger.log_line("[P]", "A", "msg", level="invalid")
        self.assertIn("invalid", str(ctx.exception))


class TestModuleLoggerStandardMethods(BaseTestCase):
    """Test cases for ModuleLogger debug, info, warning, error, exception, critical."""

    def setUp(self) -> None:
        super().setUp()
        self.logger = get_module_logger("test.module_logger")
        self.log_capture: list = []

        def capture(level: str):
            def fn(*args: object, **kwargs: object) -> None:
                self.log_capture.append((level, args, kwargs))

            return fn

        self.logger._logger.debug = capture("debug")
        self.logger._logger.info = capture("info")
        self.logger._logger.warning = capture("warning")
        self.logger._logger.error = capture("error")
        self.logger._logger.exception = capture("exception")
        self.logger._logger.critical = capture("critical")

    def test_debug_calls_logger_debug(self) -> None:
        self.logger.debug("dbg")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "debug")
        self.assertEqual(self.log_capture[0][1][0], "dbg")

    def test_info_calls_logger_info(self) -> None:
        self.logger.info("inf")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "info")
        self.assertEqual(self.log_capture[0][1][0], "inf")

    def test_warning_calls_logger_warning(self) -> None:
        self.logger.warning("warn")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "warning")

    def test_error_calls_logger_error(self) -> None:
        self.logger.error("err")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "error")

    def test_exception_calls_logger_exception(self) -> None:
        self.logger.exception("exc")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "exception")

    def test_critical_calls_logger_critical(self) -> None:
        self.logger.critical("crit")
        self.assertEqual(len(self.log_capture), 1)
        self.assertEqual(self.log_capture[0][0], "critical")
