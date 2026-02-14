"""
Base Logger - Generic base class for all custom loggers.

This class provides common functionality for structured, colored logging.
It is reusable across the entire application, not just for Secator.
"""

from abc import ABC, abstractmethod
import json
import logging
import os
import sys
from typing import Any, Dict, Optional


class BaseLogger(ABC):
    """
    Generic base logger class for structured, colored logging.

    This class provides common functionality that can be reused by any
    specialized logger in the application. It handles color detection,
    formatting, and basic logging methods.
    """

    # ANSI color codes
    COLOR_RESET = "\033[0m"
    COLOR_GREEN = "\033[32m"  # Success
    COLOR_YELLOW = "\033[33m"  # Warning/Ignored
    COLOR_RED = "\033[31m"  # Error
    COLOR_CYAN = "\033[36m"  # Action in progress
    COLOR_BLUE = "\033[34m"  # Information (INFO level)
    COLOR_MAGENTA = "\033[35m"  # Data received / DEBUG level
    COLOR_VIOLET = "\033[95m"  # DEBUG level (bright magenta/violet)
    COLOR_BRIGHT_BLUE = "\033[94m"  # INFO level (bright blue)

    def __init__(self, logger_name: Optional[str] = None):
        """
        Initialize the base logger.

        Args:
            logger_name: Optional name for the logger. If not provided, uses __name__
        """
        self._logger = logging.getLogger(logger_name or self._get_logger_name())
        self._use_colors = self._detect_color_support()

    def _get_logger_name(self) -> str:
        """
        Get the logger name. Uses the module name of the class instance.

        Returns:
            str: Logger name (module name of the class)
        """
        return self.__class__.__module__

    @abstractmethod
    def _get_prefix_color(self, prefix: str) -> str:
        """
        Get color for a prefix. Must be implemented by subclasses.

        Args:
            prefix: Log prefix

        Returns:
            str: Color code for the prefix
        """
        pass

    def _detect_color_support(self) -> bool:
        """
        Detect if colors are supported by checking logger handlers and environment.

        Returns:
            bool: True if colors should be used
        """
        # Check FORCE_COLOR environment variable first (common in CI/CD)
        if os.environ.get("FORCE_COLOR") in ("1", "true", "yes"):
            return True

        # Check if NO_COLOR is set (standard environment variable to disable colors)
        if os.environ.get("NO_COLOR"):
            return False

        # Check if we're in a terminal (stdout or stderr)
        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
            return True
        if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
            return True

        # Check logger handlers for StreamHandler with terminal streams
        # Also check parent logger handlers
        loggers_to_check = [self._logger]
        current = self._logger
        while current.parent:
            loggers_to_check.append(current.parent)
            current = current.parent

        for logger_to_check in loggers_to_check:
            for handler in logger_to_check.handlers:
                if isinstance(handler, logging.StreamHandler):
                    stream = handler.stream
                    if hasattr(stream, "isatty") and stream.isatty():
                        return True

        # Check environment variable (for Docker/CI environments)
        if os.environ.get("TERM") and os.environ.get("TERM") != "dumb":
            return True

        # Default: always use colors (ANSI codes are harmless if not supported)
        # This ensures colors work in most environments including Docker
        # The terminal will simply ignore the codes if it doesn't support them
        return True

    def _colorize(self, text: str, color: str) -> str:
        """
        Add color to text if colors are enabled.

        Args:
            text: Text to colorize
            color: ANSI color code

        Returns:
            str: Colorized text with ANSI codes
        """
        # Always use colors - ANSI codes are harmless if terminal doesn't support them
        # This ensures colors work in most environments (Docker, CI, etc.)
        return f"{color}{text}{self.COLOR_RESET}" if self._use_colors else text

    def _format_debug_message(self, prefix: str, action: str, message: str) -> str:
        """
        Format a DEBUG level message with colors.

        Args:
            prefix: Log prefix
            action: Action being performed
            message: Message to log

        Returns:
            str: Formatted message with colors
        """
        return self._format_line(prefix, action, message, self.COLOR_VIOLET)

    def _format_info_message(self, prefix: str, action: str, message: str) -> str:
        """
        Format an INFO level message with colors.

        Args:
            prefix: Log prefix
            action: Action being performed
            message: Message to log

        Returns:
            str: Formatted message with colors
        """
        return self._format_line(prefix, action, message, self.COLOR_BRIGHT_BLUE)

    def _format_line(self, prefix: str, action: str, message: str, action_color: str) -> str:
        """
        Format a single line with prefix, action and message (for use by ModuleLogger.log_line).

        Args:
            prefix: Log prefix (e.g. section name)
            action: Action label
            message: Message text
            action_color: ANSI color for the action

        Returns:
            str: Formatted line with colors
        """
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize(action, action_color)
        return f"{prefix_colored} {action_colored} | {message}"

    def _format_info_line(
        self,
        prefix: str,
        action: str,
        details: Dict[str, Any],
        result: str,
        result_color: str = COLOR_GREEN,
    ) -> str:
        """
        Format a single-line INFO log message with colors.

        Args:
            prefix: Log prefix
            action: Action being performed (CREATE, UPDATE, etc.)
            details: Dictionary of key-value pairs to include
            result: Result message (SUCCESS, SAVED, IGNORED, etc.)
            result_color: Color for the result

        Returns:
            str: Formatted log message with colors
        """
        detail_parts = [f"{key}={value}" for key, value in details.items() if value is not None]

        detail_str = " ".join(detail_parts) if detail_parts else ""
        result_str = self._colorize(result, result_color)
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        # All INFO level actions (CREATE, UPDATE, etc.) are blue
        action_colored = self._colorize(action, self.COLOR_BRIGHT_BLUE)

        return (
            f"{prefix_colored} {action_colored} | {detail_str} → {result_str}"
            if detail_str
            else f"{prefix_colored} {action_colored} | → {result_str}"
        )

    def log_error(self, error: Exception, context: Dict[str, Any], exc_info: bool = True) -> None:
        """
        Log an error with context.

        Args:
            error: Exception that occurred
            context: Context information (action, prefix, id, etc.)
            exc_info: Whether to include exception info
        """
        prefix = context.get("prefix", "[ERROR]")
        action = context.get("action", "ERROR")
        error_msg = str(error)

        details = {k: v for k, v in context.items() if k not in ["prefix", "action", "error"]}
        error_line = self._format_info_line(prefix, action, details, f"ERROR: {error_msg}", self.COLOR_RED)
        self._logger.error(error_line, exc_info=exc_info)

    def log_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a warning message.

        Args:
            message: Warning message
            context: Optional context information (prefix, action, etc.)
        """
        prefix = context.get("prefix", "[WARNING]") if context else "[WARNING]"
        action = context.get("action", "WARNING") if context else "WARNING"

        details = {k: v for k, v in (context or {}).items() if k not in ["prefix", "action"]}
        warning_line = self._format_info_line(prefix, action, details, message, self.COLOR_YELLOW)
        self._logger.warning(warning_line)

    def log_debug(self, prefix: str, action: str, message: str) -> None:
        """
        Log a DEBUG level message with colors.

        Args:
            prefix: Log prefix
            action: Action being performed
            message: Message to log
        """
        formatted_message = self._format_debug_message(prefix, action, message)
        self._logger.debug(formatted_message)

    def log_data_structure(self, data: Any, prefix: str, data_type: str) -> None:
        """
        Log complete data structure in DEBUG mode.

        Args:
            data: Data to log (any JSON-serializable type)
            prefix: Log prefix to use
            data_type: Type of data (runner, finding, etc.)
        """
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize("STRUCTURE", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Full {data_type} structure:\n{json.dumps(data, indent=2, default=str)}"
        )
