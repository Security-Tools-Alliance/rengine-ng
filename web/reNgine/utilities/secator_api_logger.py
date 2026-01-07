"""
Secator API Logger - Centralized logging for Secator API endpoints.
Provides structured, colored logging for runner and finding operations.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class SecatorAPILogger:
    """
    Centralized logger for Secator API endpoints.
    Provides structured, colored logging for runner and finding operations.
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

    # Prefixes for different log types with colors
    PREFIX_RUNNER = "[SECATOR API RUNNER]"
    PREFIX_FINDING = "[SECATOR API FINDINGS]"
    PREFIX_SYNC = "[SECATOR API STATUS SYNC]"

    # Colors for prefixes
    PREFIX_RUNNER_COLOR = COLOR_CYAN  # Cyan for runner operations
    PREFIX_FINDING_COLOR = COLOR_MAGENTA  # Magenta for finding operations
    PREFIX_SYNC_COLOR = COLOR_BLUE  # Blue for sync operations

    def __init__(self):
        """Initialize the logger."""
        self._logger = logging.getLogger(__name__)
        self._use_colors = self._detect_color_support()

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

    def _get_prefix_color(self, prefix: str) -> str:
        """
        Get color for a prefix.

        Args:
            prefix: Log prefix

        Returns:
            str: Color code for the prefix
        """
        if prefix == self.PREFIX_RUNNER:
            return self.PREFIX_RUNNER_COLOR
        elif prefix == self.PREFIX_FINDING:
            return self.PREFIX_FINDING_COLOR
        elif prefix == self.PREFIX_SYNC:
            return self.PREFIX_SYNC_COLOR
        return self.COLOR_RESET

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
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize(action, self.COLOR_VIOLET)  # DEBUG level color
        return f"{prefix_colored} {action_colored} | {message}"

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
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        # All INFO level actions (CREATE, UPDATE, etc.) are blue
        action_colored = self._colorize(action, self.COLOR_BRIGHT_BLUE)
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
            prefix: Log prefix (RUNNER, FINDING, etc.)
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

    def log_runner_api_call(self, action: str, runner_data: Dict[str, Any], runner_id: Optional[str] = None) -> None:
        """
        Log runner API call with full details.

        Args:
            action: Action being performed (CREATE, UPDATE)
            runner_data: Runner data dictionary
            runner_id: Optional runner ID
        """
        runner_type = runner_data.get("config", {}).get("type", "unknown")
        runner_name = runner_data.get("config", {}).get("name") or runner_data.get("name", "unknown")
        scan_history_id = runner_data.get("context", {}).get("scan_history_id")
        domain_id = runner_data.get("context", {}).get("domain_id")

        # INFO level - single line summary
        details = {
            "type": runner_type,
            "name": runner_name,
            "scan_id": scan_history_id,
            "domain_id": domain_id,
        }
        if runner_id:
            details["id"] = runner_id

        info_msg = self._format_info_line(
            self.PREFIX_RUNNER,
            action,
            details,
            "RECEIVED",
            self.COLOR_CYAN,
        )
        self._logger.info(info_msg)

        # DEBUG level - full data structure with colors
        prefix_colored = self._colorize(self.PREFIX_RUNNER, self.PREFIX_RUNNER_COLOR)
        action_colored = self._colorize(action, self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Full runner data received: "
            f"{json.dumps(runner_data, indent=2, default=str)}"
        )
        self._logger.debug(f"{prefix_colored} {action_colored} | Runner data keys: {list(runner_data.keys())}")

        if "config" in runner_data:
            config_keys = list(runner_data.get("config", {}).keys())
            self._logger.debug(f"{prefix_colored} {action_colored} | Config keys: {config_keys}")
            if runner_data.get("config"):
                self._logger.debug(
                    f"{prefix_colored} {action_colored} | Config: {json.dumps(runner_data.get('config', {}), indent=2, default=str)}"
                )

        if "context" in runner_data:
            context = runner_data.get("context", {})
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Context: {json.dumps(context, indent=2, default=str)}"
            )

    def log_finding_api_call(self, action: str, finding_data: Dict[str, Any], finding_id: Optional[str] = None) -> None:
        """
        Log finding API call with full details.

        Args:
            action: Action being performed (CREATE, UPDATE)
            finding_data: Finding data dictionary
            finding_id: Optional finding ID
        """
        finding_type = finding_data.get("_type", "unknown")
        context = finding_data.get("_context", {})
        scan_history_id = context.get("scan_history_id")
        domain_id = context.get("domain_id")

        # INFO level - single line summary
        details = {
            "type": finding_type,
            "scan_id": scan_history_id,
            "domain_id": domain_id,
        }
        if finding_id:
            details["id"] = finding_id

        # Extract name or identifier for display
        name = finding_data.get("name") or finding_data.get("host") or finding_data.get("ip") or "unknown"
        if name != "unknown":
            details["name"] = name

        info_msg = self._format_info_line(
            self.PREFIX_FINDING,
            action,
            details,
            "RECEIVED",
            self.COLOR_CYAN,
        )
        self._logger.info(info_msg)

        # DEBUG level - full data structure with colors
        prefix_colored = self._colorize(self.PREFIX_FINDING, self.PREFIX_FINDING_COLOR)
        action_colored = self._colorize(action, self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Full finding data received: "
            f"{json.dumps(finding_data, indent=2, default=str)}"
        )
        self._logger.debug(f"{prefix_colored} {action_colored} | Finding data keys: {list(finding_data.keys())}")
        self._logger.debug(f"{prefix_colored} {action_colored} | Finding type: {finding_type}")

        if "_context" in finding_data:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Context: {json.dumps(finding_data.get('_context', {}), indent=2, default=str)}"
            )

        # Log all fields specific to the finding type
        for key, value in finding_data.items():
            if key not in ["_type", "_context", "_uuid"]:
                if isinstance(value, (dict, list)):
                    self._logger.debug(
                        f"{prefix_colored} {action_colored} | Finding field '{key}': "
                        f"{json.dumps(value, indent=2, default=str)}"
                    )
                else:
                    self._logger.debug(f"{prefix_colored} {action_colored} | Finding field '{key}': {value}")

    def log_runner_sync(
        self,
        action: str,
        runner_name: str,
        runner_type: str,
        status: str,
        scan_history_id: Optional[int],
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log runner synchronization with ScanHistory.

        Args:
            action: Action being performed (SYNC, UPDATED, BLOCKED, etc.)
            runner_name: Name of the runner
            runner_type: Type of the runner (workflow, scan, task)
            status: Status of the runner
            scan_history_id: ID of the scan history
            additional_info: Optional additional information to log
        """
        details = {
            "runner": runner_name,
            "type": runner_type,
            "status": status,
            "scan_id": scan_history_id,
        }
        if additional_info:
            details.update(additional_info)

        info_msg = self._format_info_line(
            self.PREFIX_SYNC,
            action,
            details,
            "SYNCED",
            self.COLOR_GREEN,
        )
        self._logger.info(info_msg)

    def log_finding_save(
        self,
        action: str,
        finding_type: str,
        saved_object: Optional[Any],
        scan_history_id: Optional[int],
        domain_id: Optional[int],
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Log finding save operation.

        Args:
            action: Action being performed (CREATE, UPDATE)
            finding_type: Type of finding
            saved_object: Saved object (or None if failed)
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            success: Whether the save was successful
            error_message: Optional error message if save failed
        """
        details = {
            "type": finding_type,
            "scan_id": scan_history_id,
            "domain_id": domain_id,
        }

        if success and saved_object:
            if hasattr(saved_object, "id"):
                details["id"] = str(saved_object.id)
            result = "SAVED"
            result_color = self.COLOR_GREEN
        elif not success:
            result = f"FAILED: {error_message or 'Unknown error'}"
            result_color = self.COLOR_RED
        else:
            result = "SKIPPED (validation error)"
            result_color = self.COLOR_YELLOW

        info_msg = self._format_info_line(
            self.PREFIX_FINDING,
            action,
            details,
            result,
            result_color,
        )
        self._logger.info(info_msg)

        # DEBUG level - additional details with colors
        prefix_colored = self._colorize(self.PREFIX_FINDING, self.PREFIX_FINDING_COLOR)
        action_colored = self._colorize(action, self.COLOR_VIOLET)  # DEBUG level color
        if saved_object:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Saved object type: {type(saved_object).__name__}, "
                f"id: {getattr(saved_object, 'id', 'N/A')}"
            )
        elif not success:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Save failed for finding type={finding_type}, "
                f"scan_history_id={scan_history_id}, domain_id={domain_id}. "
                f"Error: {error_message or 'Repository returned None'}"
            )

    def log_runner_field_extraction(self, field_name: str, field_value: Any, runner_id: str) -> None:
        """
        Log extraction of a field from runner data (e.g., celery_id, status).

        Args:
            field_name: Name of the field being extracted
            field_value: Value of the field
            runner_id: ID of the runner
        """
        prefix_colored = self._colorize(self.PREFIX_SYNC, self.PREFIX_SYNC_COLOR)
        action_colored = self._colorize("EXTRACT", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Extracted {field_name}={field_value} for runner {runner_id}"
        )

    def log_data_structure(self, data: Dict[str, Any], data_type: str) -> None:
        """
        Log complete data structure in DEBUG mode.

        Args:
            data: Data dictionary to log
            data_type: Type of data (runner, finding, etc.)
        """
        prefix = self.PREFIX_RUNNER if data_type == "runner" else self.PREFIX_FINDING
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize("STRUCTURE", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Full {data_type} structure:\n{json.dumps(data, indent=2, default=str)}"
        )

    def log_error(self, error: Exception, context: Dict[str, Any], exc_info: bool = True) -> None:
        """
        Log an error with context.

        Args:
            error: Exception that occurred
            context: Context information (action, id, etc.)
            exc_info: Whether to include exception info
        """
        prefix = context.get("prefix", self.PREFIX_RUNNER)
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
            context: Optional context information
        """
        prefix = context.get("prefix", self.PREFIX_RUNNER) if context else self.PREFIX_RUNNER
        action = context.get("action", "WARNING") if context else "WARNING"

        details = {k: v for k, v in (context or {}).items() if k not in ["prefix", "action"]}
        warning_line = self._format_info_line(prefix, action, details, message, self.COLOR_YELLOW)
        self._logger.warning(warning_line)

    def log_metadata_ignored(self, finding_type: str, finding_id: Optional[str] = None) -> None:
        """
        Log that a metadata type finding was ignored.

        Args:
            finding_type: Type of finding that was ignored
            finding_id: Optional finding ID
        """
        details = {"type": finding_type}
        if finding_id:
            details["id"] = finding_id

        info_msg = self._format_info_line(
            self.PREFIX_FINDING,
            "IGNORE",
            details,
            "IGNORED (metadata)",
            self.COLOR_YELLOW,
        )
        self._logger.info(info_msg)
        prefix_colored = self._colorize(self.PREFIX_FINDING, self.PREFIX_FINDING_COLOR)
        action_colored = self._colorize("IGNORE", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Ignoring metadata type: {finding_type} for finding_id={finding_id or 'N/A'}"
        )

    def log_unknown_type(self, entity_type: str, finding_type: str, entity_id: Optional[str] = None) -> None:
        """
        Log that an unknown type was encountered.

        Args:
            entity_type: Type of entity (runner, finding)
            finding_type: Unknown type encountered
            entity_id: Optional entity ID
        """
        prefix = self.PREFIX_RUNNER if entity_type == "runner" else self.PREFIX_FINDING
        details = {"type": finding_type}
        if entity_id:
            details["id"] = entity_id

        warning_line = self._format_info_line(
            prefix,
            "UNKNOWN",
            details,
            "UNKNOWN TYPE",
            self.COLOR_YELLOW,
        )
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


# Singleton instance
_secator_api_logger = None


def get_secator_api_logger() -> SecatorAPILogger:
    """
    Get the singleton instance of SecatorAPILogger.

    Returns:
        SecatorAPILogger: Singleton logger instance
    """
    global _secator_api_logger
    if _secator_api_logger is None:
        _secator_api_logger = SecatorAPILogger()
    return _secator_api_logger
