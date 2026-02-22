"""
Secator API Logger - Centralized logging for Secator API endpoints.

Provides structured, colored logging for runner and finding operations.
This logger handles incoming data from Secator API hooks.
"""

import json
from typing import Any, Dict, Optional

from reNgine.utilities.logger.base import BaseLogger


class SecatorAPILogger(BaseLogger):
    """
    Centralized logger for Secator API endpoints.

    Provides structured, colored logging for runner and finding operations.
    This logger handles incoming data from Secator API hooks.
    """

    # Prefixes for different log types with colors
    PREFIX_RUNNER = "[SECATOR API RUNNER]"
    PREFIX_FINDING = "[SECATOR API FINDINGS]"
    PREFIX_SYNC = "[SECATOR API STATUS SYNC]"

    # Colors for prefixes
    PREFIX_RUNNER_COLOR = BaseLogger.COLOR_CYAN  # Cyan for runner operations
    PREFIX_FINDING_COLOR = BaseLogger.COLOR_MAGENTA  # Magenta for finding operations
    PREFIX_SYNC_COLOR = BaseLogger.COLOR_BLUE  # Blue for sync operations

    def __init__(self):
        """Initialize the logger."""
        super().__init__()

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

    def log_request_body_size(self, method: str, path: str, content_length: Optional[str]) -> None:
        """
        Log request body size from Content-Length header.

        Helps diagnose nginx buffering when body exceeds client_body_buffer_size.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            path: Request path
            content_length: Value of Content-Length header (bytes as string, or None if absent/chunked)
        """
        if content_length is None or content_length == "":
            self._logger.info(
                "%s %s %s | request body: unknown (Content-Length absent or chunked)",
                self.PREFIX_RUNNER,
                method,
                path,
            )
        else:
            try:
                size_bytes = int(content_length)
                size_human = (
                    f"{size_bytes / (1024 * 1024):.2f} MB"
                    if size_bytes >= 1024 * 1024
                    else (f"{size_bytes / 1024:.2f} KB" if size_bytes >= 1024 else f"{size_bytes} bytes")
                )
            except (ValueError, TypeError):
                size_human = str(content_length)
            self._logger.info(
                "%s %s %s | request body: %s bytes (%s)",
                self.PREFIX_RUNNER,
                method,
                path,
                content_length,
                size_human,
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
        target_id = context.get("target_id")
        domain_id = context.get("domain_id")

        # INFO level - single line summary
        details = {
            "type": finding_type,
            "scan_id": scan_history_id,
            "target_id": target_id,
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
            details |= additional_info

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
        target_id: Optional[int],
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
            target_id: ID of the target (reNgine-ng scan context)
            success: Whether the save was successful
            error_message: Optional error message if save failed
        """
        details = {
            "type": finding_type,
            "scan_id": scan_history_id,
            "target_id": target_id,
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
                f"scan_history_id={scan_history_id}, target_id={target_id}. "
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

    def log_data_structure(self, data: Dict[str, Any], prefix: str, data_type: str) -> None:
        """
        Log complete data structure in DEBUG mode.

        Args:
            data: Data dictionary to log
            prefix: Log prefix to use
            data_type: Type of data (runner, finding, etc.)
        """
        super().log_data_structure(data, prefix, data_type)

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
