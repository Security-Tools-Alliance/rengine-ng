"""
Runner Logger - Logging for Secator runner operations.

Provides structured, colored logging for outgoing data sent to Secator runners.
This logger handles data sent from reNgine to Secator.
"""

import json
from typing import Any, Dict, List, Optional

from reNgine.utilities.logger.base import BaseLogger


class RunnerLogger(BaseLogger):
    """
    Logger for Secator runner operations.

    Provides structured, colored logging for outgoing data sent to Secator runners.
    This logger handles data sent from reNgine to Secator.
    """

    # Prefix for runner operations
    PREFIX = "[SECATOR RUNNER OUT]"

    # Color for prefix
    PREFIX_COLOR = BaseLogger.COLOR_CYAN  # Cyan for runner operations

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
        return self.PREFIX_COLOR if prefix == self.PREFIX else self.COLOR_RESET

    def log_runner_creation(
        self,
        runner_type: str,
        runner_name: str,
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        config: Optional[Dict[str, Any]] = None,
        run_opts: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        hooks: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log runner creation with full details.

        Args:
            runner_type: Type of runner (Workflow, Scan, Task)
            runner_name: Name of the runner
            targets: List of targets
            scan_history_id: ID of scan history
            domain_id: ID of domain
            config: Optional template configuration
            run_opts: Optional run options
            context: Optional context dictionary
            hooks: Optional hooks dictionary
        """
        # INFO level - single line summary
        details = {
            "type": runner_type,
            "name": runner_name,
            "targets_count": len(targets),
            "scan_id": scan_history_id,
            "domain_id": domain_id,
        }

        info_msg = self._format_info_line(
            self.PREFIX,
            "CREATE",
            details,
            "CREATED",
            self.COLOR_CYAN,
        )
        self._logger.info(info_msg)

        # DEBUG level - full details
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("CREATE", self.COLOR_VIOLET)  # DEBUG level color

        self._logger.debug(f"{prefix_colored} {action_colored} | Runner type: {runner_type}")
        self._logger.debug(f"{prefix_colored} {action_colored} | Runner name: {runner_name}")
        self._logger.debug(f"{prefix_colored} {action_colored} | Targets ({len(targets)}): {targets}")

        if config:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Config: {json.dumps(config, indent=2, default=str)}"
            )

        if run_opts:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Run options: {json.dumps(run_opts, indent=2, default=str)}"
            )

        if context:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Context: {json.dumps(context, indent=2, default=str)}"
            )

        if hooks:
            hook_keys = list(hooks.keys()) if isinstance(hooks, dict) else []
            self._logger.debug(f"{prefix_colored} {action_colored} | Hooks available: {hook_keys}")
            if hook_keys:
                hooks_dict = {str(k): str(type(v).__name__) for k, v in hooks.items()}
                self._logger.debug(f"{prefix_colored} {action_colored} | Hooks: {json.dumps(hooks_dict, indent=2)}")

    def log_config_preparation(
        self,
        base_config: Dict[str, Any],
        merged_config: Dict[str, Any],
        profiles: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Log Secator configuration preparation.

        Args:
            base_config: Base configuration before merge
            merged_config: Final merged configuration
            profiles: Optional profiles dictionary
        """
        # INFO level - single line summary
        details = {
            "sync": merged_config.get("sync", "NOT SET"),
            "proxy": merged_config.get("proxy"),
            "delay": merged_config.get("delay", 0),
            "profiles": merged_config.get("profiles", []),
        }

        if profiles:
            if isinstance(profiles, list):
                details["profiles"] = ", ".join(profiles) if profiles else "none"
            else:
                # Legacy dict format (should not happen but handle gracefully)
                profile_list = []
                profile_list.extend(
                    f"{key}={profiles[key]}"
                    for key in ["speed", "evasion", "general", "network"]
                    if key in profiles and profiles[key]
                )
                if profile_list:
                    details["profiles"] = ", ".join(profile_list)

        info_msg = self._format_info_line(
            self.PREFIX,
            "PREPARE",
            details,
            "PREPARED",
            self.COLOR_GREEN,
        )
        self._logger.info(info_msg)

        # DEBUG level - full configuration details
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("PREPARE", self.COLOR_VIOLET)  # DEBUG level color

        self._logger.debug(
            f"{prefix_colored} {action_colored} | Base config: {json.dumps(base_config, indent=2, default=str)}"
        )
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Merged config: {json.dumps(merged_config, indent=2, default=str)}"
        )

        if profiles:
            self._logger.debug(
                f"{prefix_colored} {action_colored} | Profiles: {json.dumps(profiles, indent=2, default=str)}"
            )

    def log_targets(self, targets: List[str], runner_type: str) -> None:
        """
        Log targets being sent to runner.

        Args:
            targets: List of targets
            runner_type: Type of runner
        """
        # INFO level - summary
        details = {
            "type": runner_type,
            "count": len(targets),
        }

        info_msg = self._format_info_line(
            self.PREFIX,
            "TARGETS",
            details,
            f"{len(targets)} target(s)",
            self.COLOR_CYAN,
        )
        self._logger.info(info_msg)

        # DEBUG level - full target list
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("TARGETS", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(f"{prefix_colored} {action_colored} | Target list: {targets}")

    def log_run_opts(self, run_opts: Dict[str, Any]) -> None:
        """
        Log run options being sent to runner.

        Args:
            run_opts: Run options dictionary
        """
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("OPTS", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(
            f"{prefix_colored} {action_colored} | Run options: {json.dumps(run_opts, indent=2, default=str)}"
        )

    def log_context(self, context: Dict[str, Any]) -> None:
        """
        Log context being sent to runner.

        Args:
            context: Context dictionary
        """
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("CONTEXT", self.COLOR_VIOLET)  # DEBUG level color
        self._logger.debug(f"{prefix_colored} {action_colored} | Context: {json.dumps(context, indent=2, default=str)}")

    def log_hooks(self, hooks: Dict[str, Any]) -> None:
        """
        Log hooks being passed to runner.

        Args:
            hooks: Hooks dictionary
        """
        prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
        action_colored = self._colorize("HOOKS", self.COLOR_VIOLET)  # DEBUG level color

        if hooks:
            hook_keys = list(hooks.keys())
            self._logger.debug(f"{prefix_colored} {action_colored} | Hooks available: {hook_keys}")
            hooks_dict = {str(k): str(type(v).__name__) for k, v in hooks.items()}
            self._logger.debug(f"{prefix_colored} {action_colored} | Hooks: {json.dumps(hooks_dict, indent=2)}")
        else:
            self._logger.debug(f"{prefix_colored} {action_colored} | No hooks provided")

    def log_runner_execution_start(self, runner_type: str, runner_name: str) -> None:
        """
        Log start of runner execution.

        Args:
            runner_type: Type of runner
            runner_name: Name of the runner
        """
        details = {
            "type": runner_type,
            "name": runner_name,
        }

        info_msg = self._format_info_line(
            self.PREFIX,
            "EXECUTE",
            details,
            "STARTED",
            self.COLOR_CYAN,
        )
        self._logger.info(info_msg)

    def log_runner_execution_end(
        self,
        runner_type: str,
        runner_name: str,
        status: str,
        result: Optional[Any] = None,
    ) -> None:
        """
        Log end of runner execution.

        Args:
            runner_type: Type of runner
            runner_name: Name of the runner
            status: Execution status (success, error, etc.)
            result: Optional execution result
        """
        details = {
            "type": runner_type,
            "name": runner_name,
        }

        if status == "success":
            result_str = "COMPLETED"
            result_color = self.COLOR_GREEN
        else:
            result_str = f"FAILED ({status})"
            result_color = self.COLOR_RED

        info_msg = self._format_info_line(
            self.PREFIX,
            "EXECUTE",
            details,
            result_str,
            result_color,
        )
        self._logger.info(info_msg)

        # DEBUG level - result details if available
        if result is not None:
            prefix_colored = self._colorize(self.PREFIX, self.PREFIX_COLOR)
            action_colored = self._colorize("EXECUTE", self.COLOR_VIOLET)  # DEBUG level color
            if isinstance(result, (dict, list)):
                self._logger.debug(
                    f"{prefix_colored} {action_colored} | Result: {json.dumps(result, indent=2, default=str)}"
                )
            else:
                self._logger.debug(f"{prefix_colored} {action_colored} | Result: {result}")

    def log_runner_error(
        self,
        runner_type: str,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log runner execution error.

        Args:
            runner_type: Type of runner
            error: Exception that occurred
            context: Optional context information
        """
        details = {
            "type": runner_type,
        }
        if context:
            details |= {k: v for k, v in context.items() if k != "error"}

        error_msg = str(error)
        error_line = self._format_info_line(
            self.PREFIX,
            "ERROR",
            details,
            f"ERROR: {error_msg}",
            self.COLOR_RED,
        )
        self._logger.error(error_line, exc_info=True)


# Singleton instance
_runner_logger = None


def get_runner_logger() -> RunnerLogger:
    """
    Get the singleton instance of RunnerLogger.

    Returns:
        RunnerLogger: Singleton logger instance
    """
    global _runner_logger
    if _runner_logger is None:
        _runner_logger = RunnerLogger()
    return _runner_logger
