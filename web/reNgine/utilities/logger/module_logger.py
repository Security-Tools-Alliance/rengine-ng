"""
Module Logger - Drop-in logger for application modules (replaces get_task_logger).

Provides a BaseLogger-based logger with standard .info(), .debug(), .error(),
.warning() and .exception() methods for use outside Celery.

Usage and LOGGING configuration
-------------------------------
Always pass the module's __name__ so the logger name is the full module path
(e.g. "startScan.views", "reNgine.secator.tasks"). That way Django's LOGGING
in reNgine.settings applies as intended:

- Loggers under "reNgine" use the "reNgine" logger (console, level DEBUG/INFO).
- Other app loggers (e.g. "startScan.*") propagate to the root logger (console,
  level DEBUG/INFO).

Do not pass ad-hoc names (e.g. "mylogger" or "tasks"); that can bypass
hierarchy and lead to missing or duplicate output. Use get_module_logger(__name__)
once per module and reuse the returned logger instance.

Section prefixes (for grep filtering)
-------------------------------------
[API], [TARGET], [STARTSCAN], [SECATOR BACKGROUND SYNC], [SECATOR_PROFILES],
[SECATOR_FORM], [CRON], [SCHEDULED_SCANS], [SIGNALS], [SCANENGINE],
[WORKER_SSH], [WORKER_CONFIG], [WORKER_DEPLOY], [WORKER_TUNNEL],
[DASHBOARD], [RECON_NOTE], [STARTSCAN_APPS], [COMMON_VIEWS], [CONTEXT_PROCESSORS].
Secator API (runner/findings) uses SecatorAPILogger with its own prefix.
"""

from typing import Any

from reNgine.utilities.logger.base import BaseLogger


ALLOWED_LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})


class ModuleLogger(BaseLogger):
    """
    Logger for application modules with standard logging interface.

    Drop-in replacement for get_task_logger(__name__) when not running in Celery.
    Uses the underlying logging.Logger so Django LOGGING config (reNgine.settings)
    applies. Pass the module's __name__ as the logger name so the "reNgine" or
    root logger config is used; see module docstring for usage notes.

    Use log_line() for section-style output (prefix + action + message) with colors.
    When the logger is configured with the "default" formatter (%(message)s), only
    the formatted line is printed (no module name), so sections stay clearly visible.
    """

    def __init__(self, logger_name: str) -> None:
        super().__init__(logger_name=logger_name)

    def _get_prefix_color(self, prefix: str) -> str:
        return self.COLOR_BLUE

    def log_line(
        self,
        prefix: str,
        action: str,
        message: str,
        level: str = "info",
        exc_info: bool = False,
    ) -> None:
        """
        Log a section-style line: prefix + action + message with colors.

        Use when the logger handler uses formatter "default" (%(message)s) so
        only this line is printed and sections are clearly visible in logs.

        Args:
            prefix: Section prefix (e.g. "[SECATOR BACKGROUND SYNC]")
            action: Action label (e.g. "BACKGROUND_SYNC", "POOL")
            message: Message text
            level: "debug", "info", "warning", or "error"
            exc_info: If True, append exception traceback (honored for all levels).

        Raises:
            ValueError: If level is not one of the allowed values.
        """
        if level not in ALLOWED_LOG_LEVELS:
            raise ValueError("log_line level must be one of %s, got %r" % (sorted(ALLOWED_LOG_LEVELS), level))
        action_colors = {
            "debug": self.COLOR_VIOLET,
            "info": self.COLOR_BRIGHT_BLUE,
            "warning": self.COLOR_YELLOW,
            "error": self.COLOR_RED,
        }
        color = action_colors.get(level, self.COLOR_BRIGHT_BLUE)
        line = self._format_line(prefix, action, message, color)
        formatted = "%s" % (line)
        if level == "debug":
            self._logger.debug(formatted, exc_info=exc_info)
        elif level == "error":
            self._logger.error(formatted, exc_info=exc_info)
        elif level == "warning":
            self._logger.warning(formatted, exc_info=exc_info)
        else:
            self._logger.info(formatted, exc_info=exc_info)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(msg, *args, **kwargs)


def get_module_logger(name: str) -> ModuleLogger:
    """
    Return a ModuleLogger for the given module name.

    Use the module's __name__ so the logger name is the full module path and
    LOGGING in reNgine.settings applies (reNgine.* or root). Example::

        from reNgine.utilities.logger import get_module_logger

        logger = get_module_logger(__name__)

    Drop-in replacement for get_task_logger(__name__). Do not pass ad-hoc
    names; see module docstring for details.
    """
    return ModuleLogger(name)
