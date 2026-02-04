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
"""

from typing import Any

from reNgine.utilities.logger.base import BaseLogger


class ModuleLogger(BaseLogger):
    """
    Logger for application modules with standard logging interface.

    Drop-in replacement for get_task_logger(__name__) when not running in Celery.
    Uses the underlying logging.Logger so Django LOGGING config (reNgine.settings)
    applies. Pass the module's __name__ as the logger name so the "reNgine" or
    root logger config is used; see module docstring for usage notes.
    """

    def __init__(self, logger_name: str) -> None:
        super().__init__(logger_name=logger_name)

    def _get_prefix_color(self, prefix: str) -> str:
        return self.COLOR_BLUE

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
