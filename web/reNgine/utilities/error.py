"""
Safe user-facing error messages to avoid information exposure through exceptions.
Logs the full exception server-side and returns a generic or sanitized message for the client.

No Django or stdlib helper exists for this; Django provides HTML escaping (templates)
and ValidationError, but not heuristic detection of path/traceback leakage in messages.
This module uses a narrow heuristic: reject multi-line content, traceback markers, and
Python traceback-style file paths, while allowing validation messages that mention
URLs or paths (e.g. "invalid URL /foo").
"""

import re

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError

from reNgine.definitions import GENERIC_USER_ERROR_MESSAGE


class UserSafeError(RuntimeError):
    """
    Exception whose message is intended for the user and safe to display.
    Use this when raising from business logic with a curated, non-sensitive message.
    get_safe_user_message returns str(exc) for this type (after safety check); other
    RuntimeErrors are not passed through to avoid leaking internal messages.
    """


_SAFE_USER_MESSAGE_MAX_LEN = 256

# Substrings that indicate a Python traceback or stack trace (multi-line content).
_TRACEBACK_MARKERS = (
    "Traceback (most recent",
    "Traceback ",
    '  File "',
    '", line ',
    " in <",
)

# Regex: absolute system path (e.g. /etc/secret, /home/deploy/app). Used to reject
# internal path leakage while allowing "invalid URL /foo" or "path must be under /opt".
_RE_ABSOLUTE_SYSTEM_PATH = re.compile(r"(^|\s)/(etc|home|root|usr|var|opt|tmp)/\S+")


def _looks_safe_for_user(msg: str) -> bool:
    """
    Return False if message likely contains paths, stack traces, or other sensitive content.
    Allows slashes so validation messages like "invalid URL /foo" are not suppressed.
    Rejects multi-line content, traceback markers, Python traceback-style file paths,
    and messages containing absolute system paths (e.g. /etc/secret, /home/deploy/...).
    """
    if not msg or len(msg) > _SAFE_USER_MESSAGE_MAX_LEN:
        return False
    if "\n" in msg or "\r" in msg:
        return False
    if any(marker in msg for marker in _TRACEBACK_MARKERS):
        return False
    if re.search(r'File\s+["\'][^"\']*\.py["\']\s*,\s*line', msg):
        return False
    if _RE_ABSOLUTE_SYSTEM_PATH.search(msg):
        return False
    return True


def get_safe_user_message(exc: BaseException, logger=None, context=None):
    """
    Log the exception server-side (if logger provided) and return a safe message for the client.

    When logger is None, no logging is performed; the caller is responsible for logging
    (e.g. SecatorAPIBase calls self.logger.log_error before calling this with logger=None).

    Returns a generic message for unexpected errors, or a sanitized message for known
    validation-style errors. Never returns stack traces, paths, or internal details.
    For validation-like messages, returns str(exc) only when it looks safe (bounded length,
    no newlines, no traceback markers or traceback-style file paths); otherwise the generic.
    """
    if logger is not None:
        if hasattr(logger, "log_error") and context is not None:
            logger.log_error(exc, context, exc_info=True)
        elif context is not None:
            logger.error(
                "Exception in request: %s",
                exc,
                exc_info=True,
                extra=context,
            )
        else:
            logger.exception("Exception: %s", exc)

    if isinstance(exc, ObjectDoesNotExist):
        return "Required object not found."
    if isinstance(exc, IntegrityError):
        return "Database integrity error."
    if isinstance(exc, ValidationError):
        msg = str(exc)
        return msg if _looks_safe_for_user(msg) else GENERIC_USER_ERROR_MESSAGE
    if isinstance(exc, UserSafeError):
        msg = str(exc)
        return msg if _looks_safe_for_user(msg) else GENERIC_USER_ERROR_MESSAGE
    error_str = str(exc).lower()
    if "validation" in error_str or "invalid" in error_str or "required" in error_str:
        msg = str(exc)
        return msg if _looks_safe_for_user(msg) else GENERIC_USER_ERROR_MESSAGE
    return GENERIC_USER_ERROR_MESSAGE
