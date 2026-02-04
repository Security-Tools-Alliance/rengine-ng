"""
Safe user-facing error messages to avoid information exposure through exceptions.
Logs the full exception server-side and returns a generic or sanitized message for the client.
"""

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError

from reNgine.definitions import GENERIC_USER_ERROR_MESSAGE


# Max length and chars that suggest path/multi-line leakage; beyond this we return generic only.
_SAFE_USER_MESSAGE_MAX_LEN = 256
_UNSAFE_MESSAGE_CHARS = ("/", "\\", "\n", "\r")


def _looks_safe_for_user(msg: str) -> bool:
    """Return False if message might contain paths, stack traces, or other sensitive content."""
    if not msg or len(msg) > _SAFE_USER_MESSAGE_MAX_LEN:
        return False
    return not any(c in msg for c in _UNSAFE_MESSAGE_CHARS)


def get_safe_user_message(exc: BaseException, logger=None, context=None):
    """
    Log the exception server-side (if logger provided) and return a safe message for the client.

    When logger is None, no logging is performed; the caller is responsible for logging
    (e.g. SecatorAPIBase calls self.logger.log_error before calling this with logger=None).

    Returns a generic message for unexpected errors, or a sanitized message for known
    validation-style errors. Never returns stack traces, paths, or internal details.
    For validation-like messages, returns str(exc) only when it looks safe (no path
    separators, no newlines, bounded length); otherwise returns the generic message.
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
    error_str = str(exc).lower()
    if "validation" in error_str or "invalid" in error_str or "required" in error_str:
        msg = str(exc)
        return msg if _looks_safe_for_user(msg) else GENERIC_USER_ERROR_MESSAGE
    return GENERIC_USER_ERROR_MESSAGE
