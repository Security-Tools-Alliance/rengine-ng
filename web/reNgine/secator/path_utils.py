"""
Path utilities for Secator scan results.
Strips the worker report root prefix so paths are stored relative to the reports root.

The prefix is defined in settings.SECATOR_REPORTS_PREFIX and must match the path prefix
used by Secator workers when they emit screenshot_path / stored_response_path. Keep this
in sync with workers (and optionally set SECATOR_REPORTS_PREFIX in env on both web and
workers) so stripping and file serving work correctly.
"""

from django.conf import settings

from reNgine.utilities.logger import get_module_logger


PREFIX_PATH_UTILS = "[SECATOR_PATH_UTILS]"
logger = get_module_logger(__name__)

# Cap per-process logs for unmatched prefix; only logged when path is under SECATOR_RESULTS.
_MAX_UNMATCHED_PREFIX_LOGS = 10
_unmatched_prefix_log_count = 0

# Cap per-process logs for path truncation (truncated path may not match a real file).
_MAX_TRUNCATION_WARNING_LOGS = 10
_truncation_warning_log_count = 0


def strip_secator_reports_prefix(path: str, max_length: int = 1000) -> str:
    """
    Strip settings.SECATOR_REPORTS_PREFIX from path so only the workspace-relative part is stored.
    Used when persisting screenshot_path and stored_response_path from Secator findings.

    Args:
        path: Full path from Secator (e.g. /home/secator/.secator/reports/workspace/...)
        max_length: Max length of the returned path (default 1000 for CharField)

    Returns:
        Path relative to reports root, or original path if prefix does not match. Truncated if needed.
    """
    global _unmatched_prefix_log_count, _truncation_warning_log_count
    if not path or not isinstance(path, str):
        return path
    prefix = getattr(settings, "SECATOR_REPORTS_PREFIX", "/home/secator/.secator/reports")
    if prefix and path.startswith(prefix):
        rest = path[len(prefix) :].lstrip("/")
        path = rest
    elif path.startswith("/"):
        # Only log when path looks like it is under SECATOR_RESULTS (configuration drift),
        # not for every arbitrary absolute path (e.g. /tmp, legacy mixed data).
        results_root = (getattr(settings, "SECATOR_RESULTS", "") or "").strip().rstrip("/")
        path_under_results = bool(results_root and (path == results_root or path.startswith(f"{results_root}/")))
        if path_under_results and _unmatched_prefix_log_count < _MAX_UNMATCHED_PREFIX_LOGS:
            _unmatched_prefix_log_count += 1
            logger.log_line(
                PREFIX_PATH_UTILS,
                "STRIP_PREFIX",
                "Secator path does not start with SECATOR_REPORTS_PREFIX (%s); worker and web prefix may be out of sync. path=%s (occurrence %s/%s)"
                % (prefix, path[:200], _unmatched_prefix_log_count, _MAX_UNMATCHED_PREFIX_LOGS),
                level="info",
            )
    if len(path) > max_length:
        if _truncation_warning_log_count < _MAX_TRUNCATION_WARNING_LOGS:
            _truncation_warning_log_count += 1
            snippet = path[max_length - 80 : max_length + 20] if len(path) > 100 else path
            logger.log_line(
                PREFIX_PATH_UTILS,
                "STRIP_PREFIX",
                "Secator path truncated (len=%s, max_length=%s); stored value may not match a real file. snippet=%s (occurrence %s/%s)"
                % (len(path), max_length, snippet, _truncation_warning_log_count, _MAX_TRUNCATION_WARNING_LOGS),
                level="warning",
            )
        return path[:max_length]
    return path
