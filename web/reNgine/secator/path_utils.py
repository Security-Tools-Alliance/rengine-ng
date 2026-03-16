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

# Marker used to strip absolute worker paths when SECATOR_REPORTS_PREFIX does not match.
_SECATOR_REPORTS_MARKER = ".secator/reports"

# Cap per-process logs for unmatched prefix; only logged when path is under SECATOR_RESULTS.
_MAX_UNMATCHED_PREFIX_LOGS = 10
_unmatched_prefix_log_count = 0

# Cap per-process logs for path truncation (truncated path may not match a real file).
_MAX_TRUNCATION_WARNING_LOGS = 10
_truncation_warning_log_count = 0


def to_relative_scan_path(path: str) -> str | None:
    """
    Convert a stored path (absolute or relative) to the canonical form relative to
    RENGINE_RESULTS for URL building and file serving.

    Tries in order: SECATOR_REPORTS_PREFIX, RENGINE_RESULTS, then any path containing
    ".secator/reports" (e.g. /home/<user>/.secator/reports/...) so worker paths are
    normalized even when web and worker use different home directories.

    Returns:
        Path relative to reports root (no leading slash), or None if empty/invalid.
    """
    if not path or not isinstance(path, str):
        return None
    raw = path.strip().replace("\\", "/")
    if not raw:
        return None
    if not raw.startswith("/"):
        return raw
    rest = raw
    prefix = getattr(settings, "SECATOR_REPORTS_PREFIX", "") or ""
    if prefix:
        prefix_norm = prefix.rstrip("/")
        if rest.startswith(f"{prefix_norm}/") or rest == prefix_norm:
            rest = rest[len(prefix_norm) :].lstrip("/")
            return rest or None
        if rest.startswith(prefix_norm):
            rest = rest[len(prefix_norm) :].lstrip("/")
            return rest or None
    if rengine_results := getattr(settings, "RENGINE_RESULTS", "") or "":
        base_norm = rengine_results.rstrip("/")
        if rest.startswith(f"{base_norm}/") or rest == base_norm:
            rest = rest[len(base_norm) :].lstrip("/")
            return rest or None
        if rest.startswith(base_norm):
            rest = rest[len(base_norm) :].lstrip("/")
            return rest or None
    if _SECATOR_REPORTS_MARKER in rest:
        idx = rest.index(_SECATOR_REPORTS_MARKER)
        rest = rest[idx + len(_SECATOR_REPORTS_MARKER) :].lstrip("/")
        return rest or None
    return None


def strip_secator_reports_prefix(path: str, max_length: int = 1000) -> str:
    """
    Strip report root prefix from path so only the workspace-relative part is stored.
    Uses to_relative_scan_path so that paths like /home/<user>/.secator/reports/...
    are normalized even when SECATOR_REPORTS_PREFIX does not match the worker's path.

    Used when persisting screenshot_path and stored_response_path from Secator findings.

    Args:
        path: Full path from Secator (e.g. /home/secator/.secator/reports/workspace/...)
        max_length: Max length of the returned path (default 1000 for CharField)

    Returns:
        Path relative to reports root, or original path if no known prefix matches. Truncated if needed.
    """
    global _unmatched_prefix_log_count, _truncation_warning_log_count
    if not path or not isinstance(path, str):
        return path
    relative = to_relative_scan_path(path)
    if relative is not None:
        path = relative
    elif path.startswith("/"):
        prefix = getattr(settings, "SECATOR_REPORTS_PREFIX", "") or ""
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
