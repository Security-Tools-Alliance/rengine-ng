"""
Centralized reNgine-ng update check: read current version, fetch latest from GitHub, compare.
Used by the API view and the rengine_update_check management command.
"""

from __future__ import annotations

import re
from typing import Any

from packaging import version as pkg_version
import requests


GITHUB_RELEASES_URL = "https://api.github.com/repos/Security-Tools-Alliance/rengine-ng/releases"


def _normalize_version_string(raw: str) -> str:
    """Strip leading 'v' and quotes for comparison."""
    s = (raw[1:] if raw.startswith("v") else raw).replace("'", "").strip()
    return s


def _extract_version_from_string(s: str) -> str | None:
    """
    Extract a clean version string from a tag or arbitrary string.

    Expected formats (after trimming) include: v1, v1.2, v1.2.3, 1.2.3.
    Optional suffixes like '-beta', '-rc1', or '+meta' are stripped before
    validating the base version. The returned value is suitable for
    packaging.version.Version.
    """
    if not s:
        return None
    trimmed = s.strip()
    if trimmed.startswith("v"):
        trimmed = trimmed[1:].strip()
    base = re.split(r"[-+]", trimmed, maxsplit=1)[0].strip()
    if re.fullmatch(r"\d+(?:\.\d+){0,2}", base):
        return base
    return None


def _extract_version_from_release(release: dict[str, Any]) -> str | None:
    """Extract semantic version from GitHub release; prefer tag_name (canonical) over name."""
    tag_name = release.get("tag_name") or ""
    version = _extract_version_from_string(tag_name)
    if version:
        return version
    name = release.get("name") or ""
    return _extract_version_from_string(name)


def get_update_info() -> dict[str, Any]:
    """
    Fetch latest release from GitHub and compare with current version.

    Returns a dict with:
      - status: bool (True if check succeeded)
      - current_version: str
      - latest_version: str | None
      - update_available: bool (only when status is True)
      - changelog: str | None (only when update_available is True)
      - description: "RateLimited" when GitHub rate limit hit (status False)
      - message: optional error message
    """
    from django.conf import settings

    current = _normalize_version_string(settings.RENGINE_CURRENT_VERSION)
    result: dict[str, Any] = {
        "status": True,
        "current_version": current,
        "latest_version": None,
        "update_available": False,
    }

    try:
        response = requests.get(GITHUB_RELEASES_URL, timeout=10)
        status_code = response.status_code
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        result["status"] = False
        result["message"] = str(e)
        result["description"] = "Network or request error"
        result["error_type"] = "upstream_unavailable"
        return result

    # Handle non-200 GitHub-style error payloads; distinguish rate limit from other errors
    if isinstance(data, dict) and "message" in data and status_code != 200:
        message = data.get("message", "")
        rate_limit_indicators = (
            "API rate limit exceeded",
            "You have exceeded a secondary rate limit",
            "You have triggered an abuse detection mechanism",
            "rate limit",
        )
        lower_message = message.lower()
        is_rate_limited = any(ind.lower() in lower_message for ind in rate_limit_indicators)
        if not is_rate_limited:
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining is not None:
                try:
                    if int(remaining) <= 0:
                        is_rate_limited = True
                except ValueError:
                    pass
        result["status"] = False
        result["message"] = message or "GitHub API error"
        if is_rate_limited:
            result["description"] = "RateLimited"
            result["error_type"] = "ratelimited"
        else:
            result["description"] = "UpstreamError"
            result["error_type"] = "upstream_unavailable"
        return result

    if not isinstance(data, list) or len(data) == 0:
        result["status"] = False
        result["message"] = "No releases found"
        result["description"] = "No releases"
        result["error_type"] = "no_releases"
        return result

    latest_release = data[0]
    latest_version = _extract_version_from_release(latest_release)
    if not latest_version:
        result["status"] = False
        result["message"] = "Could not parse latest version from release tag/name"
        result["description"] = "Version parse error"
        result["error_type"] = "parse_error"
        return result

    result["latest_version"] = latest_version
    try:
        result["update_available"] = pkg_version.parse(current) < pkg_version.parse(latest_version)
    except (pkg_version.InvalidVersion, TypeError) as e:
        result["status"] = False
        result["message"] = "Invalid or uncomparable version (current or latest): %s" % (e,)
        result["description"] = "Invalid version"
        result["error_type"] = "invalid_version"
        return result

    if result["update_available"]:
        result["changelog"] = latest_release.get("body") or ""

    return result
