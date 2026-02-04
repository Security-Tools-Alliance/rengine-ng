"""
Runtime diagnostic for Secator path configuration (SECATOR_REPORTS_PREFIX vs worker/web sync).
Used by the check_secator_prefix management command and can be reused for admin or monitoring.
"""

import os
from pathlib import Path

from django.conf import settings


def get_secator_prefix_diagnostic(sample_size: int = 20) -> dict:
    """
    Validate SECATOR_REPORTS_PREFIX and RENGINE_RESULTS configuration and detect
    stored paths that still contain the prefix (worker/web mis-sync or legacy data).

    Returns a dict with:
      - prefix_configured: current SECATOR_REPORTS_PREFIX
      - rengine_results: current RENGINE_RESULTS
      - rengine_results_exists: whether the directory exists
      - rengine_results_readable: whether the directory is readable
      - paths_still_with_prefix: sample of stored paths that still start with the prefix
      - count_paths_still_with_prefix: total count of such paths in DB
      - count_total_with_path: total count of endpoints/technologies with a path set
      - ok: True if no issues detected
    """
    prefix = getattr(
        settings, "SECATOR_REPORTS_PREFIX", "/home/secator/.secator/reports"
    )
    rengine_results = getattr(
        settings, "RENGINE_RESULTS", str(Path.home() / "scan_results")
    )
    base = Path(rengine_results).resolve()
    rengine_results_exists = base.exists()
    rengine_results_readable = (
        rengine_results_exists and base.is_dir() and os.access(base, os.R_OK)
    )

    from startScan.models import EndPoint, Technology

    prefix_stripped = prefix.lstrip("/") if prefix else ""
    paths_still_with_prefix: list[str] = []
    count_paths_still_with_prefix = 0

    def has_prefix(path: str | None) -> bool:
        if not path or not path.strip():
            return False
        if prefix and path.startswith(prefix):
            return True
        return bool(prefix_stripped and path.startswith(prefix_stripped))

    def collect_with_prefix(qs, path_attr: str) -> None:
        nonlocal count_paths_still_with_prefix
        for obj in qs.only(path_attr).iterator(chunk_size=500):
            val = getattr(obj, path_attr, None)
            if not val:
                continue
            if has_prefix(val):
                count_paths_still_with_prefix += 1
                if len(paths_still_with_prefix) < sample_size:
                    paths_still_with_prefix.append(
                        f"{val[:200]}…" if len(val) > 200 else val
                    )

    ep_screenshot = EndPoint.objects.filter(
        screenshot_path__isnull=False
    ).exclude(screenshot_path="")
    ep_stored = EndPoint.objects.filter(
        stored_response_path__isnull=False
    ).exclude(stored_response_path="")
    tech_stored = Technology.objects.filter(
        stored_response_path__isnull=False
    ).exclude(stored_response_path="")

    count_total_with_path = (
        ep_screenshot.count() + ep_stored.count() + tech_stored.count()
    )

    collect_with_prefix(ep_screenshot, "screenshot_path")
    collect_with_prefix(ep_stored, "stored_response_path")
    collect_with_prefix(tech_stored, "stored_response_path")

    ok = (
        rengine_results_readable
        and count_paths_still_with_prefix == 0
    )

    return {
        "prefix_configured": prefix or "(empty)",
        "rengine_results": rengine_results,
        "rengine_results_exists": rengine_results_exists,
        "rengine_results_readable": rengine_results_readable,
        "paths_still_with_prefix": paths_still_with_prefix,
        "count_paths_still_with_prefix": count_paths_still_with_prefix,
        "count_total_with_path": count_total_with_path,
        "ok": ok,
    }
