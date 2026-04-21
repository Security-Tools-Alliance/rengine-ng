"""
Scan file access: URL building and project-scoped file serving.

Centralizes security-sensitive logic so file access rules are not duplicated
between views, serializers, and tests. All scan file URLs (screenshots, stored
responses) are built and served through this module.

All path/URL building goes through get_scan_file_urls(); callers use
build_scan_file_url or build_absolute_scan_file_url for convenience, or
get_scan_file_urls when both relative and absolute are needed.

Access control (ServeScanFile) relies on get_project_for_scan_file_path(), which
resolves the project from DB using the following model relationships. Any schema
change to these fields or relations can break access control; update this module
and run api.tests.test_serve_scan_file.

Expected relationships (startScan.models / targetApp.models):

  EndPoint
    - screenshot_path, stored_response_path (CharField): stored relative path
    - scan_history (FK -> ScanHistory, null=True)
    - Project resolution: endpoint.scan_history.target.project
    - Required: ScanHistory.target (FK -> Target), Target.project (FK -> Project)

  Technology
    - stored_response_path (CharField): stored relative path
    - No direct FK to Project; linked via Subdomain M2M
    - Project resolution: Subdomain such that tech in subdomain.technologies,
      then subdomain.scan_history.target.project or
      subdomain.domain.scan_history.target.project

  Subdomain (used for Technology -> Project only)
    - scan_history (FK -> ScanHistory), domain (FK -> Domain).
    - Domain links to target via scan_history (Domain.scan_history.target).
"""

import mimetypes
from pathlib import Path
from typing import NamedTuple

from django.db.models import Q
from django.http import FileResponse, HttpRequest
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.utils import get_user_projects
from reNgine.core.path import is_safe_path, normalize_relative_path
from reNgine.settings import RENGINE_RESULTS, SECATOR_REPORTS_PREFIX
from reNgine.utilities.logger import get_module_logger
from startScan.models import EndPoint, Subdomain, Technology


PREFIX_SCAN_FILE = "[SCAN_FILE]"
logger = get_module_logger(__name__)

# Route name for scan file serving; single source for URL building
SERVE_SCAN_FILE_URL_NAME = "api:serve_scan_file"


class ScanFileURLs(NamedTuple):
    """Relative and optional absolute URL for a scan file (screenshot or stored response)."""

    relative: str | None
    absolute: str | None


def get_scan_file_urls(relative_path: str | None, request: HttpRequest | None = None) -> ScanFileURLs:
    """
    Build relative and (when request is provided) absolute URLs for a scan file.
    Single entry point for all scan file URL building; keeps route name and logic in one place.
    Normalizes stored paths (including absolute worker paths) to a relative form so the URL
    never exposes the filesystem root.
    """
    if not relative_path:
        return ScanFileURLs(relative=None, absolute=None)
    from reNgine.secator.path_utils import to_relative_scan_path

    path_for_url = to_relative_scan_path(relative_path)
    if not path_for_url:
        return ScanFileURLs(relative=None, absolute=None)
    relative = reverse(SERVE_SCAN_FILE_URL_NAME, kwargs={"relative_path": path_for_url})
    absolute = request.build_absolute_uri(relative) if request else None
    return ScanFileURLs(relative=relative, absolute=absolute)


def get_project_for_scan_file_path(relative_path: str):
    """
    Derive the project that owns a scan file path from the database.

    Looks up EndPoint (screenshot_path / stored_response_path) or Technology
    (stored_response_path) so access control does not rely on path naming
    conventions. Tries exact match first, then matches where the stored path
    normalizes to the given path (for legacy absolute paths in DB).

    Traversal (see module docstring for full schema contract):

    1. EndPoint: match on EndPoint.screenshot_path or EndPoint.stored_response_path.
       Project = endpoint.scan_history.target.project (requires scan_history FK and
       ScanHistory.target FK, Target.project FK).

    2. Technology: match on Technology.stored_response_path. Find a Subdomain that
       has this Technology via Subdomain.technologies (M2M). Project =
       subdomain.scan_history.target.project or
       subdomain.domain.scan_history.target.project when domain.scan_history_id.
    """
    # 1. Exact match: EndPoint path
    endpoint = (
        EndPoint.objects.filter(Q(screenshot_path=relative_path) | Q(stored_response_path=relative_path))
        .select_related("scan_history__target__project")
        .first()
    )
    if endpoint and endpoint.scan_history and endpoint.scan_history.target_id:
        return endpoint.scan_history.target.project
    # 2. Fallback for legacy absolute paths: find EndPoint whose stored path normalizes to relative_path
    if relative_path and not relative_path.startswith("/"):
        from reNgine.secator.path_utils import to_relative_scan_path

        candidates = EndPoint.objects.filter(
            Q(screenshot_path__endswith=relative_path) | Q(stored_response_path__endswith=relative_path)
        ).select_related("scan_history__target__project")
        for ep in candidates:
            if (
                (
                    (ep.screenshot_path and to_relative_scan_path(ep.screenshot_path) == relative_path)
                    or (ep.stored_response_path and to_relative_scan_path(ep.stored_response_path) == relative_path)
                )
                and ep.scan_history
                and ep.scan_history.target_id
            ):
                return ep.scan_history.target.project
    # 3. Exact match: Technology path
    tech = Technology.objects.filter(stored_response_path=relative_path).first()
    if tech:
        if (
            sub := Subdomain.objects.filter(technologies=tech)
            .select_related(
                "scan_history__target__project",
                "domain__scan_history__target__project",
            )
            .first()
        ):
            if sub.scan_history and sub.scan_history.target_id:
                return sub.scan_history.target.project
            if sub.domain and sub.domain.scan_history_id:
                return sub.domain.scan_history.target.project
    # 4. Fallback for legacy: Technology whose stored path normalizes to relative_path
    if relative_path and not relative_path.startswith("/"):
        from reNgine.secator.path_utils import to_relative_scan_path

        for tech in Technology.objects.filter(stored_response_path__endswith=relative_path):
            if to_relative_scan_path(tech.stored_response_path) == relative_path:
                if (
                    sub := Subdomain.objects.filter(technologies=tech)
                    .select_related(
                        "scan_history__target__project",
                        "domain__scan_history__target__project",
                    )
                    .first()
                ):
                    if sub.scan_history and sub.scan_history.target_id:
                        return sub.scan_history.target.project
                    if sub.domain and sub.domain.scan_history_id:
                        return sub.domain.scan_history.target.project
                break
    return None


def build_scan_file_url(relative_path: str | None) -> str | None:
    """Build a stable URL path for a scan file (screenshot or stored response).

    Returns a path relative to the origin (e.g. ``/api/scan-files/...``) so the
    frontend can rely on a single URL shape; this can be used directly in
    ``img src`` / ``a href`` attributes against the current origin.

    Callers that require a fully-qualified URL (including scheme/host) should
    use ``build_absolute_scan_file_url(request, relative_path)`` or
    ``get_scan_file_urls(relative_path, request).absolute``.
    """
    return get_scan_file_urls(relative_path).relative


def build_absolute_scan_file_url(request: HttpRequest | None, relative_path: str | None) -> str | None:
    """Build a fully-qualified URL for a scan file (screenshot or stored response)."""
    return get_scan_file_urls(relative_path, request).absolute


# JSON error payloads for ServeScanFile; single source for consistent wording.
SCAN_FILE_ERROR_INVALID_PATH = {"error": "Invalid path"}
SCAN_FILE_ERROR_NOT_FOUND = {"error": "Not found"}
SCAN_FILE_ERROR_FORBIDDEN = {"error": "Forbidden"}

# Cap per-process logs for paths that still start with SECATOR_REPORTS_PREFIX.
_SECATOR_PREFIX_WARNING_LIMIT = 100
_secator_prefix_warning_count = 0


class ServeScanFile(APIView):
    """
    Serve scan result files (screenshots, stored responses) with project-scoped access control.
    Path is relative to RENGINE_RESULTS. Project is derived via get_project_for_scan_file_path()
    from EndPoint/Technology records that reference this path, not from path parsing, to avoid
    cross-project access if naming drifts. The expected EndPoint/Technology/Subdomain relationships
    are documented in this module's docstring; schema changes there require updating this view and
    running api.tests.test_serve_scan_file.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, relative_path: str):
        global _secator_prefix_warning_count
        path_for_file = normalize_relative_path(relative_path)
        if path_for_file is None:
            from reNgine.secator.path_utils import to_relative_scan_path

            path_for_file = to_relative_scan_path(relative_path)
            if path_for_file is None:
                return Response(SCAN_FILE_ERROR_INVALID_PATH, status=400)
        path_for_file = normalize_relative_path(path_for_file)
        if path_for_file is None:
            return Response(SCAN_FILE_ERROR_INVALID_PATH, status=400)
        path_has_prefix = SECATOR_REPORTS_PREFIX and (
            relative_path.startswith(SECATOR_REPORTS_PREFIX)
            or relative_path.startswith(SECATOR_REPORTS_PREFIX.lstrip("/"))
        )
        if path_has_prefix and _secator_prefix_warning_count < _SECATOR_PREFIX_WARNING_LIMIT:
            _secator_prefix_warning_count += 1
            logger.log_line(
                PREFIX_SCAN_FILE,
                "SERVE",
                "ServeScanFile: stored path still starts with SECATOR_REPORTS_PREFIX (%s); "
                "check web/worker prefix sync or legacy data. path=%s (occurrence=%s/%s)"
                % (
                    repr(SECATOR_REPORTS_PREFIX),
                    repr(relative_path[:200]),
                    _secator_prefix_warning_count,
                    _SECATOR_PREFIX_WARNING_LIMIT,
                ),
                level="warning",
            )
            if _secator_prefix_warning_count == _SECATOR_PREFIX_WARNING_LIMIT:
                logger.log_line(
                    PREFIX_SCAN_FILE,
                    "SERVE",
                    "ServeScanFile: reached SECATOR_REPORTS_PREFIX warning limit (%s); "
                    "suppressing further identical warnings in this process." % (_SECATOR_PREFIX_WARNING_LIMIT,),
                    level="warning",
                )
        base = Path(RENGINE_RESULTS).resolve()
        full_path = (base / path_for_file).resolve()
        if not full_path.is_file():
            return Response(SCAN_FILE_ERROR_NOT_FOUND, status=404)
        if not is_safe_path(str(base), str(full_path)):
            return Response(SCAN_FILE_ERROR_FORBIDDEN, status=403)
        # Project resolution from DB (EndPoint/Technology); do not derive from path.
        project = get_project_for_scan_file_path(path_for_file)
        if not project:
            project = get_project_for_scan_file_path(relative_path)
        if not project or project not in get_user_projects(request.user):
            return Response(SCAN_FILE_ERROR_FORBIDDEN, status=403)
        content_type, _ = mimetypes.guess_type(str(full_path))
        content_type = content_type or "application/octet-stream"
        return FileResponse(
            open(full_path, "rb"),
            content_type=content_type,
            as_attachment=False,
        )
