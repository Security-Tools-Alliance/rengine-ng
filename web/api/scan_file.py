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
    - Project resolution: endpoint.scan_history.domain.project
    - Required: ScanHistory.domain (FK -> Domain), Domain.project (FK -> Project)

  Technology
    - stored_response_path (CharField): stored relative path
    - No direct FK to Project; linked via Subdomain M2M
    - Project resolution: Subdomain such that tech in subdomain.technologies,
      then subdomain.scan_history.domain.project or subdomain.target_domain.project

  Subdomain (used for Technology -> Project only)
    - technologies (M2M to Technology, related_name="technologies"): used as
      Subdomain.objects.filter(technologies=tech)
    - scan_history (FK -> ScanHistory, null=True)
    - target_domain (FK -> Domain, null=True)
    - Required: ScanHistory.domain, Domain.project
"""

import logging
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
from reNgine.core.path import is_safe_path
from reNgine.settings import RENGINE_RESULTS, SECATOR_REPORTS_PREFIX
from startScan.models import EndPoint, Subdomain, Technology


logger = logging.getLogger(__name__)

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
    """
    if not relative_path:
        return ScanFileURLs(relative=None, absolute=None)
    relative = reverse(SERVE_SCAN_FILE_URL_NAME, kwargs={"relative_path": relative_path})
    absolute = request.build_absolute_uri(relative) if request else None
    return ScanFileURLs(relative=relative, absolute=absolute)


def get_project_for_scan_file_path(relative_path: str):
    """
    Derive the project that owns a scan file path from the database.

    Looks up EndPoint (screenshot_path / stored_response_path) or Technology
    (stored_response_path) so access control does not rely on path naming
    conventions. Returns the Project instance or None.

    Traversal (see module docstring for full schema contract):

    1. EndPoint: match on EndPoint.screenshot_path or EndPoint.stored_response_path.
       Project = endpoint.scan_history.domain.project (requires scan_history FK and
       ScanHistory.domain FK, Domain.project FK).

    2. Technology: match on Technology.stored_response_path. Find a Subdomain that
       has this Technology via Subdomain.technologies (M2M). Project =
       subdomain.scan_history.domain.project or subdomain.target_domain.project.
       Requires Subdomain.scan_history, Subdomain.target_domain, and Domain.project.
    """
    # 1. EndPoint path: EndPoint.scan_history -> ScanHistory.domain -> Domain.project
    endpoint = (
        EndPoint.objects.filter(Q(screenshot_path=relative_path) | Q(stored_response_path=relative_path))
        .select_related("scan_history__domain__project")
        .first()
    )
    if endpoint and endpoint.scan_history and endpoint.scan_history.domain:
        return endpoint.scan_history.domain.project
    # 2. Technology path: Technology.stored_response_path -> Subdomain (via M2M
    #    Subdomain.technologies) -> Subdomain.scan_history.domain.project or
    #    Subdomain.target_domain.project
    tech = Technology.objects.filter(stored_response_path=relative_path).first()
    if not tech:
        return None
    if (
        sub := Subdomain.objects.filter(technologies=tech)
        .select_related(
            "scan_history__domain__project",
            "target_domain__project",
        )
        .first()
    ):
        if sub.scan_history and sub.scan_history.domain:
            return sub.scan_history.domain.project
        if sub.target_domain:
            return sub.target_domain.project
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
        if not relative_path or ".." in relative_path:
            return Response(SCAN_FILE_ERROR_INVALID_PATH, status=400)
        if relative_path.startswith("/"):
            return Response(SCAN_FILE_ERROR_INVALID_PATH, status=400)
        path_has_prefix = SECATOR_REPORTS_PREFIX and (
            relative_path.startswith(SECATOR_REPORTS_PREFIX)
            or relative_path.startswith(SECATOR_REPORTS_PREFIX.lstrip("/"))
        )
        if path_has_prefix and _secator_prefix_warning_count < _SECATOR_PREFIX_WARNING_LIMIT:
            _secator_prefix_warning_count += 1
            logger.warning(
                "ServeScanFile: stored path still starts with SECATOR_REPORTS_PREFIX (%r); "
                "check web/worker prefix sync or legacy data. path=%r (occurrence=%d/%d)",
                SECATOR_REPORTS_PREFIX,
                relative_path[:200],
                _secator_prefix_warning_count,
                _SECATOR_PREFIX_WARNING_LIMIT,
            )
            if _secator_prefix_warning_count == _SECATOR_PREFIX_WARNING_LIMIT:
                logger.warning(
                    "ServeScanFile: reached SECATOR_REPORTS_PREFIX warning limit (%d); "
                    "suppressing further identical warnings in this process.",
                    _SECATOR_PREFIX_WARNING_LIMIT,
                )
        base = Path(RENGINE_RESULTS).resolve()
        full_path = (base / relative_path).resolve()
        if not full_path.is_file():
            return Response(SCAN_FILE_ERROR_NOT_FOUND, status=404)
        if not is_safe_path(str(base), str(full_path)):
            return Response(SCAN_FILE_ERROR_FORBIDDEN, status=403)
        # Project resolution from DB (EndPoint/Technology); do not derive from path.
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
