from django.shortcuts import get_object_or_404, redirect
from django.urls import resolve, reverse
from django.utils.deprecation import MiddlewareMixin

from dashboard.constants import PROJECT_CONTEXT_QUERY_PARAM
from dashboard.models import Project
from dashboard.utils import get_user_projects
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)

X_PROJECT_SLUG_HEADER = "HTTP_X_PROJECT_SLUG"
HEADER_PROJECT_CONTEXT_ALLOWED_PATH_PREFIXES = (
    "/api/",
    "/profile/",
    "/scan/",
    "/target/",
    "/recon_note/",
)


class ProjectAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resolved = resolve(request.path_info)
        if "slug" in resolved.kwargs:
            slug = resolved.kwargs["slug"]
            project = Project.objects.filter(slug=slug).first()

            # Check if the user is authenticated
            if not request.user.is_authenticated:
                return redirect(reverse("permission_denied"))

            # If the project exists and the user has access
            if project and project in get_user_projects(request.user):
                return self.get_response(request)

            # If the project does not exist or the user does not have access
            if project:
                return redirect(reverse("page_not_found"))
            else:
                return redirect(reverse("permission_denied"))

        return self.get_response(request)


class SlugMiddleware(MiddlewareMixin):
    @staticmethod
    def _resolve_project_for_context(slug, allowed_project_ids):
        if not slug:
            return None, False
        project = Project.objects.filter(slug=slug).first()
        if not project:
            return None, False
        if project.id not in allowed_project_ids:
            return None, True
        return project, False

    def _assign_project_context(self, request, slug_value, allowed_project_ids):
        project, is_forbidden = self._resolve_project_for_context(slug_value, allowed_project_ids)
        if project:
            request.current_project = project
            request.slug = project.slug
            return True, False
        return False, is_forbidden

    @staticmethod
    def _can_apply_header_context(request, resolved):
        if not request.user.is_authenticated:
            return False
        if resolved and "slug" in getattr(resolved, "kwargs", {}):
            return False
        return request.path_info.startswith(HEADER_PROJECT_CONTEXT_ALLOWED_PATH_PREFIXES)

    def process_request(self, request):
        request.current_project = None
        request.slug = None
        allowed_project_ids = set()
        if request.user.is_authenticated:
            allowed_project_ids = set(get_user_projects(request.user).values_list("id", flat=True))

        resolved = getattr(request, "resolver_match", None)
        if resolved is None:
            try:
                resolved = resolve(request.path_info)
            except Exception:
                resolved = None

        if resolved and "slug" in getattr(resolved, "kwargs", {}):
            slug = resolved.kwargs["slug"]
            request.slug = slug
            request.current_project = get_object_or_404(Project, slug=slug)
        elif self._can_apply_header_context(request, resolved):
            if raw := (request.META.get(X_PROJECT_SLUG_HEADER) or "").strip():
                query_project_slug = (request.GET.get(PROJECT_CONTEXT_QUERY_PARAM) or "").strip()
                if query_project_slug and query_project_slug != raw:
                    logger.log_line(
                        "[DASHBOARD]",
                        "SLUG_MW",
                        "X-Project-Slug ignored due to query mismatch header=%s query=%s user_id=%s"
                        % (raw[:120], query_project_slug[:120], getattr(request.user, "pk", "")),
                        level="debug",
                    )
                else:
                    assigned, is_forbidden = self._assign_project_context(request, raw, allowed_project_ids)
                    if not assigned and is_forbidden:
                        logger.log_line(
                            "[DASHBOARD]",
                            "SLUG_MW",
                            "X-Project-Slug rejected for slug=%s user_id=%s"
                            % (raw[:120], getattr(request.user, "pk", "")),
                            level="debug",
                        )

        if request.current_project is None and request.user.is_authenticated:
            if qp := (request.GET.get(PROJECT_CONTEXT_QUERY_PARAM) or "").strip():
                assigned, _is_forbidden = self._assign_project_context(request, qp, allowed_project_ids)
                if not assigned:
                    logger.log_line(
                        "[DASHBOARD]",
                        "SLUG_MW",
                        "Query project context rejected for slug=%s user_id=%s"
                        % (qp[:120], getattr(request.user, "pk", "")),
                        level="debug",
                    )

        if request.current_project is None and request.user.is_authenticated:
            request.current_project = Project.objects.filter(users=request.user).first()
            if request.current_project:
                request.slug = request.current_project.slug

        if request.current_project:
            request.session["current_project_id"] = request.current_project.id
