from __future__ import annotations

from typing import Any, TypedDict

from django.core.cache import cache
from django.http import HttpRequest, JsonResponse
from django.template.loader import render_to_string

from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow


_INVALID_EXECUTION_MODE_HTML = '<div class="alert alert-warning">Invalid execution mode</div>'
_SECATOR_SELECTION_CACHE_TIMEOUT = 300


def normalize_secator_id_prefix(raw: str) -> str:
    """Normalize id_prefix for use in templates and DOM IDs (single convention: underscores)."""
    return (raw or "").strip().replace("-", "_")


class SecatorSelectionContext(TypedDict, total=False):
    workflows: list[SecatorWorkflow]
    all_tasks: Any
    tasks_dict: dict[str, SecatorTask]
    tasks: Any
    scans: list[
        Any
    ]  # scan mode: list of {"scan": SecatorScan, "workflows": [{"workflow", "structured_tasks", "tasks_count"}, ...]}


def get_secator_selection_template_and_context(execution_mode: str) -> tuple[str, SecatorSelectionContext]:
    """
    Build the template name and context for Secator selection UIs (workflow/tasks/scan).

    This helper is intentionally view-agnostic so it can be reused across multiple views.
    """
    mode = (execution_mode or "").strip().lower()
    context: SecatorSelectionContext = {}

    if mode == "workflow":
        workflows_queryset = (
            SecatorWorkflow.objects.filter(is_active=True)
            .only(
                "id",
                "name",
                "display_name",
                "description",
                "long_description",
                "workflow_type",
                "tags",
                "yaml_configuration",
            )
            .order_by("workflow_type", "name")
        )
        all_tasks = SecatorTask.objects.filter(is_active=True).only(
            "task_type",
            "name",
            "tags",
            "description",
        )
        tasks_dict = {task.task_type: task for task in all_tasks}

        workflows_list = list(workflows_queryset)
        # Precompute once so templates/templatetags avoid N+1 (get_structured_tasks/get_tasks_count).
        for workflow in workflows_list:
            workflow._precomputed_structured_tasks = workflow.get_structured_tasks()
            workflow._precomputed_tasks_count = workflow.get_tasks_count()

        context["workflows"] = workflows_list
        context["all_tasks"] = all_tasks
        context["tasks_dict"] = tasks_dict
        return "startScan/_items/secator_workflow_select.html", context

    if mode == "tasks":
        tasks = list(
            SecatorTask.objects.filter(is_active=True)
            .only("id", "name", "task_type", "tags", "description")
            .order_by("name")
        )

        # Sort by first tag so regroup in template groups consecutive items
        def _first_tag(t):
            return (t.tags[0] if t.tags else "unknown").lower()

        tasks.sort(key=lambda t: (_first_tag(t), t.name))
        context["tasks"] = tasks
        return "startScan/_items/secator_task_select.html", context

    if mode == "scan":
        scans_qs = (
            SecatorScan.objects.filter(scan_config_type="builtin", is_active=True)
            .only("name", "description", "long_description", "yaml_configuration")
            .order_by("name")
        )
        scans_list = list(scans_qs)
        scan_workflows_cache: list[dict[str, Any]] = []
        workflow_names: set[str] = set()
        for scan in scans_list:
            wfs = scan.get_workflows()
            scan_workflows_cache.append(wfs)
            workflow_names.update(wfs.keys())
        workflows_by_name: dict[str, SecatorWorkflow] = {}
        if workflow_names:
            workflows_qs = SecatorWorkflow.objects.filter(name__in=workflow_names).only(
                "id",
                "name",
                "display_name",
                "description",
                "long_description",
                "workflow_type",
                "tags",
                "yaml_configuration",
            )
            workflows_by_name = {w.name: w for w in workflows_qs}
        all_tasks = SecatorTask.objects.filter(is_active=True).only(
            "task_type",
            "name",
            "tags",
            "description",
        )
        tasks_dict = {task.task_type: task for task in all_tasks}
        scans_context: list[dict[str, Any]] = []
        for scan, wfs in zip(scans_list, scan_workflows_cache):
            ordered_names = list(wfs.keys())
            workflow_contexts: list[dict[str, Any]] = []
            for wf_name in ordered_names:
                wf = workflows_by_name.get(wf_name)
                if not wf:
                    continue
                structured_tasks = wf.get_structured_tasks()
                tasks_count = wf.get_tasks_count()
                wf._precomputed_structured_tasks = structured_tasks
                wf._precomputed_tasks_count = tasks_count
                workflow_contexts.append(
                    {
                        "workflow": wf,
                        "structured_tasks": structured_tasks,
                        "tasks_count": tasks_count,
                    }
                )
            scans_context.append({"scan": scan, "workflows": workflow_contexts})
        context["scans"] = scans_context
        context["tasks_dict"] = tasks_dict
        return "startScan/_items/secator_scan_select.html", context

    raise ValueError(f"Invalid execution_mode: {execution_mode!r}")


def _secator_selection_cache_key(execution_mode: str, id_prefix: str) -> str:
    """Build cache key for Secator selection response (execution_mode + normalized id_prefix)."""
    mode = (execution_mode or "").strip().lower()
    prefix = normalize_secator_id_prefix(id_prefix or "")
    return f"secator_selection:{mode}:{prefix}"


def render_secator_selection_json(request: HttpRequest) -> JsonResponse:
    """
    Render and return Secator selection HTML as JSON payload: {"html": "<...>"}.
    Responses are cached per execution_mode and id_prefix to keep repeat loads fast.
    """
    execution_mode = request.GET.get("execution_mode", "")
    id_prefix = request.GET.get("id_prefix", "")

    cache_key = _secator_selection_cache_key(execution_mode, id_prefix)
    if cached := cache.get(cache_key):
        return JsonResponse(cached)

    try:
        template, context = get_secator_selection_template_and_context(execution_mode)
        if id_prefix:
            context["id_prefix"] = normalize_secator_id_prefix(id_prefix)
    except ValueError:
        return JsonResponse({"html": _INVALID_EXECUTION_MODE_HTML})

    html = render_to_string(template, context, request=request)
    payload = {"html": html}
    cache.set(cache_key, payload, _SECATOR_SELECTION_CACHE_TIMEOUT)
    return JsonResponse(payload)
