from __future__ import annotations

from typing import Any, TypedDict

from django.http import HttpRequest, JsonResponse
from django.template.loader import render_to_string

from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow


_INVALID_EXECUTION_MODE_HTML = '<div class="alert alert-warning">Invalid execution mode</div>'


class SecatorSelectionContext(TypedDict, total=False):
    workflows: list[SecatorWorkflow]
    all_tasks: Any
    tasks_dict: dict[str, SecatorTask]
    tasks: Any
    scan_types: list[tuple[str, str]]


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
                "yaml_configuration",
            )
            .order_by("workflow_type", "name")
        )
        all_tasks = SecatorTask.objects.filter(is_active=True).only(
            "task_type",
            "name",
            "category",
            "description",
        )
        tasks_dict = {task.task_type: task for task in all_tasks}

        workflows_list = list(workflows_queryset)
        for workflow in workflows_list:
            workflow._precomputed_structured_tasks = workflow.get_structured_tasks()
            workflow._precomputed_tasks_count = workflow.get_tasks_count()

        context["workflows"] = workflows_list
        context["all_tasks"] = all_tasks
        context["tasks_dict"] = tasks_dict
        return "startScan/_items/secator_workflow_select.html", context

    if mode == "tasks":
        tasks = (
            SecatorTask.objects.filter(is_active=True)
            .only("id", "name", "task_type", "category", "description")
            .order_by("category", "name")
        )
        context["tasks"] = tasks
        return "startScan/_items/secator_task_select.html", context

    if mode == "scan":
        context["scan_types"] = [
            (scan.name, scan.description)
            for scan in SecatorScan.objects.filter(scan_config_type="builtin", is_active=True).order_by("name")
        ]
        return "startScan/_items/secator_scan_select.html", context

    raise ValueError(f"Invalid execution_mode: {execution_mode!r}")


def render_secator_selection_json(request: HttpRequest) -> JsonResponse:
    """
    Render and return Secator selection HTML as JSON payload: {"html": "<...>"}.
    """
    execution_mode = request.GET.get("execution_mode", "")

    try:
        template, context = get_secator_selection_template_and_context(execution_mode)
    except ValueError:
        return JsonResponse({"html": _INVALID_EXECUTION_MODE_HTML})

    html = render_to_string(template, context, request=request)
    return JsonResponse({"html": html})
