from collections import defaultdict
from datetime import datetime
import json

from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Case, Count, F, IntegerField, Q, Value, When
from django.db.models.functions import Coalesce, Lower
from django.http import Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone
from django.utils.html import mark_safe
import markdown
from rolepermissions.decorators import has_permission_decorator
from weasyprint import CSS, HTML

from api.helpers.datatables import (
    TABLE_ID_S3_BUCKETS,
    TABLE_ID_SCAN_HISTORY,
    TABLE_ID_SUBSCAN_HISTORY,
    TABLE_ID_VULNERABILITIES,
    get_datatable_row_group_config,
    get_datatable_table_config,
    get_scan_status_filter_labels,
    get_task_status_filter_labels,
)
from api.serializers import IpSerializer
from dashboard.models import Project
from reNgine.core.data import safe_int_cast
from reNgine.core.path import resolve_results_dir_under_base, safe_rmtree
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    FOUR_OH_FOUR_URL,
    PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_SCAN_REPORT,
    PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    RUNNING_BACKGROUND,
    RUNNING_TASK,
    SKIPPED_TASK,
    SUCCESS_TASK,
)
from reNgine.llm.utils import convert_markdown_to_html
from reNgine.secator.selected_targets import (
    filter_selected_targets_per_task_for_target,
    filter_targets_override_for_target,
)
from reNgine.secator.service import run_per_task_secator_scans, start_secator_scan
from reNgine.services.repositories import EndpointRepository
from reNgine.settings import RENGINE_RESULTS
from reNgine.utilities.db import count_subquery
from reNgine.utilities.domain import (
    get_domain_for_scan_by_name,
    get_domains_queryset_for_scan,
    get_scan_display_name,
)
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.subdomain import get_interesting_subdomains
from reNgine.utilities.time import local_to_utc_aware
from scanEngine.models import (
    EngineType,
    SecatorScan,
    VulnerabilityReportSetting,
)
from startScan.models import (
    Command,
    CountryISO,
    CveId,
    CweId,
    Domain,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    S3Bucket,
    ScanActivity,
    ScanHistory,
    ScanSchedule,
    SecatorRunner,
    Subdomain,
    SubScan,
    Vulnerability,
    VulnerabilityTags,
)
from startScan.secator.ajax import render_secator_selection_json
from startScan.secator.form import build_start_secator_scan_kwargs
from startScan.secator.profiles import build_secator_profiles_context
from targetApp.constants import RENGINE_TARGET_TYPES_FOR_JS
from targetApp.models import Organization, Scope, Target
from targetApp.services.scan_param_definitions import PARAM_KEYS as SCAN_PARAM_KEYS
from targetApp.services.scan_params_context import build_scan_params_form_context
from targetApp.services.scope_params import get_scope_for_target, get_workers_for_scan_dropdown


PREFIX_SCAN = "[STARTSCAN]"
logger = get_module_logger(__name__)

# Keys from scan_config that are safe to expose in the detail-scan UI.
# Built from the public SCAN_PARAM_KEYS plus the two composite fields.
# Any internal/engine-only keys added to scan_config in the future will NOT
# be shown unless explicitly added here.
_SCAN_CONFIG_DISPLAY_KEYS: frozenset[str] = SCAN_PARAM_KEYS | frozenset({"profiles", "extra_config"})


def _parse_domain_id_list(raw_domain_ids: str) -> tuple[list[int], list[str]]:
    raw_ids = [raw.strip() for raw in (raw_domain_ids or "").split(",") if raw.strip()]

    domain_id_list: list[int] = []
    invalid_domain_ids: list[str] = []

    for raw_id in raw_ids:
        casted_id = safe_int_cast(raw_id)
        if casted_id is None:
            invalid_domain_ids.append(raw_id)
        else:
            domain_id_list.append(casted_id)

    return domain_id_list, invalid_domain_ids


def _domains_for_scan_detail(scan_id: int) -> list:
    """
    Domains for the scan detail page: only domains belonging to this scan,
    excluding hostname-style names (e.g. www.example.com) so the card shows apex/root domains.
    """
    qs = get_domains_queryset_for_scan(scan_id)
    return [d for d in qs if len(d.name.split(".")) <= 2]


def _parse_target_id_list(raw_target_ids: str) -> tuple[list[int], list[str]]:
    """Parse comma-separated target IDs; return valid IDs and list of invalid raw values."""
    raw_ids = [raw.strip() for raw in (raw_target_ids or "").split(",") if raw.strip()]

    target_id_list: list[int] = []
    invalid: list[str] = []

    for raw_id in raw_ids:
        casted_id = safe_int_cast(raw_id)
        if casted_id is None or not Target.objects.filter(pk=casted_id).exists():
            invalid.append(raw_id)
        else:
            target_id_list.append(casted_id)

    return target_id_list, invalid


def _run_secator_scan_or_per_task(
    request,
    target_id: int,
    secator_kwargs: dict,
    *,
    imported_subdomains: list | None = None,
    out_of_scope_subdomains: list | None = None,
    url_filter: str = "",
) -> tuple[int, int]:
    """
    Run one start_secator_scan (single mode) or N scans per task (per_task mode).

    When secator_kwargs contains selected_targets_per_task and execution_mode is "tasks",
    runs one scan per (task_type, targets) via run_per_task_secator_scans; otherwise
    runs a single start_secator_scan. Returns (success_count, failed_count).
    """
    kwargs_copy = dict(secator_kwargs)
    selected_targets_per_task = kwargs_copy.pop("selected_targets_per_task", None)
    scan_history_id = kwargs_copy.pop("scan_history_id", None)
    kwargs_copy.pop("_worker_ids", None)  # internal; not passed to start_secator_scan
    if selected_targets_per_task and kwargs_copy.get("execution_mode") == "tasks":
        result = run_per_task_secator_scans(
            user_id=request.user.id,
            selected_targets_per_task=selected_targets_per_task,
            target_id=target_id,
            task_type_to_id=None,
            imported_subdomains=imported_subdomains or [],
            out_of_scope_subdomains=out_of_scope_subdomains or [],
            url_filter=url_filter,
            secator_config=kwargs_copy.get("secator_config") or {},
            scan_history_id=scan_history_id,
            worker_id=kwargs_copy.get("worker_id"),
        )
        if result["validation_errors"]:
            logger.log_line(
                PREFIX_SCAN,
                "PER_TASK_VALIDATION",
                "Per-task validation errors for target_id=%s: %s"
                % (target_id, [e["task_type"] for e in result["validation_errors"]]),
                level="warning",
            )
        return result["success_count"], result["failed_count"]

    result = start_secator_scan(
        user_id=request.user.id,
        target_id=target_id,
        imported_subdomains=imported_subdomains or [],
        out_of_scope_subdomains=out_of_scope_subdomains or [],
        url_filter=url_filter,
        scan_history_id=scan_history_id,
        **kwargs_copy,
    )
    return (1, 0) if result.get("status") else (0, 1)


def _start_secator_scans_for_target_ids(request, target_ids: list[int], secator_kwargs: dict) -> tuple[int, int]:
    scan_count = 0
    failed_count = 0
    skipped_no_tasks: list[str] = []
    execution_mode = secator_kwargs.get("execution_mode")
    targets_map = {t.id: t for t in Target.objects.filter(id__in=target_ids)}
    for target_id in target_ids:
        target = targets_map.get(target_id)
        if not target:
            continue
        kwargs_for_target = dict(secator_kwargs)
        filtered_override = filter_targets_override_for_target(
            target.value, kwargs_for_target.get("targets_override")
        )
        if filtered_override is not None:
            kwargs_for_target["targets_override"] = filtered_override
        else:
            kwargs_for_target.pop("targets_override", None)
        filtered_per_task = filter_selected_targets_per_task_for_target(
            target.value, kwargs_for_target.get("selected_targets_per_task")
        )
        if filtered_per_task is not None:
            kwargs_for_target["selected_targets_per_task"] = filtered_per_task
        else:
            kwargs_for_target.pop("selected_targets_per_task", None)
        if execution_mode == "tasks" and "selected_targets_per_task" not in kwargs_for_target:
            skipped_no_tasks.append(target.value)
            continue
        sc, fc = _run_secator_scan_or_per_task(request, target_id, kwargs_for_target)
        scan_count += sc
        failed_count += fc
    if skipped_no_tasks:
        messages.warning(
            request,
            "No scan started for target(s) %s: no selected proposed targets matched these targets."
            % (", ".join(skipped_no_tasks),),
        )
    return scan_count, failed_count


def _schedule_scan_ui_context(target: "Target") -> dict:
    """Build context for schedule_scan_ui.html (single target)."""
    context = {
        "scan_history_active": "active",
        "target": target,
    }
    context |= build_secator_profiles_context()
    return context


def _schedule_organization_scan_ui_context(organization: Organization) -> dict:
    """Build context for organization/schedule_scan_ui.html."""
    engine = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    return {
        "scan_history_active": "active",
        "organization": organization,
        "domain_list": organization.get_domains(),
        "engines": engine,
        "custom_engine_count": custom_engine_count,
    }


_VALID_FREQUENCY_TYPES = {choice[0] for choice in ScanSchedule.FREQUENCY_TYPE_CHOICES}

# Centralized message when scheduled_mode is missing or invalid (no default injected)
SCHEDULE_MODE_REQUIRED_MSG = "Scheduled mode is required."


def _normalize_periodic_frequency_from_post(post_data) -> tuple[int, str]:
    """
    Parse and validate periodic frequency from POST data.

    Single source of truth for frequency value and type used by both form validation
    and schedule creation. Returns (frequency_value, frequency_type).

    Raises:
        ValueError: With a user-facing message if value is missing, not positive, or type invalid.
    """
    raw_freq = post_data.get("frequency")
    if raw_freq is None or (isinstance(raw_freq, str) and not raw_freq.strip()):
        raise ValueError("Please set the run interval for periodic scans.")
    val = safe_int_cast(raw_freq)
    if val is None or val < 1:
        raise ValueError("Frequency must be a positive number.")
    freq_type = (post_data.get("frequency_type") or "").strip().lower()
    if freq_type not in _VALID_FREQUENCY_TYPES:
        raise ValueError("Invalid frequency unit.")
    return (val, freq_type)


def _validate_schedule_form_post(post_data) -> tuple[str | None, str | None]:
    """
    Validate schedule form: scheduled_mode must be present and periodic or clocked;
    periodic requires frequency and frequency_type; clocked requires scheduled_time.

    Returns:
        (error_message, normalized_mode): if valid (None, mode); if invalid (message, None).
        Callers can rely on the returned mode when error_message is None.
    """
    raw_mode = (post_data.get("scheduled_mode") or "").strip().lower()
    if not raw_mode:
        return (SCHEDULE_MODE_REQUIRED_MSG, None)
    if raw_mode not in (ScanSchedule.SCHEDULE_MODE_PERIODIC, ScanSchedule.SCHEDULE_MODE_CLOCKED):
        return (SCHEDULE_MODE_REQUIRED_MSG, None)
    if raw_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC:
        try:
            _normalize_periodic_frequency_from_post(post_data)
        except ValueError as e:
            return (str(e), None)
        return (None, raw_mode)
    scheduled_time = (post_data.get("scheduled_time") or "").strip()
    if not scheduled_time:
        return ("Please select a date and time for the one-time scan.", None)
    try:
        datetime.strptime(scheduled_time, "%Y-%m-%d %H:%M")
    except ValueError:
        return ("Invalid date and time format for one-time scan.", None)
    return (None, raw_mode)


def _parse_scheduled_time_utc(schedule_time_str: str, timezone_offset: int) -> datetime | None:
    """
    Parse 'YYYY-MM-DD HH:MM' to timezone-aware UTC datetime.
    Returns None on parse or conversion error (avoids 500s on malformed input).
    """
    try:
        raw = (schedule_time_str or "").strip()
        if not raw:
            return None
        local_time = datetime.strptime(raw, "%Y-%m-%d %H:%M")
        return local_to_utc_aware(local_time, timezone_offset)
    except (ValueError, TypeError):
        return None


def _build_scan_schedule_common(
    name: str,
    target: "Target",
    initiated_by,
    imported_subdomains: list,
    out_of_scope_subdomains: list,
    *,
    scan_type=None,
    secator_kwargs: dict | None = None,
) -> dict:
    """
    Build common kwargs for ScanSchedule.objects.create.
    Used by both schedule_scan (secator_kwargs) and schedule_organization_scan (scan_type).
    """
    return {
        "name": name,
        "target": target,
        "scan_type": scan_type,
        "secator_kwargs": secator_kwargs,
        "initiated_by": initiated_by,
        "imported_subdomains": imported_subdomains,
        "out_of_scope_subdomains": out_of_scope_subdomains,
        "enabled": True,
    }


def _build_multiple_scan_selection_from_post(request) -> tuple[list[str], str]:
    """Build list of target display names and comma-separated target IDs from POST (target list checkboxes)."""
    list_of_target_name: list[str] = []
    list_of_target_id: list[str] = []

    ignored_keys = {
        "list_target_table_length",
        "csrfmiddlewaretoken",
    }
    for key, value in request.POST.items():
        if key in ignored_keys:
            continue
        tid = safe_int_cast(value)
        if tid is None:
            messages.warning(request, "Ignoring invalid target ID: %r" % (value,))
            continue
        target = Target.objects.filter(pk=tid).first()
        if target is None:
            messages.warning(request, "Target %s not found, ignoring" % (tid,))
            continue
        list_of_target_name.append(target.value)
        list_of_target_id.append(str(tid))

    target_ids = ",".join(list_of_target_id)
    return list_of_target_name, target_ids


def _resolve_target_from_domain(domain: Domain) -> Target:
    """Resolve the Target associated with a Domain via its scan_history, with fallback by name."""
    if domain.scan_history_id:
        target = getattr(domain.scan_history, "target", None)
        if target is not None:
            return target
    target = Target.objects.filter(value=domain.name).first()
    if target is not None:
        return target
    raise Http404(f"No Target found for domain {domain.name}")


def build_command_hierarchy(commands):
    """
    Build hierarchical structure from ordered commands.

    Takes a list of Command objects ordered by hierarchy (scan > workflow > task)
    and builds a nested structure: scan > workflows > tasks.

    Args:
        commands: List of Command objects, already ordered by hierarchy type,
                  group key (ancestor_id/workflow_name), and time.

    Returns:
        List of hierarchical entries. Each entry is either:
        - A scan dict: {"command": Command, "workflows": [...], "tasks": [...]}
        - A workflow dict: {"command": Command, "tasks": [...]}

    Example:
        Input: [scan_cmd, workflow_cmd, task_cmd1, task_cmd2]
        Output: [
            {
                "command": scan_cmd,
                "workflows": [
                    {
                        "command": workflow_cmd,
                        "tasks": [task_cmd1, task_cmd2]
                    }
                ],
                "tasks": []
            }
        ]

        Input: [scan_cmd, task_cmd1, task_cmd2]  # Direct task scan
        Output: [
            {
                "command": scan_cmd,
                "workflows": [],
                "tasks": [task_cmd1, task_cmd2]
            }
        ]
    """
    # First pass: build map of workflows by name
    workflow_by_name = {}  # Map workflow name to workflow command
    workflow_entries = {}  # Map workflow command to its entry dict

    for command in commands:
        if command.runner_type == "workflow":
            workflow_name = command.name or ""
            if workflow_name:
                workflow_by_name[workflow_name] = command
            if command.workflow_name and command.workflow_name != workflow_name:
                workflow_by_name[command.workflow_name] = command
            # Create workflow entry
            workflow_entries[command] = {"command": command, "tasks": []}

    # Second pass: build hierarchical structure
    hierarchical_structure = []
    current_scan = None

    for command in commands:
        if command.runner_type == "scan":
            # New scan - start a new top-level entry with both workflows and direct tasks
            current_scan = {
                "command": command,
                "workflows": [],
                "tasks": [],  # Direct tasks (no workflow parent)
            }
            hierarchical_structure.append(current_scan)
        elif command.runner_type == "workflow":
            # Workflow - add to current scan or create standalone
            if current_scan:
                # Add to current scan
                workflow_entry = workflow_entries.get(command, {"command": command, "tasks": []})
                current_scan["workflows"].append(workflow_entry)
            else:
                # Standalone workflow (no scan parent)
                workflow_entry = workflow_entries.get(command, {"command": command, "tasks": []})
                hierarchical_structure.append(workflow_entry)
        elif command.runner_type == "task":
            # Task - find parent workflow and add to it, or add directly to scan if no workflow found
            task_added = False
            if command.ancestor_id:
                parent_workflow = workflow_by_name.get(command.ancestor_id)
                if parent_workflow:
                    workflow_entry = workflow_entries.get(parent_workflow)
                    if workflow_entry:
                        workflow_entry["tasks"].append(command)
                        task_added = True
                    else:
                        # Workflow entry not found, create it
                        if current_scan:
                            # Add workflow to current scan first
                            new_workflow_entry = {"command": parent_workflow, "tasks": [command]}
                            current_scan["workflows"].append(new_workflow_entry)
                            workflow_entries[parent_workflow] = new_workflow_entry
                            task_added = True
                        else:
                            # Standalone workflow
                            new_workflow_entry = {"command": parent_workflow, "tasks": [command]}
                            hierarchical_structure.append(new_workflow_entry)
                            workflow_entries[parent_workflow] = new_workflow_entry
                            task_added = True

            # If task wasn't added to a workflow, add it directly to scan (scan of type "task")
            if not task_added and current_scan:
                current_scan["tasks"].append(command)
            elif not task_added:
                # No scan and no workflow found - create standalone task entry
                hierarchical_structure.append({"command": command, "tasks": []})

    return hierarchical_structure


def scan_history(request, slug):
    host = (
        ScanHistory.objects.filter(target__project__slug=slug)
        .order_by("-start_scan_date")
        .select_related("target", "target__project", "initiated_by", "scan_type")
        .prefetch_related(
            "secatorrunner_set__worker",
            "target__organizations",
        )
        .annotate(
            # Scalar count subqueries avoid cartesian products vs Count(distinct=...) over joins.
            domain_count=count_subquery(Domain, "scan_history_id"),
            subdomain_count=count_subquery(Subdomain, "scan_history_id"),
            endpoint_count=count_subquery(EndPoint, "scan_history_id"),
            vuln_count=count_subquery(Vulnerability, "scan_history_id"),
            vuln_critical_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 4}),
            vuln_high_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 3}),
            vuln_medium_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 2}),
        )
    )

    dt_config = get_datatable_table_config(TABLE_ID_SCAN_HISTORY)
    context = {
        "scan_history_active": "active",
        "scan_history": host,
        "scan_status_filter_labels": get_scan_status_filter_labels(),
        "datatable_filter_select_to_param": dt_config.get("filter_context"),
        "datatable_row_group_config": get_datatable_row_group_config(TABLE_ID_SCAN_HISTORY),
    }
    return render(request, "startScan/history.html", context)


def subscan_history(request, slug):
    subscans = (
        SubScan.objects.filter(scan_history__target__project__slug=slug)
        .select_related("secator_runner__worker", "scan_history")
        .prefetch_related("scan_history__secatorrunner_set__worker")
        .order_by("-start_scan_date")
    )
    dt_config = get_datatable_table_config(TABLE_ID_SUBSCAN_HISTORY)
    context = {
        "scan_history_active": "active",
        "subscans": subscans,
        "task_status_filter_labels": get_task_status_filter_labels(),
        "datatable_filter_select_to_param": dt_config.get("filter_context"),
        "datatable_row_group_cookie_key": dt_config.get("row_group_cookie_key"),
        "datatable_row_group_selector": dt_config.get("row_group_selector"),
    }
    return render(request, "startScan/subscan_history.html", context)


def scan_logs_view(request, slug):
    """
    View to render command logs with hierarchy.
    Returns HTML formatted logs using Django template.
    """
    scan_id = safe_int_cast(request.GET.get("scan_id"))
    activity_id = safe_int_cast(request.GET.get("activity_id"))
    include_pending = request.GET.get("include_pending", "false").lower() == "true"

    if scan_id is None and activity_id is None:
        return HttpResponse("scan_id or activity_id is required", status=400)

    # Get commands and validate slug matches project
    if scan_id is not None:
        queryset = Command.objects.filter(
            scan_history__id=scan_id,
            scan_history__target__project__slug=slug,
        )
    else:
        queryset = Command.objects.filter(
            activity__id=activity_id,
            activity__scan_of__target__project__slug=slug,
        )

    # Exclude PENDING status by default unless include_pending is true
    if not include_pending:
        queryset = queryset.filter(~Q(status="PENDING") | Q(status__isnull=True))

    # Push ordering into the database so we don't have to materialize and sort
    # a large queryset in Python. Order first by hierarchy type, then by
    # grouping key (ancestor_id/workflow_name), and finally by a stable timestamp/id.
    type_order_case = Case(
        When(runner_type="scan", then=Value(0)),
        When(runner_type="workflow", then=Value(1)),
        When(runner_type="task", then=Value(2)),
        default=Value(3),
        output_field=IntegerField(),
    )

    # Use Coalesce to handle None values for ancestor_id in group_key
    # For scans: group_key is None (appear first)
    # For workflows: group_key is workflow_name or name
    # For tasks: group_key is ancestor_id
    queryset = queryset.annotate(
        type_order=type_order_case,
        # Use ancestor_id for tasks, workflow_name for workflows, None for scans
        group_key=Coalesce(
            F("ancestor_id"),
            F("workflow_name"),
            F("name"),
            Value(""),
        ),
    ).order_by(
        "type_order",
        "group_key",
        "time",
        "id",
    )

    # Materialize the ordered queryset
    commands_list = list(queryset)

    # Build hierarchical structure in a single pass
    hierarchical_structure = build_command_hierarchy(commands_list)

    context = {
        "hierarchical_structure": hierarchical_structure,
    }
    return render(request, "startScan/_items/command_logs.html", context)


def detail_scan(request, id, slug):
    ctx = {}

    # Get scan objects (prefetch runners+worker; select_related target for context and links)
    scan = get_object_or_404(
        ScanHistory.objects.select_related("target").prefetch_related("secatorrunner_set__worker"),
        id=id,
    )
    target_value = (scan.target.value if getattr(scan, "target", None) else "") or ""
    target_domain = get_domain_for_scan_by_name(scan.id, target_value) if target_value else None
    scan_display_name = get_scan_display_name(target_value)
    context_target_id = scan.target_id
    scan_engines = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    recent_scans = (
        ScanHistory.objects.filter(target_id=context_target_id) if context_target_id else ScanHistory.objects.none()
    )
    last_scans_base = (
        ScanHistory.objects.filter(target_id=context_target_id) if context_target_id else ScanHistory.objects.none()
    )
    last_scans = last_scans_base.filter(tasks__overlap=["subdomain_discovery"]).filter(id__lte=id).filter(scan_status=2)

    # Get all kind of objects associated with our ScanHistory object
    emails = Email.objects.filter(emails__in=[scan])
    employees = Employee.objects.filter(employees__in=[scan])
    subdomains = Subdomain.objects.filter(scan_history=scan)
    endpoints = EndPoint.objects.filter(scan_history=scan)

    # Optimize vulnerability queries with prefetch_related to avoid N+1 queries
    vulns = Vulnerability.objects.filter(scan_history=scan).prefetch_related(
        "cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "domain", "scan_history"
    )

    vulns_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulns)
    # Distinct by PK so we keep one row per IpAddress; distinct("address") can drop rows on some backends.
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct()
    # Precompute subdomain count/names per IP to avoid N+1 in IpSerializer
    through = Subdomain.ip_addresses.through
    ip_subdomain_data = defaultdict(lambda: {"count": 0, "names": []})
    for ip_id, name in (
        through.objects.filter(subdomain__scan_history_id=id).values_list("ipaddress_id", "subdomain__name").distinct()
    ):
        ip_subdomain_data[ip_id]["count"] += 1
        ip_subdomain_data[ip_id]["names"].append(name)
    ip_serializer = IpSerializer(
        ip_addresses.prefetch_related("ports").all(),
        many=True,
        context={
            "scan_id": id,
            "target_id": context_target_id,
            "ip_subdomain_data": dict(ip_subdomain_data),
        },
    )
    geo_isos = CountryISO.objects.filter(ipaddress__in=ip_addresses)

    # Order in DB: status priority (running first, then failed, success, etc.), then runner type
    # (scan/workflow/task), then -time. Uses indexes and avoids materializing large sets in Python.
    status_order_case = Case(
        When(status__in=(RUNNING_TASK, RUNNING_BACKGROUND), then=Value(0)),
        When(status=FAILED_TASK, then=Value(1)),
        When(status=SUCCESS_TASK, then=Value(2)),
        When(status=ABORTED_TASK, then=Value(3)),
        When(status=SKIPPED_TASK, then=Value(4)),
        default=Value(5),
        output_field=IntegerField(),
    )
    type_order_case = Case(
        When(runner_id__runner_type="scan", then=Value(0)),
        When(runner_id__runner_type="workflow", then=Value(1)),
        When(runner_id__runner_type="task", then=Value(2)),
        default=Value(3),
        output_field=IntegerField(),
    )
    scan_activity = (
        ScanActivity.objects.filter(scan_of__id=id)
        .select_related("scan_of", "runner_id")
        .annotate(
            status_order=status_order_case,
            type_order=type_order_case,
        )
        .order_by("status_order", "type_order", "-time")
    )
    cves = CveId.objects.filter(cve_ids__in=vulns)
    cwes = CweId.objects.filter(cwe_ids__in=vulns)

    # CVEs / CWes
    common_cves = cves.annotate(nused=Count("cve_ids")).order_by("-nused").values("name", "nused")[:10]
    common_cwes = cwes.annotate(nused=Count("cwe_ids")).order_by("-nused").values("name", "nused")[:10]

    # Tags
    common_tags = vulns_tags.annotate(nused=Count("vuln_tags")).order_by("-nused").values("name", "nused")[:7]

    # Countries
    asset_countries = geo_isos.annotate(count=Count("iso")).order_by("-count")

    # Subdomains
    subdomain_count = subdomains.values("name").distinct().count()
    alive_count = subdomains.values("name").distinct().filter(http_status__gt=0).count()
    important_count = subdomains.values("name").distinct().filter(is_important=True).count()

    # Endpoints
    endpoint_count = endpoints.values("http_url").distinct().count()
    endpoint_alive_count = (
        endpoints.filter(http_status__gt=0)  # TODO: use is_alive() func as it's more precise
        .values("http_url")
        .distinct()
        .count()
    )

    # Vulnerabilities: single aggregation for severity counts
    severity_counts = dict(vulns.values("severity").annotate(c=Count("id")).values_list("severity", "c"))

    # Ensure we don't silently drop unexpected severities from level counts
    allowed_severities = {-1, 0, 1, 2, 3, 4}
    unexpected_severities = set(severity_counts.keys()) - allowed_severities
    assert not unexpected_severities, (
        f"Unexpected vulnerability severities encountered: {unexpected_severities}. "
        f"Expected severities to be a subset of {allowed_severities}."
    )

    info_count = severity_counts.get(0, 0)
    low_count = severity_counts.get(1, 0)
    medium_count = severity_counts.get(2, 0)
    high_count = severity_counts.get(3, 0)
    critical_count = severity_counts.get(4, 0)
    unknown_count = severity_counts.get(-1, 0)
    total_count = sum(severity_counts.values())
    total_count_ignore_info = total_count - info_count

    common_vulns = (
        vulns.exclude(severity=0).values("name", "severity").annotate(count=Count("name")).order_by("-count")[:10]
    )

    # Emails
    exposed_count = emails.exclude(password__isnull=True).count()

    # Preload SecatorRunner for this scan
    secator_runners = SecatorRunner.objects.filter(scan_history=scan).order_by("-created_at")
    is_secator_scan = secator_runners.exists()

    # Show Screenshots tab when scan had screenshot task (legacy) or has endpoints with screenshots (e.g. Secator)
    tasks = scan.tasks or []
    has_screenshots = (
        "screenshot" in tasks or endpoints.filter(screenshot_path__isnull=False).exclude(screenshot_path="").exists()
    )

    s3_bucket_names = sorted(
        {
            bucket_name
            for bucket_name in S3Bucket.objects.filter(buckets__id=id).order_by("name").values_list("name", flat=True)
            if bucket_name
        }
    )

    # Build render context
    ctx = {
        "scan_history_id": id,
        "context_target_id": context_target_id,
        "target_domain": target_domain,
        "scan_display_name": scan_display_name,
        "history": scan,
        "scan_activity": scan_activity,
        "secator_runners": secator_runners,
        "is_secator_scan": is_secator_scan,
        "ip_addresses": json.dumps(ip_serializer.data, cls=DjangoJSONEncoder),
        "subdomain_count": subdomain_count,
        "alive_count": alive_count,
        "important_count": important_count,
        "endpoint_count": endpoint_count,
        "endpoint_alive_count": endpoint_alive_count,
        "info_count": info_count,
        "low_count": low_count,
        "medium_count": medium_count,
        "high_count": high_count,
        "critical_count": critical_count,
        "unknown_count": unknown_count,
        "total_vulnerability_count": total_count,
        "total_vul_ignore_info_count": total_count_ignore_info,
        "total_secret_count": scan.get_secret_count(),
        "vulnerability_list": vulns.order_by("-severity").all(),
        "scan_history_active": "active",
        "scan_engines": scan_engines,
        "exposed_count": exposed_count,
        "email_count": emails.count(),
        "employees_count": employees.count(),
        "most_recent_scans": recent_scans.order_by("-start_scan_date")[:1],
        "http_status_breakdown": EndpointRepository().get_http_status_breakdown(scan),
        "most_common_cve": common_cves,
        "most_common_cwe": common_cwes,
        "most_common_tags": common_tags,
        "most_common_vulnerability": common_vulns,
        "asset_countries": asset_countries,
        "has_screenshots": has_screenshots,
        "domains": _domains_for_scan_detail(id),
        "s3_datatable_filter_select_to_param": get_datatable_table_config(TABLE_ID_S3_BUCKETS).get("filter_context"),
        "s3_bucket_names": s3_bucket_names,
        "datatable_row_group_cookie_key_vuln": get_datatable_table_config(TABLE_ID_VULNERABILITIES).get(
            "row_group_cookie_key"
        ),
        "datatable_row_group_selector_vuln": get_datatable_table_config(TABLE_ID_VULNERABILITIES).get(
            "row_group_selector"
        ),
    }

    # Find number of matched GF patterns (one query then count in Python)
    if scan.used_gf_patterns:
        gf_patterns = [p.strip() for p in scan.used_gf_patterns.split(",") if p.strip()]
        if gf_patterns:
            count_gf = {}
            matched_values = list(
                endpoints.values_list("matched_gf_patterns", flat=True)
                .exclude(matched_gf_patterns__isnull=True)
                .exclude(matched_gf_patterns="")
            )
            for gf in gf_patterns:
                count_gf[gf] = sum(1 for m in matched_values if m and gf in m)
            ctx["matched_gf_count"] = count_gf

    # Find last scan for this domain
    if last_scans.count() > 1:
        last_scan = last_scans.order_by("-start_scan_date")[1]
        ctx["last_scan"] = last_scan

    # Secator profiles context for subscan modal (Advanced config > profiles)
    ctx.update(build_secator_profiles_context())
    scope = get_scope_for_target(scan.target) if getattr(scan, "target", None) else None
    ctx["secator_workers"] = get_workers_for_scan_dropdown(scope=scope)
    ctx["rengine_target_types"] = RENGINE_TARGET_TYPES_FOR_JS

    scan_config = getattr(scan, "scan_config", None)
    if isinstance(scan_config, dict) and scan_config:
        display = {}
        for k, v in scan_config.items():
            if k not in _SCAN_CONFIG_DISPLAY_KEYS:
                continue
            if k == "profiles":
                if isinstance(v, dict):
                    display[k] = [f"{cat}: {name}" for cat, name in v.items() if name]
                elif isinstance(v, list):
                    display[k] = [str(p) for p in v if p]
                else:
                    display[k] = []
            elif k in ("header", "extra_config") and isinstance(v, dict):
                display[k] = json.dumps(v, indent=2)
            else:
                display[k] = v
        ctx["scan_config_display"] = display
    else:
        ctx["scan_config_display"] = None

    return render(request, "startScan/detail_scan.html", ctx)


def all_subdomains(request, slug):
    project = get_object_or_404(Project, slug=slug)
    subdomains = Subdomain.objects.filter(domain__scan_history__target__project__slug=slug)
    scan_engines = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    alive_subdomains = subdomains.filter(http_status__gt=0)  # TODO: replace this with is_alive() function
    important_subdomains = subdomains.filter(is_important=True).values("name").distinct().count()
    context = {
        "scan_history_id": id,
        "scan_history_active": "active",
        "current_project": project,
        "scan_engines": scan_engines,
        "subdomain_count": subdomains.values("name").distinct().count(),
        "alive_count": alive_subdomains.values("name").distinct().count(),
        "important_count": important_subdomains,
    }
    context.update(build_secator_profiles_context())
    context["secator_workers"] = get_workers_for_scan_dropdown()
    context.update(build_scan_params_form_context(level="scan"))
    return render(request, "startScan/subdomains.html", context)


def detail_vuln_scan(request, slug, id=None):
    dt_config = get_datatable_table_config(TABLE_ID_VULNERABILITIES)
    if id:
        history = get_object_or_404(ScanHistory, id=id)
        context = {"scan_history_id": id, "history": history}
    else:
        context = {"vuln_scan_active": "true"}
    context["datatable_row_group_cookie_key"] = dt_config.get("row_group_cookie_key")
    context["datatable_row_group_selector"] = dt_config.get("row_group_selector")
    return render(request, "startScan/vulnerabilities.html", context)


def all_endpoints(request, slug):
    context = {"scan_history_active": "active"}
    return render(request, "startScan/endpoints.html", context)


def start_scan_ui(request, slug, target_id):
    target = get_object_or_404(Target, id=target_id)
    if request.method == "POST":
        # Collect all parameters from form
        subdomains_in = request.POST.get("importSubdomainTextArea", "").split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST.get("outOfScopeSubdomainTextarea", "").split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        paths = request.POST.get("filterPath", "").split()
        filter_path = paths[0].rstrip() if paths else ""

        scope = get_scope_for_target(target)
        try:
            secator_kwargs = build_start_secator_scan_kwargs(request.POST, target=target, scope=scope)
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("start_scan", slug=slug, target_id=target_id)

        scan_count, failed_count = _run_secator_scan_or_per_task(
            request,
            target.id,
            secator_kwargs,
            imported_subdomains=subdomains_in,
            out_of_scope_subdomains=subdomains_out,
            url_filter=filter_path,
        )

        if scan_count >= 1:
            messages.add_message(request, messages.INFO, "Scan Started for %s" % (target.value,))
            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))
        error_msg = "Unknown error" if failed_count else "No scan started"
        messages.add_message(request, messages.ERROR, "Failed to start scan: %s" % (error_msg,))
        return HttpResponseRedirect(reverse("start_scan", kwargs={"slug": slug, "target_id": target_id}))

    # GET request
    scan_type = request.GET.get("scan_type", "internet")

    engine = (
        EngineType.objects.filter(scan_type=scan_type).annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    )

    custom_engine_count = EngineType.objects.filter(default_engine=False).count()

    has_ip_content = Subdomain.objects.filter(scan_history__target_id=target.id, ip_addresses__isnull=False).exists()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        if request.GET.get("ajax") == "true":
            return render_secator_selection_json(request)

        from django.template.loader import render_to_string

        engine_html = render_to_string(
            "startScan/_items/scanEngine_select.html",
            {
                "engines": engine,
                "custom_engine_count": custom_engine_count,
            },
        )
        return JsonResponse({"engine_html": engine_html})

    scope = get_scope_for_target(target)
    organization = scope.organization if scope else target.organizations.first()

    form_ctx = build_scan_params_form_context(target=target, scope=scope, organization=organization, level="scan")
    context = {
        "scan_history_active": "active",
        "target": target,
        "engines": engine,
        "custom_engine_count": custom_engine_count,
        "scan_type": scan_type,
        "has_ip_content": has_ip_content,
        "rengine_target_types": RENGINE_TARGET_TYPES_FOR_JS,
    }
    context.update(form_ctx)
    context["secator_workers"] = get_workers_for_scan_dropdown(scope=scope)
    return render(request, "startScan/start_scan_ui.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    if request.GET.get("ajax") == "true":
        return render_secator_selection_json(request)

    list_of_target_name: list[str] = []
    target_ids_str = ""

    if request.method == "POST":
        raw_ids = request.POST.get("list_of_target_id") or ""
        if raw_ids:
            # POST from start_multiple_scan_ui: start scans for selected targets
            try:
                secator_kwargs = build_start_secator_scan_kwargs(request.POST)
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect("start_multiple_scan", slug=slug)

            target_id_list, invalid_ids = _parse_target_id_list(raw_ids)
            if invalid_ids:
                messages.warning(request, "Ignoring invalid target ID(s): %s" % (", ".join(invalid_ids),))

            if not target_id_list:
                messages.error(request, "Please select at least one valid target.")
                return redirect("start_multiple_scan", slug=slug)

            scan_count, failed_count = _start_secator_scans_for_target_ids(request, target_id_list, secator_kwargs)

            if scan_count > 0:
                messages.add_message(request, messages.INFO, "Started %s scans for multiple targets" % (scan_count,))
            if failed_count > 0:
                messages.add_message(request, messages.WARNING, "Failed to start %s scans" % (failed_count,))

            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))

        # POST from targets list: build selection list and render UI
        list_of_target_name, target_ids_str = _build_multiple_scan_selection_from_post(request)

    # GET request
    scan_type = request.GET.get("scan_type", "internet")

    engines = EngineType.objects.filter(scan_type=scan_type)

    custom_engine_count = engines.filter(default_engine=False).count()
    first_target_id = None
    first_target = None
    scope = None
    organization = None
    if target_ids_str:
        first_id = target_ids_str.split(",")[0].strip()
        if first_id.isdigit():
            first_target_id = first_id
            first_target = Target.objects.filter(id=int(first_id)).select_related("project").first()
            if first_target and first_target.project.slug == slug:
                scope = get_scope_for_target(first_target)
                organization = scope.organization if scope else first_target.organizations.first()

    form_ctx = build_scan_params_form_context(target=first_target, scope=scope, organization=organization)
    context = {
        "scan_history_active": "active",
        "engines": engines,
        "target_list": list_of_target_name,
        "target_ids": target_ids_str,
        "domain_list": list_of_target_name,
        "domain_ids": target_ids_str,
        "custom_engine_count": custom_engine_count,
        "scan_type": scan_type,
        "first_target_id": first_target_id,
    }
    context.update(form_ctx)
    context["secator_workers"] = (
        get_workers_for_scan_dropdown(scope=scope) if scope else get_workers_for_scan_dropdown()
    )
    return render(request, "startScan/start_multiple_scan_ui.html", context)


def export_subdomains(request, slug, scan_id):
    subdomain_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.select_related("target").get(id=scan_id)
    response_body = ""
    for domain in subdomain_list:
        response_body += response_body + domain.name + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = get_scan_display_name(scan.target.value if scan.target_id else "")
    response = HttpResponse(response_body, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="subdomains_{domain_name}_{scan_start_date_str}.txt"'
    return response


def export_endpoints(request, slug, scan_id):
    endpoint_list = EndPoint.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.select_related("target").get(id=scan_id)
    response_body = ""
    for endpoint in endpoint_list:
        response_body += endpoint.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = get_scan_display_name(scan.target.value if scan.target_id else "")
    response = HttpResponse(response_body, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="endpoints_{domain_name}_{scan_start_date_str}.txt"'
    return response


def export_urls(request, slug, scan_id):
    urls_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.select_related("target").get(id=scan_id)
    response_body = ""
    for url in urls_list:
        if url.http_url:
            response_body += response_body + url.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = get_scan_display_name(scan.target.value if scan.target_id else "")
    response = HttpResponse(response_body, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="urls_{domain_name}_{scan_start_date_str}.txt"'
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scan(request, slug, id):
    obj = get_object_or_404(ScanHistory, id=id)
    if request.method == "POST":
        delete_dir = obj.results_dir
        # resolve_results_dir_under_base returns None when results_dir is missing/invalid;
        # we intentionally no-op in that case (no filesystem delete) for safety.
        resolved = resolve_results_dir_under_base(RENGINE_RESULTS, delete_dir or "")
        cleanup_status = None
        if resolved is not None:
            result = safe_rmtree(RENGINE_RESULTS, resolved)
            cleanup_status = result
            if result == "refused":
                logger.log_line(
                    PREFIX_SCAN,
                    "DELETE_SCAN",
                    "Results dir cleanup refused for path %s; likely configuration or permission issue. "
                    "scan_history_id=%s base_dir=%r" % (resolved, getattr(obj, "id", None), RENGINE_RESULTS),
                    level="warning",
                )
            elif result == "failed":
                logger.log_line(
                    PREFIX_SCAN,
                    "DELETE_SCAN",
                    "Results dir cleanup failed for path %s; transient or unexpected error. "
                    "scan_history_id=%s base_dir=%r" % (resolved, getattr(obj, "id", None), RENGINE_RESULTS),
                    level="warning",
                )
            elif result != "removed":
                logger.log_line(
                    PREFIX_SCAN,
                    "DELETE_SCAN",
                    "Results dir cleanup returned %s for path %s. scan_history_id=%s base_dir=%r"
                    % (result, resolved, getattr(obj, "id", None), RENGINE_RESULTS),
                    level="warning",
                )
        elif delete_dir:
            cleanup_status = "resolution_failed"
            logger.log_line(
                PREFIX_SCAN,
                "DELETE_SCAN",
                "results_dir resolution failed; not deleting directory. scan_history_id=%s results_dir=%r base_dir=%r"
                % (getattr(obj, "id", None), delete_dir, RENGINE_RESULTS),
                level="warning",
            )
        obj.delete()
        message_data = {"status": "true"}
        if cleanup_status and cleanup_status != "removed":
            messages.add_message(
                request,
                messages.WARNING,
                "Scan history deleted, but result files could not be fully cleaned up. "
                "This may indicate a configuration or permission issue; please contact an administrator.",
            )
        else:
            messages.add_message(request, messages.INFO, "Scan history successfully deleted!")
    else:
        message_data = {"status": "false"}
        messages.add_message(request, messages.INFO, "Oops! something went wrong!")
    return JsonResponse(message_data)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scan(request, slug, id):
    if request.method == "POST":
        scan = get_object_or_404(ScanHistory, id=id)
        try:
            from reNgine.secator.control import SecatorScanController

            controller = SecatorScanController(id)
            success = controller.stop_scan()

            if success:
                scan.refresh_from_db()
                scan.aborted_by = request.user
                scan.stop_scan_date = timezone.now()
                scan.save()
                response = {"status": True}
                messages.add_message(request, messages.INFO, "Scan successfully stopped!")
            else:
                response = {"status": False, "message": "Failed to stop scan"}
                messages.add_message(request, messages.ERROR, "Failed to stop scan")
        except Exception as e:
            logger.log_line(
                PREFIX_SCAN,
                "STOP_SCAN",
                "Failed to stop scan: %s" % (e,),
                level="error",
                exc_info=True,
            )
            response = {"status": False}
            messages.add_message(request, messages.ERROR, f"Scan failed to stop ! Error: {str(e)}")
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_scan(request, host_id, slug):
    domain = get_object_or_404(Domain, id=host_id)
    target = _resolve_target_from_domain(domain)
    if request.method == "POST":
        try:
            secator_kwargs = build_start_secator_scan_kwargs(request.POST)
        except ValueError as exc:
            messages.error(request, str(exc))
            return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(target))

        schedule_error, scheduled_mode = _validate_schedule_form_post(request.POST)
        if schedule_error:
            messages.error(request, schedule_error)
            return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(target))

        subdomains_in = [s.rstrip() for s in request.POST.get("importSubdomainTextArea", "").split() if s]
        subdomains_out = [s.rstrip() for s in request.POST.get("outOfScopeSubdomainTextarea", "").split() if s]
        paths = request.POST.get("filterPath", "").split()
        url_filter = paths[0].rstrip() if paths else ""

        kwargs_stored = {k: v for k, v in secator_kwargs.items() if k != "scan_history_id"}
        if url_filter:
            kwargs_stored["url_filter"] = url_filter
        timestr = datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S")
        mode_label = secator_kwargs.get("execution_mode", "secator")
        task_name = f"Secator {mode_label} for {target.value}: {timestr}"
        common = _build_scan_schedule_common(
            task_name,
            target,
            request.user,
            subdomains_in,
            subdomains_out,
            secator_kwargs=kwargs_stored,
        )

        if scheduled_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC:
            frequency_value, frequency_type = _normalize_periodic_frequency_from_post(request.POST)
            next_run = ScanSchedule.compute_next_run_from_frequency(timezone.now(), frequency_value, frequency_type)
            ScanSchedule.objects.create(
                **common,
                schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
                frequency_value=frequency_value,
                frequency_type=frequency_type,
                next_run=next_run,
                one_off=False,
            )
        else:
            schedule_time = request.POST.get("scheduled_time", "").strip()
            timezone_offset = max(-1440, min(1440, safe_int_cast(request.POST.get("timezone_offset", 0), 0)))
            utc_time = _parse_scheduled_time_utc(schedule_time, timezone_offset)
            if utc_time is None:
                messages.error(request, "Invalid date and time for the one-time scan.")
                return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(target))
            ScanSchedule.objects.create(
                **common,
                schedule_mode=ScanSchedule.SCHEDULE_MODE_CLOCKED,
                scheduled_time=utc_time,
                next_run=utc_time,
                one_off=True,
            )
        messages.add_message(request, messages.INFO, f"Scan scheduled for {target.value}")
        return HttpResponseRedirect(reverse("scheduled_scan_view", kwargs={"slug": slug}))

    return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(target))


def scheduled_scan_view(request, slug):
    scheduled_tasks = ScanSchedule.objects.all()
    context = {
        "scheduled_scan_active": "active",
        "scheduled_tasks": scheduled_tasks,
    }
    return render(request, "startScan/schedule_scan_list.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_task(request, slug, id):
    task_object = get_object_or_404(ScanSchedule, id=id)
    if request.method == "POST":
        task_object.delete()
        message_data = {"status": "true"}
        messages.add_message(request, messages.INFO, "Scheduled Scan successfully deleted!")
    else:
        message_data = {"status": "false"}
        messages.add_message(request, messages.INFO, "Oops! something went wrong!")
    return JsonResponse(message_data)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def change_scheduled_task_status(request, slug, id):
    if request.method == "POST":
        task = ScanSchedule.objects.get(id=id)
        task.enabled = not task.enabled
        task.save()
    return HttpResponse("")


def change_vuln_status(request, slug, id):
    if request.method == "POST":
        vuln = Vulnerability.objects.get(id=id)
        vuln.open_status = not vuln.open_status
        vuln.save()
    return HttpResponse("")


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_scan_results(request, slug):
    if request.method == "POST":
        ScanHistory.objects.filter(target__project__slug=slug).delete()
        message_data = {"status": "true"}
        messages.add_message(request, messages.INFO, "All Scan History successfully deleted!")
    return JsonResponse(message_data)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request, slug):
    if request.method == "POST":
        domains = Domain.objects.filter(scan_history__target__project__slug=slug)
        cleanup_issues = False
        for domain in domains:
            resolved = resolve_results_dir_under_base(RENGINE_RESULTS, domain.name)
            if resolved is not None and resolved.is_dir():
                result = safe_rmtree(RENGINE_RESULTS, resolved)
                if result == "refused":
                    logger.log_line(
                        PREFIX_SCAN,
                        "BULK_CLEANUP",
                        "Bulk results dir cleanup refused for domain %s at path %s; "
                        "likely configuration or permission issue. project_slug=%s" % (domain.name, resolved, slug),
                        level="warning",
                    )
                    cleanup_issues = True
                elif result == "failed":
                    logger.log_line(
                        PREFIX_SCAN,
                        "BULK_CLEANUP",
                        "Bulk results dir cleanup failed for domain %s at path %s; "
                        "transient or unexpected error. project_slug=%s" % (domain.name, resolved, slug),
                        level="warning",
                    )
                    cleanup_issues = True
                elif result != "removed":
                    logger.log_line(
                        PREFIX_SCAN,
                        "BULK_CLEANUP",
                        "Bulk results dir cleanup returned %s for domain %s at path %s. project_slug=%s"
                        % (result, domain.name, resolved, slug),
                        level="warning",
                    )
                    cleanup_issues = True
        message_data = {"status": "true"}
        if cleanup_issues:
            messages.add_message(
                request,
                messages.WARNING,
                "Screenshots deletion completed, but some result directories could not be fully cleaned up. "
                "This may indicate a configuration or permission issue; please contact an administrator.",
            )
        else:
            messages.add_message(request, messages.INFO, "Screenshots successfully deleted!")
    return JsonResponse(message_data)


def visualise(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        "scan_id": id,
        "scan_history": scan,
    }
    return render(request, "startScan/visualise.html", context)


QUICK_SCAN_TARGET_COLLAPSE_THRESHOLD = 15


def _run_quick_scan_for_targets(
    request,
    target_list,
    entity_name: str,
    redirect_view_name: str,
    redirect_kwargs: dict,
    form_redirect_view_name: str,
    form_redirect_kwargs: dict,
    *,
    scope=None,
):
    """
    Run quick scan for each target in target_list. Used by start_organization_scan and start_scope_scan.

    On full or partial success (at least one scan started), redirects to redirect_view_name.
    When all scans fail (scan_count == 0 and failed_count > 0), shows an error and redirects back
    to the form (form_redirect_view_name). Raises ValueError if build_start_secator_scan_kwargs fails.
    """
    secator_kwargs = build_start_secator_scan_kwargs(request.POST, scope=scope)
    scan_count = 0
    failed_count = 0
    skipped_no_tasks: list[str] = []
    execution_mode = secator_kwargs.get("execution_mode")
    for target in target_list:
        kwargs_for_target = dict(secator_kwargs)
        filtered_override = filter_targets_override_for_target(
            target.value, kwargs_for_target.get("targets_override")
        )
        if filtered_override is not None:
            kwargs_for_target["targets_override"] = filtered_override
        else:
            kwargs_for_target.pop("targets_override", None)
        filtered_per_task = filter_selected_targets_per_task_for_target(
            target.value, kwargs_for_target.get("selected_targets_per_task")
        )
        if filtered_per_task is not None:
            kwargs_for_target["selected_targets_per_task"] = filtered_per_task
        else:
            kwargs_for_target.pop("selected_targets_per_task", None)
        if execution_mode == "tasks" and "selected_targets_per_task" not in kwargs_for_target:
            skipped_no_tasks.append(target.value)
            continue
        sc, fc = _run_secator_scan_or_per_task(request, target.id, kwargs_for_target)
        scan_count += sc
        failed_count += fc

    if skipped_no_tasks:
        messages.warning(
            request,
            "No scan started for target(s) %s: no selected proposed targets matched these targets."
            % (", ".join(skipped_no_tasks),),
        )
    if scan_count == 0 and failed_count > 0:
        messages.error(
            request,
            "No quick scans could be started for the selected targets. "
            "Please review your selection and scan configuration, then try again.",
        )
        return redirect(form_redirect_view_name, **form_redirect_kwargs)

    if scan_count > 0:
        messages.add_message(request, messages.INFO, f"Started {scan_count} scans for {entity_name}")
    if failed_count > 0:
        messages.add_message(
            request,
            messages.WARNING,
            f"Started {scan_count} scan(s), but {failed_count} scan(s) failed to start.",
        )
    return HttpResponseRedirect(reverse(redirect_view_name, kwargs=redirect_kwargs))


def _quick_scan_form_context(target_list, scan_type: str, *, scope=None, organization=None):
    """
    Build common context for quick scan form (organization or scope). Returns dict with
    target_list, target_ids, scan_type, secator_scans, secator_workers, and build_scan_params_form_context keys.
    """
    target_list = list(target_list)
    target_ids = ",".join(str(t.id) for t in target_list)
    form_ctx = build_scan_params_form_context(scope=scope, organization=organization)
    secator_scans = SecatorScan.objects.filter(scan_type=scan_type, is_active=True)
    secator_workers = get_workers_for_scan_dropdown(scope=scope)
    return {
        "target_list": target_list,
        "target_ids": target_ids,
        "scan_type": scan_type,
        "secator_scans": secator_scans,
        "secator_workers": secator_workers,
        **form_ctx,
    }


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_organization_scan(request, id, slug):
    organization = get_object_or_404(Organization, id=id)

    if request.GET.get("ajax") == "true":
        return render_secator_selection_json(request)

    if request.method == "POST":
        target_list = list(organization.get_targets())
        if not target_list:
            messages.warning(
                request,
                "No targets to scan. Add targets to one or more scopes of this organization, "
                "or attach legacy targets to the organization.",
            )
            return redirect("start_organization_scan", slug=slug, id=id)
        try:
            return _run_quick_scan_for_targets(
                request,
                target_list,
                f"organization {organization.name}",
                "scan_history",
                {"slug": slug},
                "start_organization_scan",
                {"slug": slug, "id": id},
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("start_organization_scan", slug=slug, id=id)

    scan_type = request.GET.get("scan_type", "internet")
    target_list = list(organization.get_targets())
    context = _quick_scan_form_context(target_list, scan_type, organization=organization)
    context["organization_data_active"] = "true"
    context["list_organization_li"] = "active"
    context["organization"] = organization
    context["quick_scan_entity_label"] = "organization"
    context["quick_scan_entity_name"] = organization.name
    context["quick_scan_id_prefix"] = "start_org_scan"
    context["quick_scan_scan_params_level"] = "organization"
    context["quick_scan_scan_params_organization_id"] = organization.id
    context["quick_scan_scan_params_scope_id"] = ""
    context["quick_scan_target_collapse_threshold"] = QUICK_SCAN_TARGET_COLLAPSE_THRESHOLD
    context["quick_scan_extra_target_count"] = max(0, len(target_list) - QUICK_SCAN_TARGET_COLLAPSE_THRESHOLD)
    return render(request, "organization/start_scan.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_scope_scan(request, id, slug):
    scope = get_object_or_404(Scope, id=id, organization__project__slug=slug)

    if request.GET.get("ajax") == "true":
        return render_secator_selection_json(request)

    if request.method == "POST":
        target_list = list(scope.targets.all())
        if not target_list:
            messages.warning(request, "No targets to scan for this scope.")
            return redirect("start_scope_scan", slug=slug, id=id)
        try:
            return _run_quick_scan_for_targets(
                request,
                target_list,
                f"scope {scope.name}",
                "scan_history",
                {"slug": slug},
                "start_scope_scan",
                {"slug": slug, "id": id},
                scope=scope,
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("start_scope_scan", slug=slug, id=id)

    scan_type = request.GET.get("scan_type", "internet")
    target_list = list(scope.targets.all())
    context = _quick_scan_form_context(target_list, scan_type, scope=scope)
    context["scope"] = scope
    context["quick_scan_entity_label"] = "scope"
    context["quick_scan_entity_name"] = scope.name
    context["quick_scan_id_prefix"] = "start_scope_scan"
    context["quick_scan_scan_params_level"] = "scope"
    context["quick_scan_scan_params_organization_id"] = scope.organization_id
    context["quick_scan_scan_params_scope_id"] = scope.id
    context["quick_scan_target_collapse_threshold"] = QUICK_SCAN_TARGET_COLLAPSE_THRESHOLD
    context["quick_scan_extra_target_count"] = max(0, len(target_list) - QUICK_SCAN_TARGET_COLLAPSE_THRESHOLD)
    return render(request, "scope/start_scan.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_organization_scan(request, slug, id):
    organization = Organization.objects.get(id=id)
    if request.method == "POST":
        schedule_error, scheduled_mode = _validate_schedule_form_post(request.POST)
        if schedule_error:
            messages.error(request, schedule_error)
            return render(
                request,
                "organization/schedule_scan_ui.html",
                _schedule_organization_scan_ui_context(organization),
            )

        engine_type = int(request.POST["scan_mode"])
        engine = get_object_or_404(EngineType, id=engine_type)
        targets = list(organization.get_targets())
        if not targets:
            messages.error(
                request,
                "No targets to schedule. Add targets to one or more scopes of this organization, "
                "or attach legacy targets to the organization.",
            )
            return render(
                request,
                "organization/schedule_scan_ui.html",
                _schedule_organization_scan_ui_context(organization),
            )
        for target in targets:
            timestr = str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
            task_name = f"{engine.engine_name} for {target.value}: {timestr}"
            common = _build_scan_schedule_common(
                task_name,
                target,
                request.user,
                [],
                [],
                scan_type=engine,
            )

            if scheduled_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC:
                frequency_value, frequency_type = _normalize_periodic_frequency_from_post(request.POST)
                next_run = ScanSchedule.compute_next_run_from_frequency(timezone.now(), frequency_value, frequency_type)
                ScanSchedule.objects.create(
                    **common,
                    schedule_mode=ScanSchedule.SCHEDULE_MODE_PERIODIC,
                    frequency_value=frequency_value,
                    frequency_type=frequency_type,
                    next_run=next_run,
                    one_off=False,
                )
            else:
                schedule_time_str = request.POST.get("scheduled_time", "").strip()
                timezone_offset = max(-1440, min(1440, safe_int_cast(request.POST.get("timezone_offset", 0), 0)))
                schedule_time = _parse_scheduled_time_utc(schedule_time_str, timezone_offset)
                if schedule_time is None:
                    messages.error(
                        request,
                        "Invalid date and time for the one-time scan. Please enter a valid date and time.",
                    )
                    return render(
                        request,
                        "organization/schedule_scan_ui.html",
                        _schedule_organization_scan_ui_context(organization),
                    )
                ScanSchedule.objects.create(
                    **common,
                    schedule_mode=ScanSchedule.SCHEDULE_MODE_CLOCKED,
                    scheduled_time=schedule_time,
                    next_run=schedule_time,
                    one_off=True,
                )

        messages.add_message(
            request, messages.INFO, f"Scan started for {len(targets)} targets in organization {organization.name}"
        )
        return HttpResponseRedirect(reverse("scheduled_scan_view", kwargs={"slug": slug}))

    # GET request
    return render(
        request,
        "organization/schedule_scan_ui.html",
        _schedule_organization_scan_ui_context(organization),
    )


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scans(request, slug):
    if request.method == "POST":
        cleanup_issues = False
        for key, value in request.POST.items():
            if key == "scan_history_table_length" or key == "csrfmiddlewaretoken":
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            delete_dir = scan.results_dir
            # resolve_results_dir_under_base returns None when results_dir is missing/invalid;
            # we intentionally no-op in that case (no filesystem delete) for safety.
            resolved = resolve_results_dir_under_base(RENGINE_RESULTS, delete_dir or "")
            if resolved is not None:
                result = safe_rmtree(RENGINE_RESULTS, resolved)
                if result == "refused":
                    logger.log_line(
                        PREFIX_SCAN,
                        "DELETE_SCANS",
                        "Results dir cleanup refused for path %s; likely configuration or permission issue. "
                        "scan_history_id=%s base_dir=%r" % (resolved, getattr(scan, "id", None), RENGINE_RESULTS),
                        level="warning",
                    )
                    cleanup_issues = True
                elif result == "failed":
                    logger.log_line(
                        PREFIX_SCAN,
                        "DELETE_SCANS",
                        "Results dir cleanup failed for path %s; transient or unexpected error. "
                        "scan_history_id=%s base_dir=%r" % (resolved, getattr(scan, "id", None), RENGINE_RESULTS),
                        level="warning",
                    )
                    cleanup_issues = True
                elif result != "removed":
                    logger.log_line(
                        PREFIX_SCAN,
                        "DELETE_SCANS",
                        "Results dir cleanup returned %s for path %s. scan_history_id=%s base_dir=%r"
                        % (result, resolved, getattr(scan, "id", None), RENGINE_RESULTS),
                        level="warning",
                    )
                    cleanup_issues = True
            elif delete_dir:
                logger.log_line(
                    PREFIX_SCAN,
                    "DELETE_SCANS",
                    "results_dir resolution failed; not deleting directory. "
                    "scan_history_id=%s results_dir=%r base_dir=%r"
                    % (getattr(scan, "id", None), delete_dir, RENGINE_RESULTS),
                    level="warning",
                )
                cleanup_issues = True
            scan.delete()
        if cleanup_issues:
            messages.add_message(
                request,
                messages.WARNING,
                "All scans deleted, but some result directories could not be fully cleaned up. "
                "This may indicate a configuration or permission issue; please contact an administrator.",
            )
        else:
            messages.add_message(request, messages.INFO, "All Scans deleted!")
    return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def customize_report(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        "scan_id": id,
        "scan_history": scan,
    }
    return render(request, "startScan/customize_report.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def create_report(request, slug, id):
    primary_color = "#FFB74D"
    secondary_color = "#212121"
    # get report type
    report_type = request.GET["report_type"] if "report_type" in request.GET else "full"
    is_ignore_info_vuln = True if "ignore_info_vuln" in request.GET else False
    if report_type == "recon":
        show_recon = True
        show_vuln = False
        report_name = "Reconnaissance Report"
    elif report_type == "vulnerability":
        show_recon = False
        show_vuln = True
        report_name = "Vulnerability Report"
    else:
        # default
        show_recon = True
        show_vuln = True
        report_name = "Full Scan Report"

    scan = ScanHistory.objects.get(id=id)
    vulns = (
        (Vulnerability.objects.filter(scan_history=scan).order_by("-severity"))
        if not is_ignore_info_vuln
        else (Vulnerability.objects.filter(scan_history=scan).exclude(severity=0).order_by("-severity"))
    )
    unique_vulns = (
        (
            Vulnerability.objects.filter(scan_history=scan)
            .values("name", "severity")
            .annotate(count=Count("name"))
            .order_by("-severity", "-count")
        )
        if not is_ignore_info_vuln
        else (
            Vulnerability.objects.filter(scan_history=scan)
            .exclude(severity=0)
            .values("name", "severity")
            .annotate(count=Count("name"))
            .order_by("-severity", "-count")
        )
    )

    subdomains = Subdomain.objects.filter(scan_history=scan).order_by("-content_length")
    subdomain_alive_count = (
        Subdomain.objects.filter(scan_history__id=id).values("name").distinct().filter(http_status__gt=0).count()
    )
    interesting_subdomains = get_interesting_subdomains(scan_history=id)
    ip_addresses = (
        IpAddress.objects.filter(ip_addresses__in=subdomains)
        .prefetch_related(
            "ports",
        )
        .distinct()
    )

    data = {
        "scan_object": scan,
        "unique_vulnerabilities": unique_vulns,
        "all_vulnerabilities": vulns,
        "all_vulnerabilities_count": vulns.count(),
        "subdomain_alive_count": subdomain_alive_count,
        "interesting_subdomains": interesting_subdomains,
        "subdomains": subdomains,
        "ip_addresses": ip_addresses,
        "ip_addresses_count": ip_addresses.count(),
        "show_recon": show_recon,
        "show_vuln": show_vuln,
        "report_name": report_name,
        "is_ignore_info_vuln": is_ignore_info_vuln,
    }

    # Get report related config
    vuln_report_query = VulnerabilityReportSetting.objects.all()
    if vuln_report_query.exists():
        report = vuln_report_query[0]
        data["company_name"] = report.company_name
        data["company_address"] = report.company_address
        data["company_email"] = report.company_email
        data["company_website"] = report.company_website
        data["show_rengine_banner"] = report.show_rengine_banner
        data["show_footer"] = report.show_footer
        data["footer_text"] = report.footer_text
        data["show_executive_summary"] = report.show_executive_summary

        # Replace executive_summary_description with template syntax
        description = report.executive_summary_description
        description = description.replace("{scan_date}", scan.start_scan_date.strftime("%d %B, %Y"))
        description = description.replace("{company_name}", report.company_name)
        target_name = scan.target.value if scan.target_id else ""
        target_description = getattr(scan.target, "description", None) or "" if scan.target_id else ""
        description = description.replace("{target_name}", target_name)
        description = description.replace("{subdomain_count}", str(subdomains.count()))
        description = description.replace("{vulnerability_count}", str(vulns.count()))
        description = description.replace("{critical_count}", str(vulns.filter(severity=4).count()))
        description = description.replace("{high_count}", str(vulns.filter(severity=3).count()))
        description = description.replace("{medium_count}", str(vulns.filter(severity=2).count()))
        description = description.replace("{low_count}", str(vulns.filter(severity=1).count()))
        description = description.replace("{info_count}", str(vulns.filter(severity=0).count()))
        description = description.replace("{unknown_count}", str(vulns.filter(severity=-1).count()))
        if target_description:
            description = description.replace("{target_description}", target_description)

        # Convert to Markdown
        data["executive_summary_description"] = markdown.markdown(description)

        primary_color = report.primary_color
        secondary_color = report.secondary_color

    data["primary_color"] = primary_color
    data["secondary_color"] = secondary_color

    # Configure WeasyPrint with the necessary CSS styles
    css = CSS(
        string="""
        /* General styles */
        body { font-family: Arial, sans-serif; }

        /* Styles for markdown */
        h1, h2, h3, h4 { margin-top: 1em; }
        ul, ol { margin-left: 2em; }
        pre, code {
            background-color: #f5f5f5;
            padding: 0.2em 0.4em;
            border-radius: 3px;
        }

        /* Styles for tables */
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
    """
    )

    # Convert markdown to HTML for PDF rendering (AI reports store content as markdown)
    for vuln in data["all_vulnerabilities"]:
        if vuln.description:
            vuln.description = mark_safe(convert_markdown_to_html(vuln.description))
        if vuln.impact:
            vuln.impact = mark_safe(convert_markdown_to_html(vuln.impact))
        if vuln.remediation:
            vuln.remediation = mark_safe(convert_markdown_to_html(vuln.remediation))
        if vuln.references:
            vuln.references_display = mark_safe(convert_markdown_to_html(vuln.references))
        else:
            vuln.references_display = ""
        # Note: parse_references in template uses raw vuln.references for URL list; references_display for fallback text

    template = get_template("report/template.html")
    html = template.render(data)

    # Generate the PDF with the CSS styles
    pdf = HTML(string=html).write_pdf(stylesheets=[css], presentational_hints=True)

    if "download" in request.GET:
        response = HttpResponse(pdf, content_type="application/octet-stream")
    else:
        response = HttpResponse(pdf, content_type="application/pdf")

    return response
