from collections import defaultdict
from datetime import datetime
import json

from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Case, Count, F, IntegerField, Q, Value, When
from django.db.models.functions import Coalesce, Lower
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone
from django.utils.html import mark_safe
import markdown
from rolepermissions.decorators import has_permission_decorator
from weasyprint import CSS, HTML

from api.serializers import IpSerializer
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
from reNgine.secator.service import run_per_task_secator_scans, start_secator_scan
from reNgine.services.repositories import EndpointRepository
from reNgine.settings import RENGINE_RESULTS
from reNgine.utilities.db import count_subquery
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.subdomain import get_interesting_subdomains
from reNgine.utilities.time import local_to_utc_aware
from scanEngine.models import (
    EngineType,
    SecatorScan,
    SecatorWorker,
    VulnerabilityReportSetting,
)
from startScan.models import (
    Command,
    CountryISO,
    CveId,
    CweId,
    Email,
    Employee,
    EndPoint,
    IpAddress,
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
from targetApp.models import Domain, Organization


PREFIX_SCAN = "[STARTSCAN]"
logger = get_module_logger(__name__)


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


def _run_secator_scan_or_per_task(
    request,
    domain_id: int,
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
    if selected_targets_per_task and kwargs_copy.get("execution_mode") == "tasks":
        result = run_per_task_secator_scans(
            domain_id=domain_id,
            user_id=request.user.id,
            selected_targets_per_task=selected_targets_per_task,
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
                "Per-task validation errors for domain_id=%s: %s"
                % (domain_id, [e["task_type"] for e in result["validation_errors"]]),
                level="warning",
            )
        return result["success_count"], result["failed_count"]

    result = start_secator_scan(
        domain_id=domain_id,
        user_id=request.user.id,
        imported_subdomains=imported_subdomains or [],
        out_of_scope_subdomains=out_of_scope_subdomains or [],
        url_filter=url_filter,
        scan_history_id=scan_history_id,
        **kwargs_copy,
    )
    return (1, 0) if result.get("status") else (0, 1)


def _start_secator_scans_for_domain_ids(request, domain_ids: list[int], secator_kwargs: dict) -> tuple[int, int]:
    scan_count = 0
    failed_count = 0
    for domain_id in domain_ids:
        sc, fc = _run_secator_scan_or_per_task(request, domain_id, secator_kwargs)
        scan_count += sc
        failed_count += fc
    return scan_count, failed_count


def _schedule_scan_ui_context(domain: Domain) -> dict:
    """Build context for schedule_scan_ui.html (single domain)."""
    context = {
        "scan_history_active": "active",
        "domain": domain,
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
    domain: Domain,
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
        "domain": domain,
        "scan_type": scan_type,
        "secator_kwargs": secator_kwargs,
        "initiated_by": initiated_by,
        "imported_subdomains": imported_subdomains,
        "out_of_scope_subdomains": out_of_scope_subdomains,
        "enabled": True,
    }


def _build_multiple_scan_selection_from_post(request) -> tuple[list[str], str]:
    list_of_domain_name: list[str] = []
    list_of_domain_id: list[str] = []

    ignored_keys = {
        "list_target_table_length",
        "csrfmiddlewaretoken",
    }
    for key, value in request.POST.items():
        if key in ignored_keys:
            continue
        domain_id = safe_int_cast(value)
        if domain_id is None:
            messages.warning(request, f"Ignoring invalid domain ID: {value!r}")
            continue
        domain = get_object_or_404(Domain, id=domain_id)
        list_of_domain_name.append(domain.name)
        list_of_domain_id.append(str(domain_id))

    domain_ids = ",".join(list_of_domain_id)
    return list_of_domain_name, domain_ids


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
        ScanHistory.objects.filter(domain__project__slug=slug)
        .order_by("-start_scan_date")
        .select_related("domain", "initiated_by", "scan_type")
        .prefetch_related(
            "secatorrunner_set__worker",
            "domain__domains",
        )
        .annotate(
            # Scalar count subqueries avoid cartesian products vs Count(distinct=...) over joins.
            subdomain_count=count_subquery(Subdomain, "scan_history_id"),
            endpoint_count=count_subquery(EndPoint, "scan_history_id"),
            vuln_count=count_subquery(Vulnerability, "scan_history_id"),
            vuln_critical_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 4}),
            vuln_high_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 3}),
            vuln_medium_count=count_subquery(Vulnerability, "scan_history_id", filter_kwargs={"severity": 2}),
        )
    )

    context = {
        "scan_history_active": "active",
        "scan_history": host,
    }
    return render(request, "startScan/history.html", context)


def subscan_history(request, slug):
    subscans = (
        SubScan.objects.filter(scan_history__domain__project__slug=slug)
        .select_related("secator_runner__worker", "scan_history")
        .prefetch_related("scan_history__secatorrunner_set__worker")
        .order_by("-start_scan_date")
    )
    context = {"scan_history_active": "active", "subscans": subscans}
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
            scan_history__domain__project__slug=slug,
        )
    else:
        queryset = Command.objects.filter(
            activity__id=activity_id,
            activity__scan_of__domain__project__slug=slug,
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

    # Get scan objects (prefetch runners+worker; select_related domain to avoid N+1 for history.domain)
    scan = get_object_or_404(
        ScanHistory.objects.select_related("domain").prefetch_related("secatorrunner_set__worker"),
        id=id,
    )
    domain_id = safe_int_cast(scan.domain.id)
    scan_engines = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    recent_scans = ScanHistory.objects.filter(domain__id=domain_id)
    last_scans = (
        ScanHistory.objects.filter(domain__id=domain_id)
        .filter(tasks__overlap=["subdomain_discovery"])
        .filter(id__lte=id)
        .filter(scan_status=2)
    )

    # Get all kind of objects associated with our ScanHistory object
    emails = Email.objects.filter(emails__in=[scan])
    employees = Employee.objects.filter(employees__in=[scan])
    subdomains = Subdomain.objects.filter(scan_history=scan)
    endpoints = EndPoint.objects.filter(scan_history=scan)

    # Optimize vulnerability queries with prefetch_related to avoid N+1 queries
    vulns = Vulnerability.objects.filter(scan_history=scan).prefetch_related(
        "cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "target_domain", "scan_history"
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
            "target_id": domain_id,
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

    # Build render context
    ctx = {
        "scan_history_id": id,
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
    ctx["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")

    return render(request, "startScan/detail_scan.html", ctx)


def all_subdomains(request, slug):
    subdomains = Subdomain.objects.filter(target_domain__project__slug=slug)
    scan_engines = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    alive_subdomains = subdomains.filter(http_status__gt=0)  # TODO: replace this with is_alive() function
    important_subdomains = subdomains.filter(is_important=True).values("name").distinct().count()
    context = {
        "scan_history_id": id,
        "scan_history_active": "active",
        "scan_engines": scan_engines,
        "subdomain_count": subdomains.values("name").distinct().count(),
        "alive_count": alive_subdomains.values("name").distinct().count(),
        "important_count": important_subdomains,
    }
    context.update(build_secator_profiles_context())
    context["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")
    return render(request, "startScan/subdomains.html", context)


def detail_vuln_scan(request, slug, id=None):
    if id:
        history = get_object_or_404(ScanHistory, id=id)
        context = {"scan_history_id": id, "history": history}
    else:
        context = {"vuln_scan_active": "true"}
    return render(request, "startScan/vulnerabilities.html", context)


def all_endpoints(request, slug):
    context = {"scan_history_active": "active"}
    return render(request, "startScan/endpoints.html", context)


def start_scan_ui(request, slug, domain_id):
    domain = get_object_or_404(Domain, id=domain_id)
    if request.method == "POST":
        # Collect all parameters from form
        subdomains_in = request.POST.get("importSubdomainTextArea", "").split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST.get("outOfScopeSubdomainTextarea", "").split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        paths = request.POST.get("filterPath", "").split()
        filter_path = paths[0].rstrip() if paths else ""

        try:
            secator_kwargs = build_start_secator_scan_kwargs(request.POST)
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("start_scan", slug=slug, domain_id=domain_id)

        scan_count, failed_count = _run_secator_scan_or_per_task(
            request,
            domain.id,
            secator_kwargs,
            imported_subdomains=subdomains_in,
            out_of_scope_subdomains=subdomains_out,
            url_filter=filter_path,
        )

        if scan_count >= 1:
            messages.add_message(request, messages.INFO, f"Scan Started for {domain.name}")
            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))
        error_msg = "Unknown error" if failed_count else "No scan started"
        messages.add_message(request, messages.ERROR, f"Failed to start scan: {error_msg}")
        return HttpResponseRedirect(reverse("start_scan", kwargs={"slug": slug, "domain_id": domain_id}))

    # GET request
    # Get engines based on scan type (default to bug_bounty for backward compatibility)
    scan_type = request.GET.get("scan_type", "internet")

    # Get engines based on scan type
    engine = (
        EngineType.objects.filter(scan_type=scan_type).annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    )

    # Get custom engine count in a single query
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()

    # Check if domain has IP addresses or subdomains (indicating internal network scan)
    has_ip_content = False
    if domain.ip_address_cidr:
        has_ip_content = True
    else:
        # Check if domain has subdomains with IP addresses
        from startScan.models import Subdomain

        subdomains_with_ips = Subdomain.objects.filter(target_domain=domain, ip_addresses__isnull=False).exists()
        has_ip_content = subdomains_with_ips

    # Handle AJAX requests
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        # Handle Secator AJAX requests
        if request.GET.get("ajax") == "true":
            return render_secator_selection_json(request)

        # Handle request for engine loading (legacy)
        from django.template.loader import render_to_string

        engine_html = render_to_string(
            "startScan/_items/scanEngine_select.html",
            {
                "engines": engine,
                "custom_engine_count": custom_engine_count,
            },
        )
        return JsonResponse({"engine_html": engine_html})

    context = {
        "scan_history_active": "active",
        "domain": domain,
        "engines": engine,
        "custom_engine_count": custom_engine_count,
        "scan_type": scan_type,
        "has_ip_content": has_ip_content,
    }
    context.update(build_secator_profiles_context())
    context["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")
    return render(request, "startScan/start_scan_ui.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    if request.GET.get("ajax") == "true":
        return render_secator_selection_json(request)

    list_of_domain_name: list[str] = []
    domain_ids = ""

    if request.method == "POST":
        if request.POST.get("list_of_domain_id"):
            # POST from start_multiple_scan_ui: start scans for selected domains
            try:
                secator_kwargs = build_start_secator_scan_kwargs(request.POST)
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect("start_multiple_scan", slug=slug)

            domain_id_list, invalid_domain_ids = _parse_domain_id_list(request.POST.get("list_of_domain_id", ""))
            if invalid_domain_ids:
                messages.warning(request, f"Ignoring invalid domain ID(s): {', '.join(invalid_domain_ids)}")

            if not domain_id_list:
                messages.error(request, "Please select at least one valid target.")
                return redirect("start_multiple_scan", slug=slug)

            scan_count, failed_count = _start_secator_scans_for_domain_ids(request, domain_id_list, secator_kwargs)

            if scan_count > 0:
                messages.add_message(request, messages.INFO, f"Started {scan_count} scans for multiple targets")
            if failed_count > 0:
                messages.add_message(request, messages.WARNING, f"Failed to start {failed_count} scans")

            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))

        # POST from targets list: build selection list and render UI
        list_of_domain_name, domain_ids = _build_multiple_scan_selection_from_post(request)

    # GET request
    scan_type = request.GET.get("scan_type", "internet")

    # Get engines based on scan type
    engines = EngineType.objects.filter(scan_type=scan_type)

    # Get custom engine count in a single query
    custom_engine_count = engines.filter(default_engine=False).count()
    context = {
        "scan_history_active": "active",
        "engines": engines,
        "domain_list": list_of_domain_name,
        "domain_ids": domain_ids,
        "custom_engine_count": custom_engine_count,
        "scan_type": scan_type,
    }
    context.update(build_secator_profiles_context())
    context["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")
    return render(request, "startScan/start_multiple_scan_ui.html", context)


def export_subdomains(request, slug, scan_id):
    subdomain_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for domain in subdomain_list:
        response_body += response_body + domain.name + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="subdomains_{domain_name}_{scan_start_date_str}.txt"'
    return response


def export_endpoints(request, slug, scan_id):
    endpoint_list = EndPoint.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for endpoint in endpoint_list:
        response_body += endpoint.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="endpoints_{domain_name}_{scan_start_date_str}.txt"'
    return response


def export_urls(request, slug, scan_id):
    urls_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for url in urls_list:
        if url.http_url:
            response_body += response_body + url.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
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
    if request.method == "POST":
        try:
            secator_kwargs = build_start_secator_scan_kwargs(request.POST)
        except ValueError as exc:
            messages.error(request, str(exc))
            return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(domain))

        schedule_error, scheduled_mode = _validate_schedule_form_post(request.POST)
        if schedule_error:
            messages.error(request, schedule_error)
            return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(domain))

        subdomains_in = [s.rstrip() for s in request.POST.get("importSubdomainTextArea", "").split() if s]
        subdomains_out = [s.rstrip() for s in request.POST.get("outOfScopeSubdomainTextarea", "").split() if s]
        paths = request.POST.get("filterPath", "").split()
        url_filter = paths[0].rstrip() if paths else ""

        kwargs_stored = {k: v for k, v in secator_kwargs.items() if k != "scan_history_id"}
        if url_filter:
            kwargs_stored["url_filter"] = url_filter
        timestr = datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S")
        mode_label = secator_kwargs.get("execution_mode", "secator")
        task_name = f"Secator {mode_label} for {domain.name}: {timestr}"
        common = _build_scan_schedule_common(
            task_name,
            domain,
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
                return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(domain))
            ScanSchedule.objects.create(
                **common,
                schedule_mode=ScanSchedule.SCHEDULE_MODE_CLOCKED,
                scheduled_time=utc_time,
                next_run=utc_time,
                one_off=True,
            )
        messages.add_message(request, messages.INFO, f"Scan scheduled for {domain.name}")
        return HttpResponseRedirect(reverse("scheduled_scan_view", kwargs={"slug": slug}))

    return render(request, "startScan/schedule_scan_ui.html", _schedule_scan_ui_context(domain))


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
        ScanHistory.objects.filter(domain__project__slug=slug).delete()
        message_data = {"status": "true"}
        messages.add_message(request, messages.INFO, "All Scan History successfully deleted!")
    return JsonResponse(message_data)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request, slug):
    if request.method == "POST":
        domains = Domain.objects.filter(project__slug=slug)
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


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_organization_scan(request, id, slug):
    organization = get_object_or_404(Organization, id=id)

    # Handle AJAX request for dynamic loading
    if request.GET.get("ajax") == "true":
        return render_secator_selection_json(request)

    if request.method == "POST":
        # Collect parameters (same logic as start_scan_ui)
        try:
            secator_kwargs = build_start_secator_scan_kwargs(request.POST)
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("start_organization_scan", slug=slug, id=id)

        domain_list = organization.get_domains()
        scan_count = 0
        failed_count = 0
        for domain in domain_list:
            sc, fc = _run_secator_scan_or_per_task(request, domain.id, secator_kwargs)
            scan_count += sc
            failed_count += fc

        if scan_count > 0:
            messages.add_message(
                request, messages.INFO, f"Started {scan_count} scans for organization {organization.name}"
            )
        if failed_count > 0:
            messages.add_message(request, messages.WARNING, f"Failed to start {failed_count} scans")

        return HttpResponseRedirect(reverse("list_organization", kwargs={"slug": slug}))

    # GET request
    scan_type = request.GET.get("scan_type", "internet")

    # No longer use old EngineType, only for backward compatibility
    # New scans use only Secator
    secator_scans = SecatorScan.objects.filter(scan_type=scan_type, is_active=True)

    # Optimize domain list query
    domain_list = organization.get_domains().select_related()

    context = {
        "organization_data_active": "true",
        "list_organization_li": "active",
        "organization": organization,
        "domain_list": domain_list,
        "domain_ids": ",".join(str(d.id) for d in domain_list),
        "scan_type": scan_type,
        "secator_scans": secator_scans,
    }
    context.update(build_secator_profiles_context())
    context["secator_workers"] = SecatorWorker.objects.filter(is_active=True).order_by("name")
    return render(request, "organization/start_scan.html", context)


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
        for domain in organization.get_domains():
            timestr = str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
            task_name = f"{engine.engine_name} for {domain.name}: {timestr}"
            common = _build_scan_schedule_common(
                task_name,
                domain,
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

        ndomains = len(organization.get_domains())
        messages.add_message(
            request, messages.INFO, f"Scan started for {ndomains} domains in organization {organization.name}"
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
        description = description.replace("{target_name}", scan.domain.name)
        description = description.replace("{subdomain_count}", str(subdomains.count()))
        description = description.replace("{vulnerability_count}", str(vulns.count()))
        description = description.replace("{critical_count}", str(vulns.filter(severity=4).count()))
        description = description.replace("{high_count}", str(vulns.filter(severity=3).count()))
        description = description.replace("{medium_count}", str(vulns.filter(severity=2).count()))
        description = description.replace("{low_count}", str(vulns.filter(severity=1).count()))
        description = description.replace("{info_count}", str(vulns.filter(severity=0).count()))
        description = description.replace("{unknown_count}", str(vulns.filter(severity=-1).count()))
        if scan.domain.description:
            description = description.replace("{target_description}", scan.domain.description)

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

    # Preprocess HTML/Markdown fields
    for vuln in data["all_vulnerabilities"]:
        if vuln.description:
            vuln.description = mark_safe(vuln.description)
        if vuln.impact:
            vuln.impact = mark_safe(vuln.impact)
        if vuln.remediation:
            vuln.remediation = mark_safe(vuln.remediation)
        # Note: references are now handled by the parse_references template filter

    template = get_template("report/template.html")
    html = template.render(data)

    # Generate the PDF with the CSS styles
    pdf = HTML(string=html).write_pdf(stylesheets=[css], presentational_hints=True)

    if "download" in request.GET:
        response = HttpResponse(pdf, content_type="application/octet-stream")
    else:
        response = HttpResponse(pdf, content_type="application/pdf")

    return response
