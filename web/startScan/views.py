from datetime import datetime
import json
from pathlib import Path

from celery import group
from celery.utils.log import get_task_logger
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
from django_celery_beat.models import ClockedSchedule, IntervalSchedule, PeriodicTask
import markdown
from rolepermissions.decorators import has_permission_decorator
from weasyprint import CSS, HTML

from api.serializers import IpSerializer
from reNgine.core.data import safe_int_cast
from reNgine.definitions import (
    FOUR_OH_FOUR_URL,
    PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_SCAN_REPORT,
    PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    SCHEDULED_SCAN,
)
from reNgine.services.repositories.scan_repository import ScanRepository
from reNgine.settings import RENGINE_RESULTS
from reNgine.tasks import initiate_secator_scan
from reNgine.utilities.command import run_command
from reNgine.utilities.subdomain import get_interesting_subdomains
from reNgine.utilities.time import local_to_utc_aware
from scanEngine.models import EngineType, SecatorScan, SecatorTask, SecatorWorkflow, VulnerabilityReportSetting
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
    SecatorRunner,
    Subdomain,
    SubScan,
    Vulnerability,
    VulnerabilityTags,
)
from targetApp.models import Domain, Organization


logger = get_task_logger(__name__)


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
    host = ScanHistory.objects.filter(domain__project__slug=slug).order_by("-start_scan_date")

    # Preload scan_type and SecatorRunner to avoid N+1 queries when accessing scan_name
    host = host.select_related("scan_type").prefetch_related("secatorrunner_set")

    context = {
        "scan_history_active": "active",
        "scan_history": host,
    }
    return render(request, "startScan/history.html", context)


def subscan_history(request, slug):
    subscans = SubScan.objects.filter(scan_history__domain__project__slug=slug).order_by("-start_scan_date")
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
            activity__scan_history__domain__project__slug=slug,
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

    # Get scan objects
    scan = get_object_or_404(ScanHistory, id=id)
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
        "cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "target_domain"
    )

    vulns_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulns)
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct("address")
    ip_serializer = IpSerializer(ip_addresses.all(), many=True, context={"scan_id": id, "target_id": domain_id})
    geo_isos = CountryISO.objects.filter(ipaddress__in=ip_addresses)
    scan_activity = ScanActivity.objects.filter(scan_of__id=id).order_by("time")
    cves = CveId.objects.filter(cve_ids__in=vulns)
    cwes = CweId.objects.filter(cwe_ids__in=vulns)

    # HTTP statuses
    http_statuses = subdomains.exclude(http_status=0).values("http_status").annotate(Count("http_status"))

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

    # Vulnerabilities
    common_vulns = (
        vulns.exclude(severity=0).values("name", "severity").annotate(count=Count("name")).order_by("-count")[:10]
    )
    info_count = vulns.filter(severity=0).count()
    low_count = vulns.filter(severity=1).count()
    medium_count = vulns.filter(severity=2).count()
    high_count = vulns.filter(severity=3).count()
    critical_count = vulns.filter(severity=4).count()
    unknown_count = vulns.filter(severity=-1).count()
    total_count = vulns.count()
    total_count_ignore_info = vulns.exclude(severity=0).count()

    # Emails
    exposed_count = emails.exclude(password__isnull=True).count()

    # Preload SecatorRunner for this scan
    secator_runners = SecatorRunner.objects.filter(scan_history=scan).order_by("-created_at")
    is_secator_scan = secator_runners.exists()

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
        "http_status_breakdown": http_statuses,
        "most_common_cve": common_cves,
        "most_common_cwe": common_cwes,
        "most_common_tags": common_tags,
        "most_common_vulnerability": common_vulns,
        "asset_countries": asset_countries,
    }

    # Find number of matched GF patterns
    if scan.used_gf_patterns:
        count_gf = {}
        for gf in scan.used_gf_patterns.split(","):
            count_gf[gf] = endpoints.filter(matched_gf_patterns__icontains=gf).count()
            ctx["matched_gf_count"] = count_gf

    # Find last scan for this domain
    if last_scans.count() > 1:
        last_scan = last_scans.order_by("-start_scan_date")[1]
        ctx["last_scan"] = last_scan

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

        execution_mode = request.POST.get("execution_mode")
        scan_existing_elements = request.POST.get("scan_existing_elements") == "true"

        secator_config = {
            "proxy": request.POST.get("proxy", ""),
            "rate_limit": max(1, min(10000, safe_int_cast(request.POST.get("rate_limit", 150), 150))),
            "threads": max(1, min(1000, safe_int_cast(request.POST.get("threads", 20), 20))),
            "timeout": max(1, min(3600, safe_int_cast(request.POST.get("timeout", 300), 300))),
            "delay": max(0, min(60, safe_int_cast(request.POST.get("delay", 0), 0))),
        }

        speed_profile = request.POST.get("speed_profile")
        stealth_profile = request.POST.get("stealth_profile")
        expert_mode = request.POST.get("expert_mode") in ["true", "on", "1", True]

        # Prepare API payload
        api_data = {
            "domain_id": domain.id,
            "execution_mode": execution_mode,
            "imported_subdomains": subdomains_in,
            "out_of_scope_subdomains": subdomains_out,
            "url_filter": filter_path,
            "scan_existing_elements": scan_existing_elements,
            "secator_config": secator_config,
            "speed_profile": speed_profile,
            "stealth_profile": stealth_profile,
            "expert_mode": expert_mode,
        }

        # Add mode-specific parameters
        if execution_mode == "workflow":
            workflow_id = request.POST.get("workflow_id")
            if not workflow_id:
                messages.error(request, "Please select a workflow.")
                return redirect("start_scan", slug=slug, domain_id=domain_id)
            api_data["workflow_id"] = safe_int_cast(workflow_id)
        elif execution_mode == "tasks":
            task_ids = request.POST.getlist("task_ids")
            if not task_ids:
                messages.error(request, "Please select at least one task.")
                return redirect("start_scan", slug=slug, domain_id=domain_id)
            api_data["task_ids"] = [int(tid) for tid in task_ids]
        elif execution_mode == "scan":
            secator_scan_type = request.POST.get("secator_scan_type")
            if not secator_scan_type:
                messages.error(request, "Please select a scan type.")
                return redirect("start_scan", slug=slug, domain_id=domain_id)
            api_data["secator_scan_type"] = secator_scan_type
        else:
            messages.error(request, "Please select an execution mode.")
            return redirect("start_scan", slug=slug, domain_id=domain_id)

        # Use common scan initiation logic
        from reNgine.tasks.scan import start_secator_scan

        result = start_secator_scan(
            domain_id=domain.id,
            execution_mode=execution_mode,
            user_id=request.user.id,
            workflow_id=api_data.get("workflow_id") if execution_mode == "workflow" else None,
            task_ids=api_data.get("task_ids") if execution_mode == "tasks" else None,
            secator_scan_type=api_data.get("secator_scan_type") if execution_mode == "scan" else None,
            imported_subdomains=api_data["imported_subdomains"],
            out_of_scope_subdomains=api_data["out_of_scope_subdomains"],
            url_filter=api_data["url_filter"],
            scan_existing_elements=api_data["scan_existing_elements"],
            secator_config=api_data["secator_config"],
            speed_profile=api_data["speed_profile"],
            stealth_profile=api_data["stealth_profile"],
            expert_mode=api_data["expert_mode"],
            scan_type="internet",
        )

        # Check result
        if result.get("status") == "success":
            response_status = 200
            response_data = {"status": True, "scan_id": result.get("scan_id")}
        else:
            response_status = 400
            response_data = {"status": False, "error": result.get("error", "Unknown error")}

        if response_status == 200 and response_data.get("status"):
            messages.add_message(request, messages.INFO, f"Scan Started for {domain.name}")
            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))
        else:
            error_msg = response_data.get("error", "Unknown error")
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
        # Handle request for existing elements count
        if request.GET.get("get_elements_count"):
            from startScan.models import Subdomain

            # Get all subdomains for this domain
            subdomains = Subdomain.objects.filter(target_domain=domain)

            # Use the extended get_counts method
            counts = Subdomain.get_counts(subdomains)

            return JsonResponse({"hostname_count": counts["hostnames"], "ip_count": counts["ip_addresses"]})

        # Handle Secator AJAX requests
        if request.GET.get("ajax") == "true":
            from django.template.loader import render_to_string

            execution_mode = request.GET.get("execution_mode")

            context = {}
            if execution_mode == "workflow":
                # Optimize query: only fetch needed fields and prefetch related data
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
                # Pre-fetch all tasks once to avoid N+1 queries in template tags
                all_tasks = SecatorTask.objects.filter(is_active=True).only(
                    "task_type",
                    "name",
                    "category",
                    "description",
                )
                # Convert to dict for O(1) lookup in template tags
                tasks_dict = {task.task_type: task for task in all_tasks}

                # Pre-compute expensive operations (YAML parsing) to avoid repeated parsing in template
                # Cache is now handled at model level, but we still pre-compute for template efficiency
                # Convert queryset to list to avoid multiple DB hits
                workflows_list = list(workflows_queryset)

                # Pre-compute in parallel using list comprehension (faster than loop)
                for workflow in workflows_list:
                    # These calls now use cache at model level, but we still attach to avoid re-calls in template
                    workflow._precomputed_structured_tasks = workflow.get_structured_tasks()
                    workflow._precomputed_tasks_count = workflow.get_tasks_count()

                context["workflows"] = workflows_list
                context["all_tasks"] = all_tasks
                context["tasks_dict"] = tasks_dict
                template = "startScan/_items/secator_workflow_select.html"
            elif execution_mode == "tasks":
                tasks = (
                    SecatorTask.objects.filter(is_active=True)
                    .only("id", "name", "task_type", "category", "description")
                    .order_by("category", "name")
                )
                context["tasks"] = tasks
                template = "startScan/_items/secator_task_select.html"
            elif execution_mode == "scan":
                context["scan_types"] = [
                    (scan.name, scan.description)
                    for scan in SecatorScan.objects.filter(scan_config_type="builtin", is_active=True).order_by("name")
                ]
                template = "startScan/_items/secator_scan_select.html"
            else:
                return JsonResponse({"html": '<div class="alert alert-warning">Invalid execution mode</div>'})

            html = render_to_string(template, context, request=request)
            return JsonResponse({"html": html})

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
    return render(request, "startScan/start_scan_ui.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    if request.method == "POST":
        if request.POST.get("scan_mode", 0):
            # if scan mode is available, then start the scan
            # get engine type and scan type
            engine_id = safe_int_cast(request.POST["scan_mode"])
            scan_type = request.POST.get("scan_type", "internet")
            list_of_domains = request.POST["list_of_domain_id"]

            # Get scan existing elements option
            scan_existing_elements = request.POST.get("scan_existing_elements") == "true"

            grouped_scans = []

            for domain_id in list_of_domains.split(","):
                # Start the celery task
                scan_repo = ScanRepository()
                scan_history_id = scan_repo.create_scan(
                    host_id=domain_id, engine_id=engine_id, initiated_by_id=request.user.id
                )
                # domain = get_object_or_404(Domain, id=domain_id)

                kwargs = {
                    "scan_history_id": scan_history_id,
                    "domain_id": domain_id,
                    "engine_id": engine_id,
                    "initiated_by_id": request.user.id,
                    "scan_existing_elements": scan_existing_elements,
                    # TODO: Add this to multiple scan view
                    # 'imported_subdomains': subdomains_in,
                    # 'out_of_scope_subdomains': subdomains_out
                }

                _scan_task = initiate_secator_scan.si(**kwargs)
                grouped_scans.append(_scan_task)

            celery_group = group(grouped_scans)
            celery_group.apply_async()

            # Send start notif
            messages.add_message(request, messages.INFO, "Scan Started for multiple targets")

            return HttpResponseRedirect(reverse("scan_history", kwargs={"slug": slug}))

        else:
            # this else condition will have post request from the scan page
            # containing all the targets id
            list_of_domain_name = []
            list_of_domain_id = []
            for key, value in request.POST.items():
                if key not in [
                    "list_target_table_length",
                    "csrfmiddlewaretoken",
                ]:
                    domain = get_object_or_404(Domain, id=value)
                    list_of_domain_name.append(domain.name)
                    list_of_domain_id.append(value)
            domain_ids = ",".join(list_of_domain_id)

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
        run_command("rm -rf " + delete_dir)
        obj.delete()
        message_data = {"status": "true"}
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
            logger.error(e)
            response = {"status": False}
            messages.add_message(request, messages.ERROR, f"Scan failed to stop ! Error: {str(e)}")
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_scan(request, host_id, slug):
    domain = Domain.objects.get(id=host_id)
    if request.method == "POST":
        scheduled_mode = request.POST["scheduled_mode"]
        engine_type = int(request.POST["scan_mode"])

        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST["importSubdomainTextArea"].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST["outOfScopeSubdomainTextarea"].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]

        # Get engine type
        engine = get_object_or_404(EngineType, id=engine_type)
        timestr = str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
        task_name = f"{engine.engine_name} for {domain.name}: {timestr}"
        if scheduled_mode == "periodic":
            frequency_value = int(request.POST["frequency"])
            frequency_type = request.POST["frequency_type"]
            if frequency_type == "minutes":
                period = IntervalSchedule.MINUTES
            elif frequency_type == "hours":
                period = IntervalSchedule.HOURS
            elif frequency_type == "days":
                period = IntervalSchedule.DAYS
            elif frequency_type == "weeks":
                period = IntervalSchedule.DAYS
                frequency_value *= 7
            elif frequency_type == "months":
                period = IntervalSchedule.DAYS
                frequency_value *= 30
            schedule, _ = IntervalSchedule.objects.get_or_create(every=frequency_value, period=period)
            kwargs = {
                "domain_id": host_id,
                "engine_id": engine.id,
                "scan_history_id": 1,
                "scan_type": SCHEDULED_SCAN,
                "imported_subdomains": subdomains_in,
                "out_of_scope_subdomains": subdomains_out,
                "initiated_by_id": request.user.id,
            }
            PeriodicTask.objects.create(
                interval=schedule, name=task_name, task="initiate_secator_scan", kwargs=json.dumps(kwargs)
            )
        elif scheduled_mode == "clocked":
            schedule_time = request.POST["scheduled_time"]
            timezone_offset = max(-1440, min(1440, safe_int_cast(request.POST.get("timezone_offset", 0), 0)))
            # Convert received hour in UTC
            local_time = datetime.strptime(schedule_time, "%Y-%m-%d %H:%M")
            # Convert local time to UTC-aware datetime
            utc_time = local_to_utc_aware(local_time, timezone_offset)
            clock, _ = ClockedSchedule.objects.get_or_create(clocked_time=utc_time)
            kwargs = {
                "scan_history_id": 0,
                "domain_id": host_id,
                "engine_id": engine.id,
                "scan_type": SCHEDULED_SCAN,
                "imported_subdomains": subdomains_in,
                "out_of_scope_subdomains": subdomains_out,
                "initiated_by_id": request.user.id,
            }
            PeriodicTask.objects.create(
                clocked=clock, one_off=True, name=task_name, task="initiate_secator_scan", kwargs=json.dumps(kwargs)
            )
        messages.add_message(request, messages.INFO, f"Scan Scheduled for {domain.name}")
        return HttpResponseRedirect(reverse("scheduled_scan_view", kwargs={"slug": slug}))

    # GET request
    engines = EngineType.objects
    custom_engine_count = engines.filter(default_engine=False).count()
    context = {
        "scan_history_active": "active",
        "domain": domain,
        "engines": engines,
        "custom_engine_count": custom_engine_count,
    }
    return render(request, "startScan/schedule_scan_ui.html", context)


def scheduled_scan_view(request, slug):
    scheduled_tasks = PeriodicTask.objects.all().exclude(name="celery.backend_cleanup")
    context = {
        "scheduled_scan_active": "active",
        "scheduled_tasks": scheduled_tasks,
    }
    return render(request, "startScan/schedule_scan_list.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_task(request, slug, id):
    task_object = get_object_or_404(PeriodicTask, id=id)
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
        task = PeriodicTask.objects.get(id=id)
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
        ScanHistory.objects.filter(project__slug=slug).delete()
        message_data = {"status": "true"}
        messages.add_message(request, messages.INFO, "All Scan History successfully deleted!")
    return JsonResponse(message_data)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request, slug):
    if request.method == "POST":
        domains = Domain.objects.filter(project__slug=slug)
        for domain in domains:
            run_command(f"rm -rf {str(Path(RENGINE_RESULTS) / domain.name)}")
        message_data = {"status": "true"}
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
        from django.template.loader import render_to_string

        execution_mode = request.GET.get("execution_mode")

        context = {}
        if execution_mode == "workflow":
            # Optimize query: only fetch needed fields and prefetch related data
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
            # Pre-fetch all tasks once to avoid N+1 queries in template tags
            all_tasks = SecatorTask.objects.filter(is_active=True).only(
                "task_type",
                "name",
                "category",
                "description",
            )
            # Convert to dict for O(1) lookup in template tags
            tasks_dict = {task.task_type: task for task in all_tasks}

            # Pre-compute expensive operations (YAML parsing) to avoid repeated parsing in template
            # Cache is now handled at model level, but we still pre-compute for template efficiency
            # Convert queryset to list to avoid multiple DB hits
            workflows_list = list(workflows_queryset)

            # Pre-compute in parallel using list comprehension (faster than loop)
            for workflow in workflows_list:
                # These calls now use cache at model level, but we still attach to avoid re-calls in template
                workflow._precomputed_structured_tasks = workflow.get_structured_tasks()
                workflow._precomputed_tasks_count = workflow.get_tasks_count()

            context["workflows"] = workflows_list
            context["all_tasks"] = all_tasks
            context["tasks_dict"] = tasks_dict
            template = "startScan/_items/secator_workflow_select.html"
        elif execution_mode == "tasks":
            tasks = (
                SecatorTask.objects.filter(is_active=True)
                .only("id", "name", "task_type", "category", "description")
                .order_by("category", "name")
            )
            context["tasks"] = tasks
            template = "startScan/_items/secator_task_select.html"
        elif execution_mode == "scan":
            context["scan_types"] = [
                (scan.name, scan.description)
                for scan in SecatorScan.objects.filter(scan_config_type="builtin", is_active=True).order_by("name")
            ]
            template = "startScan/_items/secator_scan_select.html"
        else:
            return JsonResponse({"html": '<div class="alert alert-warning">Invalid execution mode</div>'})

        html = render_to_string(template, context, request=request)
        return JsonResponse({"html": html})

    if request.method == "POST":
        # Collect parameters (même logique que start_scan_ui)
        execution_mode = request.POST.get("execution_mode")
        scan_existing_elements = request.POST.get("scan_existing_elements") == "true"

        secator_config = {
            "proxy": request.POST.get("proxy", ""),
            "rate_limit": max(1, min(10000, safe_int_cast(request.POST.get("rate_limit", 150), 150))),
            "threads": max(1, min(1000, safe_int_cast(request.POST.get("threads", 20), 20))),
            "timeout": max(1, min(3600, safe_int_cast(request.POST.get("timeout", 300), 300))),
            "delay": max(0, min(60, safe_int_cast(request.POST.get("delay", 0), 0))),
        }

        speed_profile = request.POST.get("speed_profile")
        stealth_profile = request.POST.get("stealth_profile")
        expert_mode = request.POST.get("expert_mode") == "true"

        domain_list = organization.get_domains()
        scan_count = 0
        failed_count = 0

        for domain in domain_list:
            # Prepare API payload for each domain
            api_data = {
                "domain_id": domain.id,
                "execution_mode": execution_mode,
                "scan_existing_elements": scan_existing_elements,
                "secator_config": secator_config,
                "speed_profile": speed_profile,
                "stealth_profile": stealth_profile,
                "expert_mode": expert_mode,
            }

            # Add mode-specific parameters
            if execution_mode == "workflow":
                api_data["workflow_id"] = safe_int_cast(request.POST.get("workflow_id"))
            elif execution_mode == "tasks":
                api_data["task_ids"] = [int(tid) for tid in request.POST.getlist("task_ids")]
            elif execution_mode == "scan":
                api_data["secator_scan_type"] = request.POST.get("secator_scan_type")

            # Call API
            import json

            from django.http import HttpRequest
            from rest_framework.request import Request

            from api.views import StartScan

            api_view = StartScan()
            mock_request = HttpRequest()
            mock_request.method = "POST"
            mock_request.user = request.user
            mock_request._body = json.dumps(api_data).encode()
            mock_request.content_type = "application/json"
            api_request = Request(mock_request)
            api_request._data = api_data

            response = api_view.post(api_request)

            if response.status_code == 200 and response.data.get("status"):
                scan_count += 1
            else:
                failed_count += 1
                logger.error(f"Failed to start scan for {domain.name}: {response.data.get('error')}")

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
    return render(request, "organization/start_scan.html", context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_organization_scan(request, slug, id):
    organization = Organization.objects.get(id=id)
    if request.method == "POST":
        engine_type = int(request.POST["scan_mode"])
        engine = get_object_or_404(EngineType, id=engine_type)
        scheduled_mode = request.POST["scheduled_mode"]
        for domain in organization.get_domains():
            timestr = str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
            task_name = f"{engine.engine_name} for {domain.name}: {timestr}"

            # Period task
            if scheduled_mode == "periodic":
                frequency_value = int(request.POST["frequency"])
                frequency_type = request.POST["frequency_type"]
                if frequency_type == "minutes":
                    period = IntervalSchedule.MINUTES
                elif frequency_type == "hours":
                    period = IntervalSchedule.HOURS
                elif frequency_type == "days":
                    period = IntervalSchedule.DAYS
                elif frequency_type == "weeks":
                    period = IntervalSchedule.DAYS
                    frequency_value *= 7
                elif frequency_type == "months":
                    period = IntervalSchedule.DAYS
                    frequency_value *= 30

                schedule, _ = IntervalSchedule.objects.get_or_create(every=frequency_value, period=period)
                _kwargs = json.dumps(
                    {
                        "domain_id": domain.id,
                        "engine_id": engine.id,
                        "scan_history_id": 0,
                        "scan_type": SCHEDULED_SCAN,
                        "imported_subdomains": None,
                        "initiated_by_id": request.user.id,
                    }
                )
                PeriodicTask.objects.create(
                    interval=schedule, name=task_name, task="initiate_secator_scan", kwargs=_kwargs
                )

            # Clocked task
            elif scheduled_mode == "clocked":
                schedule_time = request.POST["scheduled_time"]
                clock, _ = ClockedSchedule.objects.get_or_create(clocked_time=schedule_time)
                _kwargs = json.dumps(
                    {
                        "domain_id": domain.id,
                        "engine_id": engine.id,
                        "scan_history_id": 0,
                        "imported_subdomains": None,
                        "initiated_by_id": request.user.id,
                    }
                )
                PeriodicTask.objects.create(
                    clocked=clock, one_off=True, name=task_name, task="initiate_secator_scan", kwargs=_kwargs
                )

        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request, messages.INFO, f"Scan started for {ndomains} domains in organization {organization.name}"
        )
        return HttpResponseRedirect(reverse("scheduled_scan_view", kwargs={"slug": slug}))

    # GET request
    engine = EngineType.objects.annotate(lower_name=Lower("engine_name")).order_by("lower_name")
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    context = {
        "scan_history_active": "active",
        "organization": organization,
        "domain_list": organization.get_domains(),
        "engines": engine,
        "custom_engine_count": custom_engine_count,
    }
    return render(request, "organization/schedule_scan_ui.html", context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key == "scan_history_table_length" or key == "csrfmiddlewaretoken":
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            delete_dir = scan.results_dir
            run_command("rm -rf " + delete_dir)
            scan.delete()
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
