import csv
from datetime import datetime, timedelta
import io
import ipaddress
import json
from pathlib import Path

from django import http
from django.conf import settings
from django.contrib import messages
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import Case, Count, IntegerField, Value, When
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST
from rolepermissions.checkers import has_role
from rolepermissions.decorators import has_permission_decorator
import validators

from api.helpers.datatables import (
    TABLE_ID_ORGANIZATION_LIST,
    TABLE_ID_SCOPE_LIST,
    TABLE_ID_TARGET_LIST,
    get_datatable_row_group_config,
    get_datatable_table_config,
)
from api.serializers import IpSerializer
from dashboard.models import Project
from reNgine.core.data import get_ips_from_cidr_range
from reNgine.core.path import resolve_results_dir_under_base, safe_rmtree
from reNgine.core.validators import is_valid_cidr
from reNgine.definitions import (
    FOUR_OH_FOUR_URL,
    PERM_MODIFY_TARGETS,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_RUNNING_BACKGROUND,
)
from reNgine.services.repositories import EndpointRepository
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.request import get_string_from_post_or_json
from scanEngine.models import EngineType
from startScan.models import (
    CountryISO,
    CveId,
    CweId,
    Domain,
    Email,
    Employee,
    EndPoint,
    IpAddress,
    ScanHistory,
    Subdomain,
    Vulnerability,
    VulnerabilityTags,
)
from startScan.secator.form import parse_secator_profiles_to_dict
from startScan.secator.profiles import build_secator_profiles_context
from targetApp.constants import (
    RENGINE_TARGET_TYPES_FOR_JS,
    SCOPE_TYPE_CHOICES,
    TARGET_TYPE_CIDR_RANGE,
    TARGET_TYPE_FILENAME,
    TARGET_TYPE_HOST,
    TARGET_TYPE_IP,
    TARGET_TYPE_ORG_NAME,
    TARGET_TYPE_SLUG,
    TARGET_TYPE_STR,
    TARGET_TYPE_URL,
    TARGET_TYPE_USERNAME,
)
from targetApp.forms import (
    AddOrganizationForm,
    AddTargetForm,
    ScopeForm,
    UpdateOrganizationForm,
    UpdateTargetModelForm,
)
from targetApp.models import TARGET_TYPE_CHOICES, Organization, Scope, Target
from targetApp.services.organization_dashboard import get_organization_dashboard_data
from targetApp.services.scan_param_definitions import TARGET_OVERRIDE_PREFIX
from targetApp.services.scan_params_context import build_scan_params_form_context
from targetApp.services.scope_normalizer import parse_scope_raw_input
from targetApp.services.scope_params import (
    _normalize_scan_config,
    build_effective_params_display,
    get_allowed_workers_for_scope,
    get_default_worker_for_scope,
    get_scope_for_target,
    get_workers_for_scan_dropdown,
    parse_scan_config_from_post,
    scope_allow_local,
    strip_empty_override_keys,
)
from targetApp.services.target_update import (
    build_update_target_context,
    process_target_scan_override_from_post,
)


PREFIX_TARGET = "[TARGET]"
logger = get_module_logger(__name__)

# Target types that can be added via the single-value form (Target only, no Domain).
ADD_SINGLE_TARGET_TYPES = {
    TARGET_TYPE_CIDR_RANGE,
    TARGET_TYPE_FILENAME,
    TARGET_TYPE_ORG_NAME,
    TARGET_TYPE_SLUG,
    TARGET_TYPE_STR,
    TARGET_TYPE_URL,
    TARGET_TYPE_USERNAME,
}

# Specs for the 7 "simple" add-target tabs (single value input). Used to render tab panes via a shared partial.
ADD_TARGET_SIMPLE_TAB_SPECS = [
    {
        "tab_id": "cidr-tab",
        "label": "CIDR",
        "target_type_key": TARGET_TYPE_CIDR_RANGE,
        "alert": "Add an IP range in CIDR notation (e.g. 192.168.1.0/24). Only a Target is created; use scans to discover hosts.",
        "input_label": "CIDR range",
        "input_id": "cidr_value",
        "input_type": "text",
        "placeholder": "192.168.1.0/24",
        "secator_hint": "scan_names",
        "secator_hint_label": "scans",
    },
    {
        "tab_id": "url-tab",
        "label": "URL",
        "target_type_key": TARGET_TYPE_URL,
        "alert": "Add a single URL (e.g. https://example.com/path). Only a Target is created.",
        "input_label": "URL",
        "input_id": "url_value",
        "input_type": "url",
        "placeholder": "https://example.com",
        "secator_hint": "scan_names",
        "secator_hint_label": "scans",
    },
    {
        "tab_id": "organization-tab",
        "label": "Organization",
        "target_type_key": TARGET_TYPE_ORG_NAME,
        "alert": "Add an organization name as target (e.g. for OSINT or scope). Only a Target is created.",
        "input_label": "Organization name",
        "input_id": "org_value",
        "input_type": "text",
        "placeholder": "Acme Corp",
        "secator_hint": "workflow_names",
        "secator_hint_label": "workflows",
    },
    {
        "tab_id": "username-tab",
        "label": "Username",
        "target_type_key": TARGET_TYPE_USERNAME,
        "alert": "Add a username as target (e.g. for credential or social checks). Only a Target is created.",
        "input_label": "Username",
        "input_id": "username_value",
        "input_type": "text",
        "placeholder": "j.doe",
        "secator_hint": "task_names",
        "secator_hint_label": "tasks",
    },
    {
        "tab_id": "filename-tab",
        "label": "Filename",
        "target_type_key": TARGET_TYPE_FILENAME,
        "alert": "Add a filename as target (e.g. for fuzzing or discovery). Only a Target is created.",
        "input_label": "Filename",
        "input_id": "filename_value",
        "input_type": "text",
        "placeholder": "config.json",
        "secator_hint": None,
        "secator_hint_label": None,
    },
    {
        "tab_id": "slug-tab",
        "label": "Slug",
        "target_type_key": TARGET_TYPE_SLUG,
        "alert": "Add a slug (URL-safe identifier). Only a Target is created.",
        "input_label": "Slug",
        "input_id": "slug_value",
        "input_type": "text",
        "placeholder": "my-target-slug",
        "secator_hint": None,
        "secator_hint_label": None,
    },
    {
        "tab_id": "string-tab",
        "label": "String",
        "target_type_key": TARGET_TYPE_STR,
        "alert": "Add a generic string target (e.g. for custom workflows or tasks). Only a Target is created.",
        "input_label": "Value",
        "input_id": "string_value",
        "input_type": "text",
        "placeholder": "Any string",
        "secator_hint": "workflow_names",
        "secator_hint_label": "workflows",
    },
]


def _build_add_target_simple_tabs(target_type_choices, secator_configs):
    """Build context list for simple add-target tab panes (single value per type)."""
    tabs = []
    for spec in ADD_TARGET_SIMPLE_TAB_SPECS:
        tab = {
            **spec,
            "target_type_value": target_type_choices.get(spec["target_type_key"], spec["target_type_key"]),
            "secator_names": (secator_configs.get(spec["secator_hint"], []) if spec.get("secator_hint") else []),
        }
        tabs.append(tab)
    return tabs


def _get_secator_configs_for_add_target():
    """Return Secator workflow, scan and task names for display on add target form. Safe if Secator unavailable."""
    try:
        from secator.loader import get_configs_by_type

        workflows = get_configs_by_type("workflow") or {}
        scans = get_configs_by_type("scan") or {}
        tasks = get_configs_by_type("task") or {}
        return {
            "workflow_names": list(workflows.keys())[:20],
            "scan_names": list(scans.keys())[:20],
            "task_names": list(tasks.keys())[:30],
        }
    except Exception:
        return {"workflow_names": [], "scan_names": [], "task_names": []}


def _get_or_create_target(project, value, target_type=TARGET_TYPE_HOST):
    """Get or create a Target for the given project and value. Returns (target, created)."""
    target, created = Target.objects.get_or_create(
        project=project,
        value=value,
        target_type=target_type,
        defaults={"insert_date": timezone.now()},
    )
    return target, created


def _apply_pending_normalizer_targets(scope, request):
    """
    If the request contains pending_normalizer_targets (JSON from scope normalizer Apply to form),
    create those targets in the scope's project and add them to the scope.
    """
    raw = request.POST.get("pending_normalizer_targets")
    if not raw or not raw.strip():
        return
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return
    domain_targets = data.get("domain_targets") or []
    ip_targets = data.get("ip_targets") or []
    if not domain_targets and not ip_targets:
        return
    project = scope.organization.project
    with transaction.atomic():
        for value in domain_targets:
            if value and isinstance(value, str) and value.strip():
                target, _ = _get_or_create_target(project, value.strip(), target_type=TARGET_TYPE_HOST)
                scope.targets.add(target)
        for value in ip_targets:
            if value and isinstance(value, str) and value.strip():
                target, _ = _get_or_create_target(project, value.strip(), target_type=TARGET_TYPE_IP)
                scope.targets.add(target)


def validate_dns_servers(dns_servers_string):
    """
    Validate a comma-separated string of DNS servers.

    Validates that each entry is either a valid IPv4 address, IPv6 address, or hostname.
    Supports optional port specification (e.g., 8.8.8.8:53).

    Args:
        dns_servers_string (str): Comma-separated DNS servers string

    Returns:
        tuple: (is_valid, error_message, cleaned_servers)
            - is_valid: Boolean indicating if validation passed
            - error_message: Error message if validation failed, None otherwise
            - cleaned_servers: Cleaned and validated DNS servers string

    Examples:
        >>> validate_dns_servers("8.8.8.8,1.1.1.1")
        (True, None, "8.8.8.8,1.1.1.1")

        >>> validate_dns_servers("8.8.8.8,invalid!@#,1.1.1.1")
        (False, "Invalid DNS server: invalid!@#", None)
    """
    if not dns_servers_string:
        return True, None, ""

    # Split by comma and clean up whitespace
    servers = [s.strip() for s in dns_servers_string.split(",") if s.strip()]

    if not servers:
        return True, None, ""

    validated_servers = []

    for server in servers:
        # Split address and port if port is specified
        if ":" in server and not server.count(":") > 1:  # IPv4 with port
            address, port = server.rsplit(":", 1)
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    return False, f"Invalid port number in DNS server: {server}", None
            except ValueError:
                return False, f"Invalid port in DNS server: {server}", None
        elif server.count(":") > 1:  # Likely IPv6
            # Handle IPv6 - could be with or without port
            # For simplicity, we'll treat it as full address for now
            address = server
        else:
            address = server

        # Validate the address part
        is_valid = False

        # Try IPv4
        try:
            ipaddress.IPv4Address(address)
            is_valid = True
        except (ipaddress.AddressValueError, ValueError):
            pass

        # Try IPv6 if IPv4 failed
        if not is_valid:
            try:
                ipaddress.IPv6Address(address)
                is_valid = True
            except (ipaddress.AddressValueError, ValueError):
                pass

        # Try hostname validation if IP validation failed
        if not is_valid and (validators.domain(address) or validators.ipv4(address) or validators.ipv6(address)):
            is_valid = True

        if not is_valid:
            return False, f"Invalid DNS server address: {server}", None

        validated_servers.append(server)

    # Return cleaned servers string
    cleaned = ",".join(validated_servers)
    return True, None, cleaned


def index(request):
    """
    index renders the index page for the target application. It returns the HTML template for the target index view, allowing users to access the main interface for managing targets.

    Args:
        request (HttpRequest): The HTTP request object containing metadata about the request.

    Returns:
        HttpResponse: The rendered HTML response for the target index page.
    """
    # TODO bring default target page
    return render(request, "target/index.html")


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def add_target(request, slug):
    """Add a new target. Targets can be URLs, IPs, CIDR ranges, or Domains.

    Args:
        request: Django request.
    """
    project = Project.objects.get(slug=slug)
    form = AddTargetForm(request.POST or None)
    if request.method == "POST":
        logger.log_line(
            PREFIX_TARGET,
            "ADD_TARGET",
            "POST data received: %s" % (dict(request.POST),),
            level="info",
        )
        total_processed_count = 0
        add_single_target = request.POST.get("add-single-target")
        target_type_single = request.POST.get("target_type", "").strip()
        multiple_targets = request.POST.get("add-multiple-targets")
        ip_target = request.POST.get("add-ip-target")
        try:
            # Single target by type (Target only, no Domain): CIDR, URL, Organization, Username, Filename, Slug, String
            if add_single_target and target_type_single in ADD_SINGLE_TARGET_TYPES:
                value = request.POST.get("target_value", "").strip()
                if not value:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Value is required.",
                    )
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                if target_type_single == TARGET_TYPE_CIDR_RANGE and not is_valid_cidr(value):
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Invalid CIDR range. Example: 192.168.1.0/24",
                    )
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                if target_type_single == TARGET_TYPE_URL and not validators.url(value):
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Invalid URL.",
                    )
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                description = request.POST.get("targetDescription", "") or None
                h1_team_handle = request.POST.get("targetH1TeamHandle") or None
                target, created = Target.objects.get_or_create(
                    project=project,
                    value=value,
                    target_type=target_type_single,
                    defaults={
                        "insert_date": timezone.now(),
                        "description": description,
                        "h1_team_handle": h1_team_handle,
                    },
                )
                if created:
                    logger.log_line(
                        PREFIX_TARGET,
                        "ADD_TARGET",
                        "Added target %s (%s)" % (value, target_type_single),
                        level="info",
                    )
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Target added successfully.",
                    )
                else:
                    messages.add_message(
                        request,
                        messages.INFO,
                        "Target already exists.",
                    )
                return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))

            # Multiple targets: only create Target entries (no Domain/startScan models)
            if multiple_targets:
                bulk_targets = [t.rstrip() for t in request.POST["addTargets"].split("\n") if t]
                logger.log_line(
                    PREFIX_TARGET,
                    "ADD_TARGET",
                    "Adding multiple targets: %s" % (bulk_targets,),
                    level="info",
                )
                description = request.POST.get("targetDescription", "")
                h1_team_handle = request.POST.get("targetH1TeamHandle")
                organization_name = request.POST.get("targetOrganization")
                created_targets = []
                for raw_value in bulk_targets:
                    raw_value = raw_value.rstrip("\n")
                    is_domain = bool(validators.domain(raw_value))
                    is_ip = bool(validators.ipv4(raw_value)) or bool(validators.ipv6(raw_value))
                    is_range = is_valid_cidr(raw_value)
                    is_url = bool(validators.url(raw_value))

                    if is_domain:
                        tgt, created = _get_or_create_target(project, raw_value, target_type=TARGET_TYPE_HOST)
                        if created:
                            if description or h1_team_handle:
                                tgt.description = description or tgt.description
                                tgt.h1_team_handle = h1_team_handle or tgt.h1_team_handle
                                tgt.save(update_fields=["description", "h1_team_handle"])
                            total_processed_count += 1
                            logger.log_line(
                                PREFIX_TARGET, "ADD_TARGET", "Added target %s (host)" % (raw_value,), level="info"
                            )
                        created_targets.append(tgt)

                    elif is_url:
                        tgt, created = _get_or_create_target(project, raw_value, target_type=TARGET_TYPE_URL)
                        if created:
                            if description or h1_team_handle:
                                tgt.description = description or tgt.description
                                tgt.h1_team_handle = h1_team_handle or tgt.h1_team_handle
                                tgt.save(update_fields=["description", "h1_team_handle"])
                            total_processed_count += 1
                            logger.log_line(
                                PREFIX_TARGET, "ADD_TARGET", "Added target %s (url)" % (raw_value,), level="info"
                            )
                        created_targets.append(tgt)

                    elif is_ip:
                        tgt, created = _get_or_create_target(project, raw_value, target_type=TARGET_TYPE_IP)
                        if created:
                            if description or h1_team_handle:
                                tgt.description = description or tgt.description
                                tgt.h1_team_handle = h1_team_handle or tgt.h1_team_handle
                                tgt.save(update_fields=["description", "h1_team_handle"])
                            total_processed_count += 1
                            logger.log_line(
                                PREFIX_TARGET, "ADD_TARGET", "Added target %s (ip)" % (raw_value,), level="info"
                            )
                        created_targets.append(tgt)

                    elif is_range:
                        for ip_address in get_ips_from_cidr_range(raw_value):
                            tgt, created = _get_or_create_target(project, ip_address, target_type=TARGET_TYPE_IP)
                            if created:
                                total_processed_count += 1
                            created_targets.append(tgt)
                        logger.log_line(
                            PREFIX_TARGET,
                            "ADD_TARGET",
                            "Added targets from CIDR %s" % (raw_value,),
                            level="info",
                        )
                    else:
                        msg = f"{raw_value} is not a valid domain, IP, or URL. Skipped."
                        logger.log_line(PREFIX_TARGET, "ADD_TARGET", msg, level="warning")
                        messages.add_message(request, messages.WARNING, msg)

                if organization_name and created_targets:
                    organization_obj, _ = Organization.objects.get_or_create(
                        name=organization_name,
                        project=project,
                        defaults={"insert_date": timezone.now()},
                    )
                    for tgt in created_targets:
                        if tgt.project_id != organization_obj.project_id:
                            logger.log_line(
                                PREFIX_TARGET,
                                "ADD_TARGET",
                                "Skipping organization association for target due to cross-project mismatch "
                                "(target_id=%s, target_project_id=%s, organization_id=%s, "
                                "organization_project_id=%s, organization_name=%s)"
                                % (
                                    tgt.id,
                                    tgt.project_id,
                                    organization_obj.id,
                                    organization_obj.project_id,
                                    organization_obj.name,
                                ),
                                level="warning",
                            )
                            continue
                        organization_obj.targets.add(tgt)

            # Import from txt / csv
            elif "import-txt-target" in request.POST or "import-csv-target" in request.POST:
                txt_file = request.FILES.get("txtFile")
                csv_file = request.FILES.get("csvFile")
                if not (txt_file or csv_file):
                    messages.add_message(request, messages.ERROR, "Files uploaded are not .txt or .csv files.")
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

                if (txt_file and txt_file.size == 0) or (csv_file and csv_file.size == 0):
                    messages.add_message(
                        request, messages.ERROR, "The uploaded file is empty. Please upload a valid file."
                    )
                    return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

                if txt_file:
                    is_txt = txt_file.content_type == "text/plain" or txt_file.name.split(".")[-1] == "txt"
                    if not is_txt:
                        messages.add_message(request, messages.ERROR, "File is not a valid TXT file")
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    txt_content = txt_file.read().decode("UTF-8")
                    io_string = io.StringIO(txt_content)
                    for line in io_string:
                        value = line.rstrip("\n").rstrip("\r")
                        if not value:
                            continue
                        if not validators.domain(value):
                            messages.add_message(
                                request,
                                messages.ERROR,
                                f"Domain {value} is not a valid domain name. Skipping.",
                            )
                            continue
                        tgt, created = _get_or_create_target(project, value, target_type=TARGET_TYPE_HOST)
                        if created:
                            total_processed_count += 1

                elif csv_file:
                    is_csv = csv_file.content_type == "text/csv" or csv_file.name.split(".")[-1] == "csv"
                    if not is_csv:
                        messages.add_message(request, messages.ERROR, "File is not a valid CSV file.")
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    csv_content = csv_file.read().decode("UTF-8")
                    io_string = io.StringIO(csv_content)
                    org_cache = {}
                    for column in csv.reader(io_string, delimiter=","):
                        value = column[0] if column else ""
                        if not value:
                            continue
                        if not validators.domain(value):
                            messages.add_message(
                                request,
                                messages.ERROR,
                                f"Domain {value} is not a valid domain name. Skipping.",
                            )
                            continue
                        description = None if len(column) <= 1 else column[1]
                        organization_name_csv = None if len(column) <= 2 else column[2]
                        tgt, created = _get_or_create_target(project, value, target_type=TARGET_TYPE_HOST)
                        if created:
                            if description:
                                tgt.description = description
                                tgt.save(update_fields=["description"])
                            total_processed_count += 1
                            if organization_name_csv:
                                if organization_name_csv not in org_cache:
                                    org_cache[organization_name_csv], _ = Organization.objects.get_or_create(
                                        name=organization_name_csv,
                                        project=project,
                                        defaults={"insert_date": timezone.now()},
                                    )
                                org_cache[organization_name_csv].targets.add(tgt)
            elif ip_target:
                import json

                from reNgine.utilities.url import get_domain_from_subdomain

                # Get selected items from the form
                discovered_domains = request.POST.getlist("discovered_domains")
                resolved_hosts_data = request.POST.getlist("resolved_hosts")

                target_name = request.POST.get("targetName", "").strip()
                description = request.POST.get("targetDescription", "")
                h1_team_handle = request.POST.get("targetH1TeamHandle")
                original_ip_range = request.POST.get("ip_address", "").strip()
                used_dns_servers = request.POST.get("used_dns_servers", "").strip()

                # Add single IP without DNS discovery (CIDR is only for DNS discovery, not for direct add)
                if original_ip_range and not discovered_domains and not resolved_hosts_data:
                    if "/" in original_ip_range:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            "CIDR is only supported for DNS discovery. Use a single IP address to add without discovery, or run DNS discovery first.",
                        )
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    if not (validators.ipv4(original_ip_range) or validators.ipv6(original_ip_range)):
                        messages.add_message(
                            request,
                            messages.ERROR,
                            "Invalid IP address.",
                        )
                        return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                    target_name = request.POST.get("targetName", "").strip()
                    description = request.POST.get("targetDescription", "") or None
                    h1_team_handle = request.POST.get("targetH1TeamHandle") or None
                    if used_dns_servers:
                        is_valid, error_msg, cleaned_dns = validate_dns_servers(used_dns_servers)
                        if not is_valid:
                            messages.add_message(request, messages.ERROR, f"Invalid DNS servers: {error_msg}")
                            return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))
                        used_dns_servers = cleaned_dns
                    tgt, created = _get_or_create_target(project, original_ip_range, target_type=TARGET_TYPE_IP)
                    if created:
                        description_text = description or (
                            f"IP target {original_ip_range}" + (f" ({target_name})" if target_name else "")
                        )
                        tgt.description = description_text
                        tgt.h1_team_handle = h1_team_handle
                        tgt.save(update_fields=["description", "h1_team_handle"])
                    total_processed_count = 1
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Added IP target without discovery: %s" % (original_ip_range,),
                        level="info",
                    )
                    messages.add_message(request, messages.SUCCESS, "Target added successfully.")
                    return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))

                # Validate DNS servers input for security
                if used_dns_servers:
                    is_valid, error_msg, cleaned_dns = validate_dns_servers(used_dns_servers)
                    if not is_valid:
                        messages.add_message(request, messages.ERROR, f"Invalid DNS servers configuration: {error_msg}")
                        logger.log_line(
                            PREFIX_TARGET,
                            "IP_SCAN",
                            "Invalid DNS servers submitted: %s - %s" % (used_dns_servers, error_msg),
                            level="warning",
                        )
                        context = {
                            "add_target_li": "active",
                            "target_data_active": "active",
                            "current_project": project,
                            "form": form,
                            "rengine_target_types": RENGINE_TARGET_TYPES_FOR_JS,
                            "secator_configs": _get_secator_configs_for_add_target(),
                            "target_type_choices": dict(TARGET_TYPE_CHOICES),
                            "override_prefix": TARGET_OVERRIDE_PREFIX,
                            "secator_workers": get_workers_for_scan_dropdown(),
                        }
                        context.update(build_scan_params_form_context(level="target"))
                        return render(request, "target/add.html", context)
                    used_dns_servers = cleaned_dns

                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Processing IP scan results for %s" % (original_ip_range,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Target name: %s" % (target_name,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Selected domains: %s" % (discovered_domains,),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "Selected hosts count: %s" % (len(resolved_hosts_data),),
                    level="info",
                )
                logger.log_line(
                    PREFIX_TARGET,
                    "IP_SCAN",
                    "DNS servers used: %s" % (used_dns_servers,),
                    level="info",
                )

                # Parse selected hosts to categorize them and deduplicate
                selected_domains = set()
                selected_hostnames = []
                selected_ips = []
                seen_hostnames = set()
                seen_ips = set()

                # Only create Target entries (no Domain/Subdomain); scans will populate startScan models
                if target_name:
                    tgt, created = _get_or_create_target(project, target_name, target_type=TARGET_TYPE_HOST)
                    if created:
                        tgt.description = description or ("Grouped target from %s" % original_ip_range)
                        tgt.h1_team_handle = h1_team_handle
                        tgt.save(update_fields=["description", "h1_team_handle"])
                        total_processed_count += 1
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Creating target(s) for %s selected hosts" % (len(resolved_hosts_data),),
                        level="info",
                    )
                    for host_data_json in resolved_hosts_data:
                        try:
                            host_info = json.loads(host_data_json.replace("&quot;", '"'))
                            ip = host_info.get("ip")
                            hostname = host_info.get("domain")
                            if hostname in seen_hostnames:
                                continue
                            seen_hostnames.add(hostname)
                            if hostname != ip and validators.domain(hostname):
                                _, created = _get_or_create_target(project, hostname, target_type=TARGET_TYPE_HOST)
                                if created:
                                    total_processed_count += 1
                            elif validators.ipv4(ip) or validators.ipv6(ip):
                                _, created = _get_or_create_target(project, ip, target_type=TARGET_TYPE_IP)
                                if created:
                                    total_processed_count += 1
                        except (json.JSONDecodeError, KeyError):
                            continue
                    for domain in discovered_domains:
                        if validators.domain(domain) and domain not in seen_hostnames:
                            _, created = _get_or_create_target(project, domain, target_type=TARGET_TYPE_HOST)
                            if created:
                                total_processed_count += 1
                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Grouped target processing complete.",
                        level="info",
                    )

                else:
                    # No target name: create one Target per selected domain/hostname/IP (no Domain/Subdomain)
                    for host_data_json in resolved_hosts_data:
                        try:
                            host_info = json.loads(host_data_json.replace("&quot;", '"'))
                            ip = host_info.get("ip")
                            hostname = host_info.get("domain")
                            if hostname != ip:
                                if hostname not in seen_hostnames:
                                    seen_hostnames.add(hostname)
                                    selected_hostnames.append(hostname)
                                    domain_name = get_domain_from_subdomain(hostname)
                                    if domain_name:
                                        selected_domains.add(domain_name)
                            else:
                                if ip not in seen_ips:
                                    seen_ips.add(ip)
                                    selected_ips.append(ip)
                        except (json.JSONDecodeError, KeyError):
                            continue

                    for domain in discovered_domains:
                        if validators.domain(domain):
                            selected_domains.add(domain)

                    for domain_name in selected_domains:
                        if validators.domain(domain_name):
                            _, created = _get_or_create_target(project, domain_name, target_type=TARGET_TYPE_HOST)
                            if created:
                                total_processed_count += 1

                    for hostname in selected_hostnames:
                        _, created = _get_or_create_target(project, hostname, target_type=TARGET_TYPE_HOST)
                        if created:
                            total_processed_count += 1

                    for ip in selected_ips:
                        _, created = _get_or_create_target(project, ip, target_type=TARGET_TYPE_IP)
                        if created:
                            total_processed_count += 1

                    logger.log_line(
                        PREFIX_TARGET,
                        "IP_SCAN",
                        "Processing complete.",
                        level="info",
                    )

        except (Http404, ValueError) as e:
            logger.log_line(
                PREFIX_TARGET,
                "ADD_TARGET",
                "Exception while adding target: %s" % (e,),
                level="error",
                exc_info=True,
            )
            messages.add_message(request, messages.ERROR, "Exception while adding target: %s" % (e,))
            return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

        # No targets processed, handle error case
        if total_processed_count == 0:
            # Provide more detailed error message based on the operation type
            if ip_target:
                error_msg = "No targets were processed. This could be due to: 1) All selected hosts already exist, 2) Invalid host data format, or 3) Domain extraction errors. Check the logs for details."
            else:
                error_msg = (
                    "Oops! Could not import any targets, either targets already exists or is not a valid target."
                )

            logger.log_line(
                PREFIX_TARGET,
                "ADD_TARGET",
                "No targets processed (total_processed_count=0) for request: %s" % (dict(request.POST),),
                level="warning",
            )
            messages.add_message(request, messages.ERROR, error_msg)

            # Handle AJAX requests with JSON error response
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse({"status": "error", "message": error_msg, "added_count": 0}, status=400)

            return http.HttpResponseRedirect(reverse("add_target", kwargs={"slug": slug}))

        msg = f"{total_processed_count} target(s) processed successfully"

        messages.add_message(request, messages.SUCCESS, msg)

        # Handle AJAX requests with JSON response
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            response_data = {
                "status": "success",
                "message": msg,
                "processed_count": total_processed_count,
                "redirect_url": reverse("list_target", kwargs={"slug": slug}),
            }

            return JsonResponse(response_data)

        # Regular form submission redirect
        return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))

    # GET request
    secator_configs = _get_secator_configs_for_add_target()
    target_type_choices = dict(TARGET_TYPE_CHOICES)
    context = {
        "add_target_li": "active",
        "target_data_active": "active",
        "form": form,
        "rengine_target_types": RENGINE_TARGET_TYPES_FOR_JS,
        "secator_configs": secator_configs,
        "target_type_choices": target_type_choices,
        "override_prefix": TARGET_OVERRIDE_PREFIX,
        "secator_workers": get_workers_for_scan_dropdown(),
        "add_target_simple_tabs": _build_add_target_simple_tabs(target_type_choices, secator_configs),
        "import_txt_alert": mark_safe(
            "Your txt file must have list of domains separated by a new line."
            "<br><br>By default all domains imported from txt will have no description "
            "and no organization. If you choose to import multiple domains with "
            "description and/or organization, csv import is recommended."
        ),
        "import_csv_alert": mark_safe(
            "Your csv file must be in the format of "
            "<strong>domain, description, organization</strong> separated by a new line."
        ),
    }
    context.update(build_scan_params_form_context(level="target"))
    return render(request, "target/add.html", context)


def list_target(request, slug):
    project = get_object_or_404(Project, slug=slug)
    dt_config = get_datatable_table_config(TABLE_ID_TARGET_LIST)
    context = {
        "list_target_li": "active",
        "target_data_active": "active",
        "datatable_filter_select_to_param": dt_config.get("filter_context"),
        "datatable_row_group_config": get_datatable_row_group_config(TABLE_ID_TARGET_LIST),
        "detail_scan_url": reverse("detail_scan", args=[project.slug, 0]),
        "start_scan_url": reverse("start_scan", args=[project.slug, 0]),
        "schedule_scan_url": reverse("schedule_scan", args=[project.slug, 0]),
        "update_target_url": reverse("update_target", args=[project.slug, 0]),
        "delete_target_url": reverse("delete_target", args=[project.slug, 0]),
        "target_summary_url": reverse("target_summary", args=[project.slug, 0]),
        "show_full_target_actions": has_role(request.user, "penetration_tester") or has_role(request.user, "admin"),
    }
    return render(request, "target/list.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_target(request, slug, id):
    if request.method == "POST":
        try:
            target = get_object_or_404(Target, id=id)
            base = Path(settings.RENGINE_RESULTS)
            if base.exists():
                result_dirs = set()
                for scan in ScanHistory.objects.filter(target_id=target.id):
                    results_dir = getattr(scan, "results_dir", None) or ""
                    resolved = resolve_results_dir_under_base(settings.RENGINE_RESULTS, results_dir)
                    if resolved is not None:
                        result_dirs.add(resolved)
                for dir_path in result_dirs:
                    result = safe_rmtree(settings.RENGINE_RESULTS, dir_path)
                    if result != "removed":
                        logger.log_line(
                            PREFIX_TARGET,
                            "DELETE_TARGET",
                            "Results dir cleanup returned %s for path %s" % (result, dir_path),
                            level="warning",
                        )
                resolved_direct = resolve_results_dir_under_base(settings.RENGINE_RESULTS, target.value)
                if resolved_direct is not None and resolved_direct.is_dir():
                    result = safe_rmtree(settings.RENGINE_RESULTS, resolved_direct)
                    if result != "removed":
                        logger.log_line(
                            PREFIX_TARGET,
                            "DELETE_TARGET",
                            "Results dir cleanup returned %s for path %s" % (result, resolved_direct),
                            level="warning",
                        )
                prefix = f"{target.value}__"
                for entry in base.iterdir():
                    if entry.is_dir() and entry.name.startswith(prefix):
                        result = safe_rmtree(settings.RENGINE_RESULTS, entry)
                        if result != "removed":
                            logger.log_line(
                                PREFIX_TARGET,
                                "DELETE_TARGET",
                                "Results dir cleanup returned %s for path %s" % (result, entry),
                                level="warning",
                            )
            target.delete()
            response_data = {"status": "true"}
            messages.add_message(request, messages.INFO, "Target successfully deleted!")
        except Http404:
            if isinstance(id, int):
                logger.log_line(
                    PREFIX_TARGET,
                    "DELETE_TARGET",
                    "Target not found: %d" % (id,),
                    level="error",
                )
            else:
                logger.log_line(
                    PREFIX_TARGET,
                    "DELETE_TARGET",
                    "Target not found: Invalid ID provided",
                    level="error",
                )
            messages.add_message(request, messages.ERROR, "Target not found.")
            response_data = {"status": "false"}
    else:
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        if request.method in valid_methods:
            logger.log_line(
                PREFIX_TARGET,
                "DELETE_TARGET",
                "Invalid request method: %s" % (request.method,),
                level="error",
            )
        else:
            logger.log_line(
                PREFIX_TARGET,
                "DELETE_TARGET",
                "Invalid request method: Unknown method provided",
                level="error",
            )

        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Oops! Target could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_targets(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                Target.objects.filter(id=value).delete()
        messages.add_message(request, messages.INFO, "Targets deleted!")
    return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def update_target(request, slug, id):
    target = get_object_or_404(Target, id=id)
    form = UpdateTargetModelForm(instance=target)
    override_form_fallback = None
    override_header_initial = None
    scan_override = None

    if request.method == "POST":
        form = UpdateTargetModelForm(request.POST, instance=target)
        if form.is_valid():
            (
                scan_override,
                override_errors,
                override_form_fallback,
                override_header_initial,
            ) = process_target_scan_override_from_post(request.POST)
            if override_errors:
                for msg in override_errors:
                    messages.error(request, msg)
            else:
                updated_target = form.save(commit=False)
                updated_target.scan_config = strip_empty_override_keys(scan_override or {}) or None
                updated_target.save()
                messages.add_message(request, messages.INFO, "Target %s modified!" % (target.value,))
                return http.HttpResponseRedirect(reverse("list_target", kwargs={"slug": slug}))

    context = build_update_target_context(
        target,
        form,
        override_form_fallback=override_form_fallback,
        override_header_initial=override_header_initial,
        scan_override=scan_override if override_form_fallback else None,
    )
    scope = get_scope_for_target(target)
    context["secator_workers"] = get_workers_for_scan_dropdown(scope=scope)
    return render(request, "target/update.html", context)


class _AggregatedRelatedList:
    """List-like object exposing .count for template compatibility with M2M .all."""

    def __init__(self, items):
        self._items = list(items)

    def __iter__(self):
        return iter(self._items)

    def count(self):
        return len(self._items)


class _FakeRelatedManager:
    """Mimics M2M .all for templates: .all returns a list-like with .count()."""

    def __init__(self, items):
        self.all = _AggregatedRelatedList(items)


class _AggregatedDomainInfo:
    """Wrapper exposing aggregated related_domains and related_tlds for target summary.
    Template uses domain_info.related_domains.all and .count; .all is the list-like.
    """

    def __init__(self, related_domains, related_tlds):
        self.related_domains = _FakeRelatedManager(related_domains)
        self.related_tlds = _FakeRelatedManager(related_tlds)


def _aggregate_related_from_domains(domains, attr):
    """Collect related_domains or related_tlds from all domains with domain_info.
    Deduplicate by RelatedDomain.name, keeping the one from the most recent scan.
    Returns list of RelatedDomain instances ordered by most recent scan first.
    """
    # (name, related_domain_obj, scan_date) then dedupe by name keeping max date
    seen = {}
    for domain in domains:
        info = domain.domain_info
        if not info:
            continue
        scan_date = domain.scan_history.start_scan_date if domain.scan_history else None
        for related in getattr(info, attr).all():
            name = related.name
            if name not in seen or (scan_date and (not seen[name][1] or scan_date > seen[name][1])):
                seen[name] = (related, scan_date)
    return [
        v[0]
        for v in sorted(
            seen.values(),
            key=lambda x: (x[1] or datetime.min.replace(tzinfo=timezone.utc),),
            reverse=True,
        )
    ]


def target_summary(request, slug, id):
    """Summary of a target. Contains aggregated information on all
    objects (Subdomain, EndPoint, Vulnerability, Emails, ...) found across all
    scans for this target. Single-value content uses the most recent scan when
    available; list content (e.g. related domains/TLDs) is aggregated and
    deduplicated, preferring the most recent scan.

    Args:
        request: Django request.
        id: Target id.
    """
    context = {}

    target = get_object_or_404(Target, id=id)
    context["target"] = target
    domains_ordered = list(
        Domain.objects.filter(scan_history__target_id=target.id)
        .select_related("scan_history", "domain_info")
        .prefetch_related(
            "domain_info__registrar",
            "domain_info__registrant",
            "domain_info__admin",
            "domain_info__tech",
            "domain_info__name_servers",
            "domain_info__dns_records",
            "domain_info__historical_ips",
            "domain_info__status",
            "domain_info__related_domains",
            "domain_info__related_tlds",
        )
        .order_by("-scan_history__start_scan_date")
    )
    seen_names = set()
    domains = [d for d in domains_ordered if d.name not in seen_names and not seen_names.add(d.name)]
    context["domains"] = domains
    if not domains_ordered:
        context["domain_info"] = None
    else:
        domains_with_info = [d for d in domains_ordered if d.domain_info_id]
        if not domains_with_info:
            context["domain_info"] = None
        else:
            agg_related_domains = _aggregate_related_from_domains(domains_with_info, "related_domains")
            agg_related_tlds = _aggregate_related_from_domains(domains_with_info, "related_tlds")
            context["domain_info"] = _AggregatedDomainInfo(agg_related_domains, agg_related_tlds)

    scan = ScanHistory.objects.filter(target_id=id)
    scan_status_order = Case(
        When(scan_status=SCAN_STATUS_RUNNING, then=Value(0)),
        When(scan_status=SCAN_STATUS_RUNNING_BACKGROUND, then=Value(0)),
        When(scan_status=SCAN_STATUS_QUEUED, then=Value(1)),
        When(scan_status=SCAN_STATUS_COMPLETED, then=Value(2)),
        When(scan_status=SCAN_STATUS_FAILED, then=Value(3)),
        default=Value(4),
        output_field=IntegerField(),
    )
    context["recent_scans"] = scan.annotate(sort_priority=scan_status_order).order_by(
        "sort_priority", "-start_scan_date"
    )[:4]
    context["scan_count"] = scan.count()
    last_week = timezone.now() - timedelta(days=7)
    context["this_week_scan_count"] = scan.filter(start_scan_date__gte=last_week).count()

    context["scan_engines"] = EngineType.objects.order_by("engine_name").all()

    subdomains = Subdomain.objects.filter(domain__scan_history__target_id=id).values("name").distinct()
    context["subdomain_count"] = subdomains.count()
    context["alive_count"] = subdomains.filter(http_status__gt=0).count()

    endpoints = EndPoint.objects.filter(domain__scan_history__target_id=id).values("http_url").distinct()
    context["endpoint_count"] = endpoints.count()
    context["endpoint_alive_count"] = endpoints.filter(http_status__gt=0).count()

    vulnerabilities = Vulnerability.objects.filter(domain__scan_history__target_id=id)
    unknown_count = vulnerabilities.filter(severity=-1).count()
    info_count = vulnerabilities.filter(severity=0).count()
    low_count = vulnerabilities.filter(severity=1).count()
    medium_count = vulnerabilities.filter(severity=2).count()
    high_count = vulnerabilities.filter(severity=3).count()
    critical_count = vulnerabilities.filter(severity=4).count()
    ignore_info_count = sum([low_count, medium_count, high_count, critical_count])
    context["unknown_count"] = unknown_count
    context["info_count"] = info_count
    context["low_count"] = low_count
    context["medium_count"] = medium_count
    context["high_count"] = high_count
    context["critical_count"] = critical_count
    context["total_vul_ignore_info_count"] = ignore_info_count
    context["most_common_vulnerability"] = (
        vulnerabilities.exclude(severity=0)
        .values("name", "severity")
        .annotate(count=Count("name"))
        .order_by("-count")[:10]
    )
    context["vulnerability_count"] = vulnerabilities.count()
    context["vulnerability_list"] = vulnerabilities.order_by("-severity").all()[:30]

    # Vulnerability Tags
    context["most_common_tags"] = (
        VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities)
        .annotate(nused=Count("vuln_tags"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    # Emails
    emails = Email.objects.filter(emails__in=scan).distinct()
    context["exposed_count"] = emails.exclude(password__isnull=True).count()
    context["email_count"] = emails.count()

    # Employees
    context["employees_count"] = Employee.objects.filter(employees__in=scan).count()

    # CVEs
    context["most_common_cve"] = (
        CveId.objects.filter(cve_ids__in=vulnerabilities)
        .annotate(nused=Count("cve_ids"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    # CWEs
    context["most_common_cwe"] = (
        CweId.objects.filter(cwe_ids__in=vulnerabilities)
        .annotate(nused=Count("cwe_ids"))
        .order_by("-nused")
        .values("name", "nused")[:7]
    )

    endpoint_repo = EndpointRepository()
    status_counts = {}
    for domain in domains_ordered:
        for row in endpoint_repo.get_http_status_breakdown(domain):
            status = row.get("http_status")
            count = row.get("http_status__count", 0)
            status_counts[status] = status_counts.get(status, 0) + count
    context["http_status_breakdown"] = [
        {"http_status": status, "http_status__count": count} for status, count in sorted(status_counts.items())
    ]

    subdomains = Subdomain.objects.filter(domain__scan_history__target_id=id)
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct("address")
    ip_serializer = IpSerializer(ip_addresses.all(), many=True, context={"target_id": id})
    context["ip_addresses"] = json.dumps(ip_serializer.data, cls=DjangoJSONEncoder)

    context["asset_countries"] = (
        CountryISO.objects.filter(ipaddress__in=ip_addresses).annotate(count=Count("iso")).order_by("-count")
    )

    context.update(build_secator_profiles_context())
    scope = get_scope_for_target(target)
    context["secator_workers"] = get_workers_for_scan_dropdown(scope=scope)
    context.update(build_scan_params_form_context(target=target))
    return render(request, "target/summary.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def add_organization(request, slug):
    form = AddOrganizationForm(request.POST or None, project=slug)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        project = Project.objects.get(slug=slug)
        profiles_dict = parse_secator_profiles_to_dict(request.POST)
        scan_config, config_errors = parse_scan_config_from_post(request.POST, profiles_dict=profiles_dict, prefix="")
        if config_errors:
            for msg in config_errors:
                messages.error(request, msg)
        else:
            organization = Organization.objects.create(
                name=data["name"],
                description=data["description"],
                project=project,
                insert_date=timezone.now(),
                scan_config=strip_empty_override_keys(scan_config or {}) or None,
            )
            for target in data.get("targets") or []:
                organization.targets.add(target)
            messages.add_message(request, messages.INFO, f"Organization {data['name']} added successfully")
            return http.HttpResponseRedirect(reverse("list_organization", kwargs={"slug": slug}))
    context = {
        "organization_active": "active",
        "form": form,
        "section_collapse_id": "scanOverridesSectionOrgAdd",
        "secator_workers": get_workers_for_scan_dropdown(),
    }
    context.update(build_scan_params_form_context())
    return render(request, "organization/add.html", context)


def organization_dashboard(request, slug, organization_id):
    """Dashboard view for a single organization (scopes, targets, vulns, feeds)."""
    try:
        project = Project.get_from_slug(slug)
    except Project.DoesNotExist:
        raise Http404("Project not found")
    organization = get_object_or_404(Organization, id=organization_id, project=project)
    dashboard_data = get_organization_dashboard_data(organization)
    organizations_list = list(Organization.objects.for_project(project).order_by("name").values("id", "name"))
    context = {
        "organization_active": "active",
        "current_project": project,
        "organizations_list": organizations_list,
        **dashboard_data,
    }
    return render(request, "organization/dashboard.html", context)


def list_organization(request, slug):
    organizations = Organization.objects.for_project(slug).order_by("-insert_date")
    dt_config = get_datatable_table_config(TABLE_ID_ORGANIZATION_LIST)
    context = {
        "organization_active": "active",
        "organizations": organizations,
        "datatable_filter_select_to_param": dt_config.get("filter_context"),
        "datatable_row_group_cookie_key": dt_config.get("row_group_cookie_key"),
        "datatable_row_group_selector": dt_config.get("row_group_selector"),
    }
    return render(request, "organization/list.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_organization(request, slug, id):
    if request.method == "POST":
        try:
            organization = get_object_or_404(Organization, id=id)
            organization.delete()
            messages.add_message(request, messages.INFO, "Organization successfully deleted!")
            response_data = {"status": "true"}
        except Http404:
            messages.add_message(request, messages.ERROR, "Organization not found.")
            response_data = {"status": "false"}
    else:
        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Oops! Organization could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def update_organization(request, slug, id):
    organization = get_object_or_404(Organization, id=id)
    form = UpdateOrganizationForm(instance=organization)
    domain_list = []
    target_list = []
    if request.method == "POST":
        form = UpdateOrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            data = form.cleaned_data
            profiles_dict = parse_secator_profiles_to_dict(request.POST)
            scan_config, config_errors = parse_scan_config_from_post(
                request.POST,
                profiles_dict=profiles_dict,
                existing_config=organization.scan_config,
                prefix="",
            )
            if config_errors:
                for msg in config_errors:
                    messages.error(request, msg)
            else:
                organization.targets.clear()
                organization.name = data["name"]
                organization.description = data["description"]
                organization.scan_config = strip_empty_override_keys(scan_config or {}) or None
                organization.save()
                for target in data.get("targets") or []:
                    organization.targets.add(target)
                msg = "Organization %s modified!" % (organization.name,)
                logger.log_line(
                    PREFIX_TARGET,
                    "ORGANIZATION",
                    msg,
                    level="info",
                )
                messages.add_message(request, messages.INFO, msg)
                return http.HttpResponseRedirect(reverse("list_organization", kwargs={"slug": slug}))
        domain_list = request.POST.getlist("domains")
        target_list = request.POST.getlist("targets")
    else:
        domain_list = list(organization.get_domains().values_list("id", flat=True))
        domain_list = [str(did) for did in domain_list]
        target_list = list(organization.targets.values_list("id", flat=True))
        target_list = [str(tid) for tid in target_list]
        form.set_value(organization.name, organization.description, target_list)
    context = {
        "list_organization_li": "active",
        "organization_data_active": "true",
        "organization": organization,
        "domain_list": mark_safe(domain_list),
        "target_list": mark_safe(target_list),
        "form": form,
        "section_collapse_id": "scanOverridesSectionOrg",
        "secator_workers": get_workers_for_scan_dropdown(),
    }
    context.update(build_scan_params_form_context(organization=organization))
    return render(request, "organization/update.html", context)


# ---------------------------------------------------------------------------
# Scope views
# ---------------------------------------------------------------------------


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def list_scope(request, slug):
    scopes = (
        Scope.objects.filter(organization__project__slug=slug)
        .select_related("organization")
        .annotate(
            target_count=Count("targets", distinct=True),
            worker_count=Count("workers", distinct=True),
        )
        .order_by("-insert_date")
    )
    dt_config = get_datatable_table_config(TABLE_ID_SCOPE_LIST)
    context = {
        "scope_active": "active",
        "scopes": scopes,
        "scope_type_choices": mark_safe(json.dumps([[val, label] for val, label in SCOPE_TYPE_CHOICES])),
        "slug": slug,
        "datatable_filter_select_to_param": dt_config.get("filter_context"),
        "datatable_row_group_config": get_datatable_row_group_config(TABLE_ID_SCOPE_LIST),
    }
    return render(request, "scope/list.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def add_scope(request, slug):
    form = ScopeForm(request.POST or None, project_slug=slug)
    if request.method == "POST" and form.is_valid():
        scope = form.save(commit=False)
        profiles_dict = parse_secator_profiles_to_dict(request.POST)
        config, errors = parse_scan_config_from_post(request.POST, prefix="", profiles_dict=profiles_dict)
        if errors:
            for msg in errors:
                messages.error(request, msg)
        else:
            scope.scan_config = strip_empty_override_keys(config or {}) or None
            scope.save()
            form.save_m2m()
            _apply_pending_normalizer_targets(scope, request)
            messages.add_message(request, messages.INFO, "Scope %s added successfully" % (scope.name,))
            return http.HttpResponseRedirect(reverse("list_scope", kwargs={"slug": slug}))
    initial_workers = form.initial.get("workers") or []
    allowed_ids = [w.id for w in initial_workers] if initial_workers else []
    allow_local = form.initial.get("allow_local_worker", True)
    show_default_worker = (1 if allow_local else 0) + len(allowed_ids) >= 2
    context = {
        "scope_active": "active",
        "form": form,
        "slug": slug,
        "section_collapse_id": "scanOverridesSectionScopeAdd",
        "secator_workers": get_workers_for_scan_dropdown(allowed_worker_ids=allowed_ids),
        "show_default_worker": show_default_worker,
        "scan_params_allow_local_worker": allow_local,
        "scan_params_default_worker_id": None,
    }
    context.update(build_scan_params_form_context(level="scope"))
    return render(request, "scope/add.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def update_scope(request, slug, id):
    scope = get_object_or_404(Scope, id=id, organization__project__slug=slug)
    form = ScopeForm(request.POST or None, instance=scope, project_slug=slug)
    if request.method == "POST" and form.is_valid():
        updated_scope = form.save(commit=False)
        profiles_dict = parse_secator_profiles_to_dict(request.POST)
        config, errors = parse_scan_config_from_post(
            request.POST, prefix="", profiles_dict=profiles_dict, existing_config=scope.scan_config
        )
        if errors:
            for msg in errors:
                messages.error(request, msg)
        else:
            updated_scope.scan_config = strip_empty_override_keys(config or {}) or None
            updated_scope.save()
            form.save_m2m()
            _apply_pending_normalizer_targets(updated_scope, request)
            messages.add_message(request, messages.INFO, "Scope %s updated successfully" % (scope.name,))
            return http.HttpResponseRedirect(reverse("list_scope", kwargs={"slug": slug}))
    allowed_options = get_allowed_workers_for_scope(scope)
    show_default_worker = len(allowed_options) >= 2
    default_worker_id = get_default_worker_for_scope(scope)
    context = {
        "scope_active": "active",
        "form": form,
        "scope": scope,
        "slug": slug,
        "section_collapse_id": "scanOverridesSectionScope",
        "secator_workers": get_workers_for_scan_dropdown(scope=scope),
        "show_default_worker": show_default_worker,
        "scan_params_allow_local_worker": scope_allow_local(scope),
        "scan_params_default_worker_id": default_worker_id,
    }
    context.update(build_scan_params_form_context(scope=scope, organization=scope.organization))
    return render(request, "scope/update.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scope(request, slug, id):
    if request.method == "POST":
        try:
            scope = get_object_or_404(Scope, id=id, organization__project__slug=slug)
            scope.delete()
            messages.add_message(request, messages.INFO, "Scope successfully deleted!")
            response_data = {"status": "true"}
        except Http404:
            messages.add_message(request, messages.ERROR, "Scope not found.")
            response_data = {"status": "false"}
    else:
        response_data = {"status": "false"}
        messages.add_message(request, messages.ERROR, "Scope could not be deleted!")
    return http.JsonResponse(response_data)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
def scope_detail(request, slug, id):
    scope = get_object_or_404(
        Scope.objects.select_related("organization").prefetch_related("targets", "workers"),
        id=id,
        organization__project__slug=slug,
    )
    scope_scan_config = _normalize_scan_config(getattr(scope, "scan_config", None))
    context = {
        "scope_active": "active",
        "scope": scope,
        "scope_scan_config": scope_scan_config,
        "slug": slug,
        "scan_params_effective": build_effective_params_display(scope=scope, organization=scope.organization),
    }
    return render(request, "scope/detail.html", context)


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
@require_POST
def scope_normalize(request, slug):
    """POST: normalize raw scope input; returns JSON with domain_targets, ip_targets, allowed_finding_hosts."""
    raw, body_error = get_string_from_post_or_json(request, key="raw")
    if body_error:
        return JsonResponse({"error": body_error}, status=400)
    if raw is None:
        return JsonResponse({"error": "Missing or invalid 'raw' input"}, status=400)
    result = parse_scope_raw_input(raw)
    return JsonResponse(
        {
            "domain_targets": list(result.domain_targets),
            "ip_targets": list(result.ip_targets),
            "allowed_finding_hosts": list(result.allowed_finding_hosts),
        }
    )


@has_permission_decorator(PERM_MODIFY_TARGETS, redirect_url=FOUR_OH_FOUR_URL)
@require_POST
def scope_normalize_apply(request, slug):
    """
    POST: normalize raw input and get_or_create targets for project; returns target_ids and lists.
    The scope add/update UI uses the preview flow (normalize + pending_normalizer_targets on save) instead.
    This endpoint remains for API or programmatic use.
    """
    raw, body_error = get_string_from_post_or_json(request, key="raw")
    if body_error:
        return JsonResponse({"error": body_error}, status=400)
    if raw is None:
        return JsonResponse({"error": "Missing or invalid 'raw' input"}, status=400)
    project = get_object_or_404(Project, slug=slug)
    result = parse_scope_raw_input(raw)
    with transaction.atomic():
        target_ids = []
        for value in result.domain_targets:
            target, _ = _get_or_create_target(project, value, target_type=TARGET_TYPE_HOST)
            target_ids.append(target.id)
        for value in result.ip_targets:
            target, _ = _get_or_create_target(project, value, target_type=TARGET_TYPE_IP)
            target_ids.append(target.id)
    return JsonResponse(
        {
            "target_ids": target_ids,
            "domain_targets": list(result.domain_targets),
            "ip_targets": list(result.ip_targets),
            "allowed_finding_hosts": list(result.allowed_finding_hosts),
            "restrict_findings_to_target": True,
        }
    )
