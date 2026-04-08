from collections import defaultdict
import html
import json
from typing import Any, Iterable, MutableMapping, Sequence

from django.contrib.humanize.templatetags.humanize import naturalday, naturaltime
from django.db.models import F, JSONField, QuerySet, Value
from django.urls import reverse
from rest_framework import serializers
import yaml

# Scan file URLs: build_scan_file_url (api.scan_file) yields paths served by ServeScanFile
# with project-scoped access; do not build scan file URLs outside this helper.
from api.scan_file import build_scan_file_url
from dashboard.models import (
    Project,
    SearchHistory,
)
from recon_note.models import (
    TodoNote,
)
from reNgine.definitions import ENGINE_NAMES
from reNgine.services.default_endpoint_queryset import apply_endpoint_port_and_techs_related
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.subdomain import get_interesting_subdomains
from scanEngine.models import (
    EngineType,
    SecatorWorker,
    Wordlist,
)
from startScan.models import (
    Certificate,
    Command,
    DirectoryFile,
    DirectoryScan,
    Domain,
    Dork,
    Email,
    Employee,
    EndPoint,
    Exploit,
    IpAddress,
    MetaFinderDocument,
    Port,
    S3Bucket,
    ScanActivity,
    ScanHistory,
    ScanSchedule,
    SecatorRunner,
    Secret,
    Subdomain,
    SubScan,
    Technology,
    Vulnerability,
    Waf,
)
from targetApp.models import Organization, Scope, Target
from targetApp.services.scope_params import get_scope_for_target


# Sentinel to distinguish "annotated count missing" from "count present but None" in get_*_count.
_CACHE_MISSING = object()

PREFIX_API_SERIALIZERS = "[API_SERIALIZERS]"
logger = get_module_logger(__name__)


class SearchHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SearchHistory
        fields = ["query"]


class DomainSerializer(serializers.ModelSerializer):
    vuln_count = serializers.SerializerMethodField()
    organization = serializers.SerializerMethodField()
    most_recent_scan = serializers.SerializerMethodField()
    insert_date = serializers.SerializerMethodField()
    insert_date_humanized = serializers.SerializerMethodField()
    start_scan_date = serializers.SerializerMethodField()
    start_scan_date_humanized = serializers.SerializerMethodField()
    project = serializers.SerializerMethodField()

    class Meta:
        model = Domain
        fields = [
            "id",
            "name",
            "h1_team_handle",
            "ip_address_cidr",
            "description",
            "insert_date",
            "start_scan_date",
            "request_headers",
            "domain_info",
            "project",
            "vuln_count",
            "organization",
            "most_recent_scan",
            "insert_date_humanized",
            "start_scan_date_humanized",
        ]
        depth = 2

    def get_vuln_count(self, obj):
        try:
            return obj.vuln_count
        except Exception:
            return None

    def get_project(self, obj):
        if obj.scan_history_id and obj.scan_history.target_id:
            return obj.scan_history.target.project_id
        return None

    def get_organization(self, obj):
        target_id = obj.scan_history.target_id if obj.scan_history_id else None
        if not target_id:
            return []
        orgs = Organization.objects.filter(targets__id=target_id)
        return [org.name for org in orgs]

    def get_most_recent_scan(self, obj):
        return obj.get_recent_scan_id()

    def get_insert_date(self, obj):
        return naturalday(obj.insert_date).title()

    def get_insert_date_humanized(self, obj):
        return naturaltime(obj.insert_date).title()

    def get_start_scan_date(self, obj):
        if obj.start_scan_date:
            return naturalday(obj.start_scan_date).title()

    def get_start_scan_date_humanized(self, obj):
        if obj.start_scan_date:
            return naturaltime(obj.start_scan_date).title()


class TargetSerializer(serializers.ModelSerializer):
    """Serializer for Target model (list targets API). Exposes 'name' as alias for 'value' for frontend compat."""

    name = serializers.SerializerMethodField()
    organization = serializers.SerializerMethodField()
    scope_group = serializers.SerializerMethodField()
    most_recent_scan = serializers.SerializerMethodField()
    insert_date = serializers.SerializerMethodField()
    insert_date_humanized = serializers.SerializerMethodField()
    start_scan_date = serializers.SerializerMethodField()
    start_scan_date_humanized = serializers.SerializerMethodField()
    domain_count = serializers.IntegerField(read_only=True, default=0)
    subdomain_count = serializers.IntegerField(read_only=True, default=0)
    endpoint_count = serializers.IntegerField(read_only=True, default=0)
    vulnerability_count = serializers.IntegerField(read_only=True, default=0)
    secret_count = serializers.IntegerField(read_only=True, default=0)
    exploit_count = serializers.IntegerField(read_only=True, default=0)
    ip_address_count = serializers.SerializerMethodField()
    ip_alive_count = serializers.SerializerMethodField()
    attack_surface = serializers.SerializerMethodField()
    attack_surface_count = serializers.SerializerMethodField()

    class Meta:
        model = Target
        fields = [
            "id",
            "value",
            "name",
            "target_type",
            "description",
            "insert_date",
            "start_scan_date",
            "project",
            "organization",
            "scope_group",
            "most_recent_scan",
            "insert_date_humanized",
            "start_scan_date_humanized",
            "domain_count",
            "subdomain_count",
            "endpoint_count",
            "vulnerability_count",
            "secret_count",
            "exploit_count",
            "ip_address_count",
            "ip_alive_count",
            "has_scan",
            "attack_surface",
            "attack_surface_count",
        ]
        datatables_always_serialize = (
            "domain_count",
            "subdomain_count",
            "endpoint_count",
            "vulnerability_count",
            "secret_count",
            "exploit_count",
            "ip_address_count",
            "ip_alive_count",
            "attack_surface_count",
        )

    has_scan = serializers.SerializerMethodField()

    def get_name(self, obj):
        return obj.value

    def get_organization(self, obj):
        return [org.name for org in obj.organizations.all()]

    def get_scope_group(self, obj):
        if hasattr(obj, "scope_group_name"):
            return obj.scope_group_name
        first = get_scope_for_target(obj)
        return first.name if first else "No scope"

    def get_most_recent_scan(self, obj):
        from startScan.models import ScanHistory

        sh = ScanHistory.objects.filter(target_id=obj.id).order_by("-id").first()
        return sh.id if sh else None

    def get_insert_date(self, obj):
        return naturalday(obj.insert_date).title() if obj.insert_date else None

    def get_insert_date_humanized(self, obj):
        return naturaltime(obj.insert_date).title() if obj.insert_date else None

    def get_start_scan_date(self, obj):
        return naturalday(obj.start_scan_date).title() if obj.start_scan_date else None

    def get_start_scan_date_humanized(self, obj):
        return naturaltime(obj.start_scan_date).title() if obj.start_scan_date else None

    def get_has_scan(self, obj):
        return bool(obj.start_scan_date)

    def _target_ip_counts_for_serialization(self, obj):
        from reNgine.services.scan_finding_metrics import (
            TARGET_IP_ALIVE_ATTR,
            TARGET_IP_COUNT_ATTR,
            get_ip_metrics_for_target,
        )

        total = getattr(obj, TARGET_IP_COUNT_ATTR, _CACHE_MISSING)
        alive = getattr(obj, TARGET_IP_ALIVE_ATTR, _CACHE_MISSING)
        if total is not _CACHE_MISSING and alive is not _CACHE_MISSING:
            return total, alive
        cache = self.context.setdefault("_target_ip_metrics_fallback", {})
        if obj.id not in cache:
            cache[obj.id] = get_ip_metrics_for_target(obj.id)
        return cache[obj.id]

    def get_ip_address_count(self, obj):
        total, _alive = self._target_ip_counts_for_serialization(obj)
        return total

    def get_ip_alive_count(self, obj):
        _total, alive = self._target_ip_counts_for_serialization(obj)
        return alive

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        from reNgine.llm.attack_surface_storage import parent_has_llm_attack_surface_analyses

        return parent_has_llm_attack_surface_analyses(obj)

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        from reNgine.llm.attack_surface_storage import count_llm_attack_surface_analyses_for_parent

        return count_llm_attack_surface_analyses_for_parent(obj)


class SubScanResultSerializer(serializers.ModelSerializer):
    task = serializers.SerializerMethodField("get_task_name")
    subdomain_name = serializers.SerializerMethodField("get_subdomain_name")
    engine = serializers.SerializerMethodField("get_engine_name")

    class Meta:
        model = SubScan
        fields = [
            "id",
            "type",
            "subdomain_name",
            "start_scan_date",
            "stop_scan_date",
            "scan_history",
            "subdomain",
            "status",
            "subdomain_name",
            "task",
            "engine",
        ]

    def get_subdomain_name(self, subscan):
        if subscan.subdomain:
            return subscan.subdomain.name
        if subscan.scan_history and subscan.scan_history.target:
            return f"Domain-level: {subscan.scan_history.target.value}"
        return ""

    def get_task_name(self, subscan):
        return subscan.type

    def get_engine_name(self, subscan):
        if subscan.engine:
            return subscan.engine.engine_name
        if subscan.secator_runner and subscan.secator_runner.runner_name:
            return subscan.secator_runner.runner_name
        return subscan.type or ""


class ReconNoteSerializer(serializers.ModelSerializer):
    domain_name = serializers.SerializerMethodField("get_domain_name")
    subdomain_name = serializers.SerializerMethodField("get_subdomain_name")
    scan_started_time = serializers.SerializerMethodField("get_scan_started_time")

    class Meta:
        model = TodoNote
        fields = [
            "id",
            "title",
            "description",
            "scan_history",
            "subdomain",
            "is_done",
            "is_important",
            "project",
            "domain_name",
            "subdomain_name",
            "scan_started_time",
        ]

    def get_domain_name(self, note):
        if note.scan_history and note.scan_history.target:
            return note.scan_history.target.value
        return ""

    def get_subdomain_name(self, note):
        if note.subdomain:
            return note.subdomain.name

    def get_scan_started_time(self, note):
        if note.scan_history:
            return note.scan_history.start_scan_date


class OnlySubdomainNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = ["name", "id"]


class SubScanSerializer(serializers.ModelSerializer):
    subdomain_name = serializers.SerializerMethodField("get_subdomain_name")
    time_taken = serializers.SerializerMethodField("get_total_time_taken")
    elapsed_time = serializers.SerializerMethodField("get_elapsed_time")
    completed_ago = serializers.SerializerMethodField("get_completed_ago")
    engine = serializers.SerializerMethodField("get_engine_name")
    formatted_task_name = serializers.SerializerMethodField("get_formatted_task_name")
    effective_status = serializers.SerializerMethodField("get_effective_status")

    class Meta:
        model = SubScan
        fields = [
            "id",
            "type",
            "start_scan_date",
            "status",
            "scan_history",
            "subdomain",
            "stop_scan_date",
            "error_message",
            "engine",
            "subdomain_subscan_ids",
            "subdomain_name",
            "time_taken",
            "elapsed_time",
            "completed_ago",
            "formatted_task_name",
            "effective_status",
        ]

    def get_subdomain_name(self, subscan):
        if subscan.subdomain:
            return subscan.subdomain.name
        if subscan.scan_history and subscan.scan_history.target:
            return f"Domain-level: {subscan.scan_history.target.value}"
        return ""

    def get_total_time_taken(self, subscan):
        return subscan.get_total_time_taken()

    def get_elapsed_time(self, subscan):
        return subscan.get_elapsed_time()

    def get_completed_ago(self, subscan):
        return subscan.get_completed_ago()

    def get_engine_name(self, subscan):
        if subscan.engine:
            return subscan.engine.engine_name
        if subscan.secator_runner and subscan.secator_runner.runner_name:
            return subscan.secator_runner.runner_name
        return subscan.type or ""

    def get_formatted_task_name(self, subscan):
        """Unified display name for legacy (engine) and Secator (runner)."""
        return subscan.display_scan_name or (subscan.type or "Unknown")

    def get_effective_status(self, subscan):
        """Status code for UI: from DB for legacy, from runner for Secator."""
        return subscan.status_code


class CommandSerializer(serializers.ModelSerializer):
    activity_id = serializers.SerializerMethodField()
    runner_id = serializers.SerializerMethodField()
    status_string = serializers.SerializerMethodField()
    elapsed = serializers.SerializerMethodField()
    formatted_output = serializers.SerializerMethodField()
    indent_level = serializers.SerializerMethodField()

    class Meta:
        model = Command
        fields = [
            "id",
            "scan_history",
            "activity",
            "activity_id",
            "runner_id",
            "status_string",
            "command",
            "return_code",
            "output",
            "time",
            "end_time",
            "elapsed",
            "errors",
            "warnings",
            "name",
            "status",
            "cwd",
            "runner_type",
            "has_parent",
            "has_children",
            "workflow_name",
            "node_id",
            "ancestor_id",
            "scan_type",
            "formatted_output",
            "indent_level",
        ]
        depth = 1

    def get_activity_id(self, obj):
        """Return activity FK id for modal context filtering."""
        return obj.activity_id

    def get_runner_id(self, obj):
        """Return runner FK id from activity for modal context filtering."""
        activity = getattr(obj, "activity", None)
        return activity.runner_id_id if activity is not None else None

    def get_status_string(self, obj):
        """Return effective status (from runner for Secator) for display."""
        return obj.status_string

    def get_elapsed(self, obj):
        """Return elapsed field as float."""
        try:
            elapsed_value = obj.elapsed
            return float(elapsed_value) if elapsed_value is not None else None
        except (AttributeError, TypeError, ValueError):
            return None

    def get_formatted_output(self, obj):
        """
        Format output with JSON formatting and ANSI to HTML conversion.

        Returns formatted output as a dictionary with metadata.
        The HTML is already escaped in the formatter for security.
        For JSON API, we return the HTML as a string (not mark_safe).
        The JavaScript will insert it directly since it's generated by our secure formatter.
        """
        from html import escape

        from reNgine.utilities.output_formatter import format_output

        if not obj.output:
            return {
                "formatted": "",
                "is_json": False,
                "has_ansi": False,
                "raw": "",
            }

        try:
            return format_output(obj.output)
        except Exception as e:
            # Fallback to escaped raw output if formatting fails
            # We must escape here to prevent XSS since the client inserts this into innerHTML
            logger.log_line(
                PREFIX_API_SERIALIZERS,
                "FORMAT_OUTPUT",
                "Error formatting output for command %s: %s" % (obj.id, e),
                level="warning",
            )
            escaped_output = escape(obj.output)
            return {
                "formatted": escaped_output,
                "is_json": False,
                "has_ansi": False,
                "raw": obj.output,
            }

    def __init__(self, *args, **kwargs):
        """Initialize serializer and precompute indent level mapping."""
        super().__init__(*args, **kwargs)
        # Precompute indent level mapping to avoid O(n²) lookups
        self._indent_level_map = self._compute_indent_level_map()

    def _compute_indent_level_map(self):
        """
        Precompute indent level mapping for all commands.

        Returns a dict mapping workflow identifiers (name/workflow_name) to their indent level.
        This avoids O(n²) lookups in get_indent_level.
        """
        all_commands = self.context.get("all_commands", [])
        if not all_commands:
            return {}

        # Map workflow identifiers to their indent levels
        indent_map = {}

        for cmd in all_commands:
            if cmd.runner_type == "workflow":
                # Calculate workflow indent level
                workflow_indent = 1 if cmd.has_parent else 0
                # Map both name and workflow_name to the indent level
                if cmd.name:
                    indent_map[cmd.name] = workflow_indent
                if cmd.workflow_name and cmd.workflow_name != cmd.name:
                    indent_map[cmd.workflow_name] = workflow_indent

        return indent_map

    def get_indent_level(self, obj):
        """
        Calculate indent level based on hierarchy.
        Uses precomputed mapping to avoid O(n²) lookups.
        """
        if obj.runner_type == "scan":
            return 0
        elif obj.runner_type == "workflow":
            # Workflow indent: 1 if has_parent (child of scan), 0 otherwise
            return 1 if obj.has_parent else 0
        elif obj.runner_type == "task" and obj.has_parent:
            # Task under a workflow - lookup parent workflow indent and add 1
            if obj.ancestor_id and self._indent_level_map:
                workflow_indent = self._indent_level_map.get(obj.ancestor_id, 1)
                return workflow_indent + 1
            # Default: task is at level 2 (workflow at 1 + task at 2)
            return 2

        return 0


class ScanHistorySerializer(serializers.ModelSerializer):
    subdomain_count = serializers.SerializerMethodField("get_subdomain_count")
    endpoint_count = serializers.SerializerMethodField("get_endpoint_count")
    vulnerability_count = serializers.SerializerMethodField("get_vulnerability_count")
    ip_address_count = serializers.SerializerMethodField("get_ip_address_count")
    current_progress = serializers.SerializerMethodField("get_progress")
    current_task = serializers.SerializerMethodField("get_current_task")
    completed_time = serializers.SerializerMethodField("get_total_scan_time_in_sec")
    elapsed_time = serializers.SerializerMethodField("get_elapsed_time")
    completed_ago = serializers.SerializerMethodField("get_completed_ago")
    organizations = serializers.SerializerMethodField("get_organizations")
    scan_type_display = serializers.SerializerMethodField("get_scan_type_display")
    domain = serializers.SerializerMethodField("get_domain_display")

    class Meta:
        model = ScanHistory
        fields = [
            "id",
            "subdomain_count",
            "endpoint_count",
            "vulnerability_count",
            "ip_address_count",
            "current_progress",
            "current_task",
            "completed_time",
            "elapsed_time",
            "completed_ago",
            "organizations",
            "start_scan_date",
            "scan_status",
            "results_dir",
            "tasks",
            "stop_scan_date",
            "error_message",
            "target",
            "scan_type",
            "scan_type_display",
            "display_runner_type",
            "display_scan_name",
            "scan_name",
            "runner_type",
            "domain",
        ]
        depth = 1

    def get_domain_display(self, scan_history):
        """Return {name: ...} for sidebar/UI compatibility (scan no longer has domain FK)."""
        name = scan_history.target.value if scan_history.target else ""
        return {"name": name}

    def get_subdomain_count(self, scan_history):
        val = getattr(scan_history, "subdomain_count", _CACHE_MISSING)
        if val is not _CACHE_MISSING:
            return val
        if scan_history.get_subdomain_count:
            return scan_history.get_subdomain_count()

    def get_endpoint_count(self, scan_history):
        val = getattr(scan_history, "endpoint_count", _CACHE_MISSING)
        if val is not _CACHE_MISSING:
            return val
        if scan_history.get_endpoint_count:
            return scan_history.get_endpoint_count()

    def get_vulnerability_count(self, scan_history):
        val = getattr(scan_history, "vulnerability_count", _CACHE_MISSING)
        if val is not _CACHE_MISSING:
            return val
        if scan_history.get_vulnerability_count:
            return scan_history.get_vulnerability_count()

    def get_ip_address_count(self, scan_history):
        val = getattr(scan_history, "ip_address_count", _CACHE_MISSING)
        if val is not _CACHE_MISSING:
            return val
        from reNgine.services.scan_finding_metrics import get_ip_address_total_for_scan

        return get_ip_address_total_for_scan(scan_history.id)

    def get_progress(self, scan_history):
        return scan_history.get_progress()

    def get_current_task(self, scan_history):
        return scan_history.get_current_task()

    def get_total_scan_time_in_sec(self, scan_history):
        return scan_history.get_total_scan_time_in_sec()

    def get_elapsed_time(self, scan_history):
        return scan_history.get_elapsed_time()

    def get_completed_ago(self, scan_history):
        return scan_history.get_completed_ago()

    def get_organizations(self, scan_history):
        target = scan_history.target
        return [org.name for org in target.get_organization()] if target else []

    def get_scan_type_display(self, scan_history):
        """Get scan type display name using scan_name property."""
        if not scan_history.is_legacy_scan or not scan_history.scan_type:
            # For Secator scans, return scan_name
            return scan_history.scan_name
        if hasattr(scan_history.scan_type, "get_scan_type_display"):
            return scan_history.scan_type.get_scan_type_display()
        elif hasattr(scan_history.scan_type, "scan_type"):
            return scan_history.scan_type.scan_type
        else:
            return "internet"


class ScanActivitySerializer(serializers.ModelSerializer):
    domain_name = serializers.SerializerMethodField("get_domain_name")
    scan_id = serializers.SerializerMethodField("get_scan_id")
    engine_name = serializers.SerializerMethodField("get_engine_name")
    formatted_task_name = serializers.SerializerMethodField("get_formatted_task_name")
    elapsed_time = serializers.SerializerMethodField("get_elapsed_time")
    status_code = serializers.SerializerMethodField()

    class Meta:
        model = ScanActivity
        fields = [
            "id",
            "title",
            "name",
            "time",
            "status",
            "status_code",
            "domain_name",
            "scan_id",
            "engine_name",
            "formatted_task_name",
            "elapsed_time",
            "error_message",
            "runner_id",
        ]

    def get_status_code(self, scan_activity):
        """Get status as integer code (for compatibility with JavaScript)."""
        return scan_activity.status_code

    def get_domain_name(self, scan_activity):
        if scan_activity.scan_of and scan_activity.scan_of.target:
            return scan_activity.scan_of.target.value
        return "Unknown"

    def get_scan_id(self, scan_activity):
        return scan_activity.scan_of.id if scan_activity.scan_of else None

    def get_engine_name(self, scan_activity):
        return scan_activity.scan_of.scan_name if scan_activity.scan_of else "Unknown"

    def get_formatted_task_name(self, scan_activity):
        """Format task name for display"""
        task_name = scan_activity.name

        # If title is set and different from default name, use it (e.g. for Nuclei severity)
        if scan_activity.title and scan_activity.title != task_name.replace("_", " ").capitalize():
            return scan_activity.title

        task_display_names = {
            "subdomain_discovery": "Subdomain Discovery",
            "osint": "OSINT Gathering",
            "pre_crawl": "Pre-crawl Analysis",
            "port_scan": "Port Scanning",
            "fetch_url": "URL Discovery",
            "intermediate_crawl": "Intermediate Crawl",
            "http_crawl": "HTTP Crawling",
            "screenshot": "Taking Screenshots",
            "vulnerability_scan": "Vulnerability Scanning",
            "nuclei_scan": "Nuclei Scanning",
            "nuclei_individual_severity_module": "Nuclei Scanning",
            "waf_detection": "WAF Detection",
            "dir_file_fuzz": "Directory Fuzzing",
            "dalfox_xss_scan": "XSS Scanning",
            "crlfuzz_scan": "CRLF Injection Scan",
            "post_crawl": "Post-crawl Analysis",
        }

        return task_display_names.get(task_name, task_name.replace("_", " ").title())

    def get_elapsed_time(self, scan_activity):
        """Get elapsed time since task started"""
        from django.utils import timezone

        from reNgine.core.time import get_time_taken

        return get_time_taken(timezone.now(), scan_activity.time)


class SecatorRunnerSerializer(serializers.ModelSerializer):
    """Serializer for SecatorRunner model with computed fields."""

    elapsed = serializers.SerializerMethodField()
    elapsed_seconds = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    status_code = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    done = serializers.SerializerMethodField()
    start_time = serializers.SerializerMethodField()

    class Meta:
        model = SecatorRunner
        fields = [
            "id",
            "runner_type",
            "runner_name",
            "status",
            "status_display",
            "status_code",
            "progress",
            "done",
            "created_at",
            "updated_at",
            "elapsed",
            "elapsed_seconds",
            "start_time",
            "scan_history",
            "domain",
            "celery_id",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_status(self, obj):
        """Get status from status field or runner_data as fallback."""
        if obj.status:
            return obj.status
        if obj.runner_data:
            return obj.runner_data.get("status", "PENDING")
        return "PENDING"

    def get_status_display(self, obj):
        """Get human-readable status."""
        status = self.get_status(obj)
        status_map = {
            "RUNNING": "Running",
            "SUCCESS": "Success",
            "FAILURE": "Failed",
            "FAILED": "Failed",
            "PENDING": "Pending",
            "REVOKED": "Aborted",
            "SKIPPED": "Skipped",
        }
        return status_map.get(status.upper(), "Unknown")

    def get_status_code(self, obj):
        """Get reNgine status code from Secator status."""
        from reNgine.secator import SecatorProgressSync

        status = self.get_status(obj)
        return SecatorProgressSync.map_secator_status_to_rengine(status)

    def get_progress(self, obj):
        """Get progress from runner_data."""
        return obj.runner_data.get("progress", 0) if obj.runner_data else 0

    def get_done(self, obj):
        """Get done flag from runner_data."""
        return obj.runner_data.get("done", False) if obj.runner_data else False

    def get_start_time(self, obj):
        """Get start time from runner_data or created_at."""
        if obj.runner_data and "start_time" in obj.runner_data:
            return obj.runner_data["start_time"]
        return obj.created_at.isoformat() if obj.created_at else None

    def get_elapsed(self, obj):
        """Calculate elapsed time since start as formatted string."""
        from django.utils import timezone

        from reNgine.core.time import get_time_taken
        from reNgine.utilities.time import parse_datetime_iso

        start_time = obj.created_at
        if obj.runner_data and "start_time" in obj.runner_data:
            start_time_str = obj.runner_data.get("start_time")
            if parsed_start := parse_datetime_iso(start_time_str):
                start_time = parsed_start

        return get_time_taken(timezone.now(), start_time) if start_time else "0s"

    def get_elapsed_seconds(self, obj):
        """Calculate elapsed time since start in seconds."""
        from django.utils import timezone

        from reNgine.utilities.time import parse_datetime_iso

        # Try to get elapsed from runner_data first (float in seconds)
        if obj.runner_data and "elapsed" in obj.runner_data:
            elapsed_value = obj.runner_data.get("elapsed")
            if isinstance(elapsed_value, (int, float)):
                return float(elapsed_value)

        # Calculate elapsed from start_time or created_at
        start_time = obj.created_at
        if obj.runner_data and "start_time" in obj.runner_data:
            start_time_str = obj.runner_data.get("start_time")
            if parsed_start := parse_datetime_iso(start_time_str):
                start_time = parsed_start

        if start_time:
            delta = timezone.now() - start_time
            return delta.total_seconds()

        return 0.0


class SecatorWorkerListSerializer(serializers.ModelSerializer):
    """Serializer for SecatorWorker list; excludes credentials."""

    class Meta:
        model = SecatorWorker
        fields = [
            "id",
            "name",
            "ssh_host",
            "ssh_port",
            "ssh_ok",
            "container_running",
            "api_reachable",
            "last_status_at",
            "last_error",
            "is_active",
            "api_access_type",
            "api_tunnel_port",
            "api_url",
            "https_pull_agent",
            "https_pull_verify_ssl",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class SecatorWorkerDetailSerializer(serializers.ModelSerializer):
    """Serializer for SecatorWorker detail with runners; excludes secret fields."""

    runners = SecatorRunnerSerializer(source="secatorrunner_set", many=True, read_only=True)

    class Meta:
        model = SecatorWorker
        fields = [
            "id",
            "name",
            "ssh_host",
            "ssh_port",
            "ssh_user",
            "ssh_auth_type",
            "deploy_path",
            "container_name",
            "ssh_ok",
            "container_running",
            "api_reachable",
            "last_status_at",
            "last_error",
            "is_active",
            "api_access_type",
            "api_tunnel_port",
            "api_url",
            "https_pull_agent",
            "https_pull_verify_ssl",
            "created_at",
            "updated_at",
            "runners",
        ]
        read_only_fields = fields


class SecatorWorkerCreateUpdateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating SecatorWorker (used by UI form)."""

    class Meta:
        model = SecatorWorker
        fields = [
            "id",
            "name",
            "ssh_host",
            "ssh_port",
            "ssh_user",
            "ssh_auth_type",
            "ssh_key_path",
            "ssh_password_encrypted",
            "deploy_path",
            "container_name",
            "is_active",
            "api_access_type",
            "api_tunnel_port",
            "api_url",
            "https_pull_agent",
            "https_pull_verify_ssl",
        ]
        read_only_fields = ["id"]


class OrganizationSerializer(serializers.ModelSerializer):
    domains = serializers.SerializerMethodField()

    def get_domains(self, obj):
        return OrganizationTargetsSerializer(obj.get_domains(), many=True).data

    class Meta:
        model = Organization
        fields = ["id", "name", "description", "insert_date", "domains", "project"]


class EngineSerializer(serializers.ModelSerializer):
    tasks = serializers.SerializerMethodField()
    scan_type_display = serializers.SerializerMethodField()

    def get_tasks(self, obj):
        try:
            yaml_config = yaml.safe_load(obj.yaml_configuration)
            if not isinstance(yaml_config, dict):
                return []
        except Exception:
            return []
        return sorted([task for task in yaml_config.keys() if task in ENGINE_NAMES])

    def get_scan_type_display(self, obj):
        return obj.get_scan_type_display()

    class Meta:
        model = EngineType
        fields = ["id", "engine_name", "scan_type", "scan_type_display", "tasks"]


class OrganizationTargetsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ["name"]


class ScopeDatatableSerializer(serializers.ModelSerializer):
    """Serializer for scope list DataTables API. Expects annotated target_count, worker_count."""

    organization_name = serializers.CharField(source="organization.name", read_only=True)
    scope_type = serializers.SerializerMethodField()
    target_count = serializers.IntegerField(read_only=True, default=0)
    worker_count = serializers.IntegerField(read_only=True, default=0)
    insert_date_humanized = serializers.SerializerMethodField()
    attack_surface = serializers.SerializerMethodField()
    attack_surface_count = serializers.SerializerMethodField()

    class Meta:
        model = Scope
        fields = [
            "id",
            "name",
            "organization_name",
            "scope_type",
            "start_date",
            "end_date",
            "target_count",
            "worker_count",
            "insert_date",
            "insert_date_humanized",
            "attack_surface",
            "attack_surface_count",
        ]

    def get_scope_type(self, obj):
        return obj.get_scope_type_display() or ""

    def get_insert_date_humanized(self, obj):
        return naturaltime(obj.insert_date).title() if obj.insert_date else ""

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        # DataTables queries should annotate `llm_attack_surface_count`; returning 0 avoids
        # per-row DB access when this serializer is used on un-annotated instances.
        return False

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        # See `get_attack_surface` for rationale.
        return 0


class OrganizationDatatableSerializer(serializers.ModelSerializer):
    """Serializer for organization list DataTables API. Expects annotated scope_count, total_targets."""

    scope_count = serializers.IntegerField(read_only=True, default=0)
    total_targets = serializers.IntegerField(read_only=True, default=0)
    insert_date_humanized = serializers.SerializerMethodField()
    attack_surface = serializers.SerializerMethodField()
    attack_surface_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "description",
            "scope_count",
            "total_targets",
            "insert_date",
            "insert_date_humanized",
            "attack_surface",
            "attack_surface_count",
        ]

    def get_insert_date_humanized(self, obj):
        return naturaltime(obj.insert_date).title() if obj.insert_date else ""

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        # DataTables queries should annotate `llm_attack_surface_count`; returning `False`
        # avoids per-row database access when this serializer is used without annotation.
        return False

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        # DataTables queries should annotate `llm_attack_surface_count`; returning `0`
        # avoids per-row database access when this serializer is used without annotation.
        return 0


class ScanHistoryDatatableSerializer(serializers.ModelSerializer):
    """Serializer for scan history list DataTables API. Flat fields for table columns."""

    target_value = serializers.SerializerMethodField()
    target_id = serializers.SerializerMethodField()
    organizations = serializers.SerializerMethodField()
    most_recent_scan = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()
    scan_engine_text = serializers.SerializerMethodField()
    worker_name = serializers.SerializerMethodField()
    last_scan = serializers.SerializerMethodField()
    initiated_by = serializers.SerializerMethodField()
    status_text = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    scope_name = serializers.SerializerMethodField()
    attack_surface = serializers.SerializerMethodField()
    attack_surface_count = serializers.SerializerMethodField()

    class Meta:
        model = ScanHistory
        fields = [
            "id",
            "target_value",
            "target_id",
            "organizations",
            "most_recent_scan",
            "summary",
            "scan_engine_text",
            "worker_name",
            "last_scan",
            "initiated_by",
            "status_text",
            "scan_status",
            "progress",
            "scope_name",
            "attack_surface",
            "attack_surface_count",
        ]

    def get_target_value(self, obj):
        return obj.target.value if obj.target else ""

    def get_target_id(self, obj):
        return obj.target_id or None

    def get_organizations(self, obj):
        target = obj.target
        return [org.name for org in target.get_organization()] if target else []

    def get_most_recent_scan(self, obj):
        return obj.id

    def get_summary(self, obj):
        from reNgine.services.scan_finding_metrics import (
            SCAN_HISTORY_IP_ALIVE_ATTR,
            SCAN_HISTORY_IP_COUNT_ATTR,
            get_ip_address_metrics_for_scan,
        )

        domain_count = obj.get_domain_count() if callable(getattr(obj, "get_domain_count", None)) else 0
        subdomain_count = obj.get_subdomain_count() if callable(getattr(obj, "get_subdomain_count", None)) else 0
        endpoint_count = obj.get_endpoint_count() if callable(getattr(obj, "get_endpoint_count", None)) else 0
        vuln_count = obj.get_vulnerability_count() if callable(getattr(obj, "get_vulnerability_count", None)) else 0
        secret_count = obj.get_secret_count() if callable(getattr(obj, "get_secret_count", None)) else 0
        exploit_count = obj.get_exploit_count() if callable(getattr(obj, "get_exploit_count", None)) else 0
        ip_total = getattr(obj, SCAN_HISTORY_IP_COUNT_ATTR, _CACHE_MISSING)
        ip_alive = getattr(obj, SCAN_HISTORY_IP_ALIVE_ATTR, _CACHE_MISSING)
        if ip_total is not _CACHE_MISSING and ip_alive is not _CACHE_MISSING:
            ip_address_count, ip_alive_count = ip_total, ip_alive
        else:
            ip_address_count, ip_alive_count = get_ip_address_metrics_for_scan(obj.id)
        return {
            "domain_count": domain_count,
            "subdomain_count": subdomain_count,
            "endpoint_count": endpoint_count,
            "vulnerability_count": vuln_count,
            "secret_count": secret_count,
            "exploit_count": exploit_count,
            "ip_address_count": ip_address_count,
            "ip_alive_count": ip_alive_count,
        }

    def get_scan_engine_text(self, obj):
        return obj.scan_engine_used

    def get_worker_name(self, obj):
        return getattr(obj, "secator_worker_name", None) or "Local"

    def get_last_scan(self, obj):
        return naturalday(obj.start_scan_date).title() if obj.start_scan_date else None

    def get_initiated_by(self, obj):
        return obj.initiated_by.username if obj.initiated_by else ""

    def get_status_text(self, obj):
        from reNgine.definitions import SCAN_STATUSES

        status = getattr(obj, "scan_status", None)
        if status is None:
            return "Unknown"
        return dict(SCAN_STATUSES).get(status, "Unknown")

    def get_progress(self, obj):
        return obj.get_progress() if callable(getattr(obj, "get_progress", None)) else 0

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        # DataTables queries should annotate `llm_attack_surface_count`; returning False
        # avoids per-row DB access when this serializer is used without annotation.
        return False

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        # See `get_attack_surface` for rationale.
        return 0

    def get_scope_name(self, obj):
        if not obj.target:
            return ""
        first = get_scope_for_target(obj.target)
        return first.name if first else ""


class SubScanDatatableSerializer(serializers.ModelSerializer):
    """Serializer for subscan history list DataTables API. Alias fields for column names."""

    target_name = serializers.SerializerMethodField()
    scan_engine_text = serializers.SerializerMethodField()
    worker_name = serializers.SerializerMethodField()
    scan_started = serializers.DateTimeField(source="start_scan_date", read_only=True)
    status_text = serializers.SerializerMethodField()
    status_code = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()

    class Meta:
        model = SubScan
        fields = [
            "id",
            "scan_history",
            "target_name",
            "scan_engine_text",
            "worker_name",
            "scan_started",
            "status_text",
            "status_code",
            "progress",
        ]

    def get_target_name(self, obj):
        if obj.subdomain:
            return obj.subdomain.name
        if obj.scan_history and obj.scan_history.target:
            return f"Domain-level: {obj.scan_history.target.value}"
        return ""

    def get_scan_engine_text(self, obj):
        return obj.scan_engine_used

    def get_worker_name(self, obj):
        return getattr(obj.scan_history, "secator_worker_name", None) or "Local"

    def get_status_code(self, obj):
        return getattr(obj, "status_code", None) if hasattr(obj, "status_code") else getattr(obj, "status", None)

    def get_status_text(self, obj):
        code = self.get_status_code(obj)
        return str(code) if code is not None else ""

    def get_progress(self, obj):
        fn = getattr(obj, "get_progress", None)
        return fn() if callable(fn) else 0


class ScanScheduleDatatableSerializer(serializers.ModelSerializer):
    """Serializer for scheduled scans list DataTables API."""

    description = serializers.SerializerMethodField()
    frequency = serializers.SerializerMethodField()
    last_run = serializers.SerializerMethodField()
    run_count = serializers.IntegerField(source="total_run_count", read_only=True)

    class Meta:
        model = ScanSchedule
        fields = [
            "id",
            "description",
            "frequency",
            "last_run",
            "run_count",
            "one_off",
            "enabled",
        ]

    def get_description(self, obj):
        parts = (obj.name or "").split(":", 1)
        return parts[0] if parts else ""

    def get_frequency(self, obj):
        if obj.schedule_mode == "periodic":
            label = (
                obj.get_frequency_type_display_for_value()
                if hasattr(obj, "get_frequency_type_display_for_value")
                else (obj.get_frequency_type_display() or "")
            )
            return f"Every {obj.frequency_value} {label}" if obj.frequency_value else ""
        if obj.scheduled_time:
            return f"At {obj.scheduled_time.strftime('%Y-%m-%d %H:%M')} UTC"
        return "—"

    def get_last_run(self, obj):
        if not obj.last_run_at:
            return None
        return obj.last_run_at.strftime("%Y-%m-%d %H:%M") + " UTC"


def _s3_bucket_permission_labels(bucket, prefix):
    """Build list of permission labels (READ, WRITE, etc.) for auth or all users."""
    labels = []
    if getattr(bucket, f"perm_{prefix}_read", 0) == 1:
        labels.append("READ")
    if getattr(bucket, f"perm_{prefix}_write", 0) == 1:
        labels.append("WRITE")
    if getattr(bucket, f"perm_{prefix}_read_acl", 0) == 1:
        labels.append("Read_ACP")
    if getattr(bucket, f"perm_{prefix}_write_acl", 0) == 1:
        labels.append("WRITE_ACP")
    if getattr(bucket, f"perm_{prefix}_full_control", 0) == 1:
        labels.append("FULL_CONTROL")
    return labels


class S3BucketDatatableSerializer(serializers.ModelSerializer):
    """
    Serializer for S3 buckets DataTables API.

    Consuming template: startScan/detail_scan.html (S3 tab).
    Column map: web.api.helpers.datatables.DATATABLE_COLUMN_MAP_S3_BUCKETS.
    """

    owner = serializers.SerializerMethodField()
    objects_count = serializers.IntegerField(source="num_objects", read_only=True)
    bucket_size = serializers.IntegerField(source="size", read_only=True)
    auth_users_permission = serializers.SerializerMethodField()
    all_users_permission = serializers.SerializerMethodField()

    class Meta:
        model = S3Bucket
        fields = [
            "name",
            "region",
            "provider",
            "owner",
            "objects_count",
            "bucket_size",
            "auth_users_permission",
            "all_users_permission",
        ]

    def get_owner(self, obj):
        parts = []
        if obj.owner_id:
            parts.append(f"ID: {obj.owner_id}")
        if obj.owner_display_name:
            parts.append(f"Display Name: {obj.owner_display_name}")
        return ", ".join(parts) if parts else ""

    def get_auth_users_permission(self, obj):
        return ", ".join(_s3_bucket_permission_labels(obj, "auth_users"))

    def get_all_users_permission(self, obj):
        return ", ".join(_s3_bucket_permission_labels(obj, "all_users"))


class WordlistDatatableSerializer(serializers.ModelSerializer):
    """
    Serializer for wordlist list DataTables API.

    Consuming template: scanEngine/wordlist/index.html.
    Column map: web.api.helpers.datatables.DATATABLE_COLUMN_MAP_WORDLIST.
    """

    action = serializers.SerializerMethodField()

    class Meta:
        model = Wordlist
        fields = ["id", "name", "short_name", "count", "action"]

    def get_action(self, obj):
        name_js = json.dumps(obj.name)
        return (
            f'<a href="#" class="btn btn-sm btn-soft-danger btnDelWordlist" data-toggle="tooltip" '
            f'data-placement="top" title="Delete Wordlist" '
            f"onclick=\"delete_api({obj.id}, {name_js}, 'wordlist'); return false;\">"
            f'<i class="fe-trash-2"></i></a>'
        )


def _engine_type_tasks_html(engine):
    """Build task badges HTML for EngineType datatable (matches scanEngine/index.html)."""
    task_badges = {
        "subdomain_discovery": (
            '<span class="badge badge-soft-success task-badge" data-toggle="tooltip" title="Subdomain Discovery"><i class="fas fa-search"></i> SD</span>',
        ),
        "waf_detection": (
            '<span class="badge badge-soft-info task-badge" data-toggle="tooltip" title="WAF Detection"><i class="fas fa-shield-alt"></i> WAF</span>',
        ),
        "screenshot": (
            '<span class="badge badge-soft-primary task-badge" data-toggle="tooltip" title="Screenshot"><i class="fas fa-camera"></i> SS</span>',
        ),
        "osint": (
            '<span class="badge badge-soft-warning task-badge" data-toggle="tooltip" title="OSINT"><i class="fas fa-globe"></i> OSINT</span>',
        ),
        "port_scan": (
            '<span class="badge badge-soft-danger task-badge" data-toggle="tooltip" title="Port Scan"><i class="fas fa-network-wired"></i> PS</span>',
        ),
        "dir_file_fuzz": (
            '<span class="badge badge-soft-secondary task-badge" data-toggle="tooltip" title="Directory &amp; Files Discovery"><i class="fas fa-folder-open"></i> DF</span>',
        ),
        "fetch_url": (
            '<span class="badge badge-soft-dark task-badge" data-toggle="tooltip" title="Fetch URLs"><i class="fas fa-link"></i> URL</span>',
        ),
        "vulnerability_scan": (
            '<span class="badge badge-soft-orange task-badge" data-toggle="tooltip" title="Vulnerability Scan"><i class="fas fa-bug"></i> VULN</span>',
        ),
    }
    tasks = getattr(engine, "tasks", None) or []
    parts = [task_badges.get(t, (f'<span class="badge badge-soft-secondary task-badge">{t}</span>',))[0] for t in tasks]
    if config_params := getattr(engine, "get_config_parameters", lambda: {})():
        config_display = getattr(engine, "get_config_parameters_display", lambda: "")()
        config_title = html.escape(config_display) if config_display else ""
        parts.append(
            f'<span class="badge badge-soft-purple task-badge config-badge" data-toggle="tooltip" '
            f'data-placement="top" data-html="true" title="{config_title}">'
            f'<span class="config-count">{len(config_params)}</span><i class="fas fa-cog"></i> CONFIG</span>'
        )
    count = getattr(engine, "get_tasks_count", lambda: 0)()
    summary = f"{count} task{'s' if count != 1 else ''} enabled"
    return '<div class="task-badges">' + "".join(parts) + '</div><div class="task-summary">' + summary + "</div>"


class EngineTypeDatatableSerializer(serializers.ModelSerializer):
    """
    Serializer for scan engine list DataTables API (legacy EngineType).

    Consuming template: scanEngine/index.html.
    Column map: web.api.helpers.datatables.DATATABLE_COLUMN_MAP_SCAN_ENGINE.
    """

    engine_name_display = serializers.SerializerMethodField()
    engine_type_display = serializers.SerializerMethodField()
    scan_type_display = serializers.SerializerMethodField()
    tasks_html = serializers.SerializerMethodField()
    action = serializers.SerializerMethodField()

    class Meta:
        model = EngineType
        fields = [
            "id",
            "engine_name",
            "engine_name_display",
            "engine_type_display",
            "scan_type_display",
            "tasks_html",
            "action",
        ]

    def get_engine_name_display(self, obj):
        update_url = reverse("update_engine", args=[obj.id])
        return (
            f'<a href="{html.escape(update_url)}" class="open-domain text-primary">{html.escape(obj.engine_name)}</a>'
        )

    def get_engine_type_display(self, obj):
        return "Default" if obj.default_engine else "Custom"

    def get_scan_type_display(self, obj):
        return obj.get_scan_type_display() or (obj.scan_type or "").title()

    def get_tasks_html(self, obj):
        return _engine_type_tasks_html(obj)

    def get_action(self, obj):
        update_url = reverse("update_engine", args=[obj.id])
        duplicate_url = reverse("duplicate_engine", args=[obj.id])
        name_js = json.dumps(obj.engine_name)
        return (
            f'<a href="{html.escape(update_url)}" class="open-domain" data-toggle="tooltip" title="Edit Engine">'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg></a> '
            f'<a href="{html.escape(duplicate_url)}" class="text-info" data-toggle="tooltip" title="Duplicate {html.escape(obj.engine_name)} Engine">'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></a> '
            f'<a onclick="delete_api({obj.id}, {name_js}, \'scanEngine\')" class="btnDelDomain text-danger" href="#" data-toggle="tooltip" title="Delete {html.escape(obj.engine_name)} Engine">'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg></a>'
        )


class VisualiseVulnerabilitySerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField("get_description")

    class Meta:
        model = Vulnerability
        fields = ["description", "http_url"]

    def get_description(self, vulnerability):
        return vulnerability.name


class VisualiseTechnologySerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField("get_description")

    class Meta:
        model = Technology
        fields = ["description"]

    def get_description(self, tech):
        return tech.name


class VisualisePortSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    is_uncommon = serializers.SerializerMethodField()

    class Meta:
        model = Port
        fields = ["description", "title", "is_uncommon"]

    def get_description(self, port):
        return f"{port.number}/{port.service_name}/{port.service_name}"

    def get_title(self, port):
        return "Uncommon Port" if port.is_uncommon else "Port"

    def get_is_uncommon(self, port):
        return port.is_uncommon


class VisualiseIpSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField("get_description")
    children = serializers.SerializerMethodField("get_children")

    class Meta:
        model = IpAddress
        fields = ["description", "children"]

    def get_description(self, ip):
        return ip.address

    def get_children(self, ip):
        ports = ip.ports.all()
        serializer = VisualisePortSerializer(ports, many=True)
        return serializer.data


class VisualiseEndpointSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField("get_description")

    class Meta:
        model = EndPoint
        fields = ["description", "http_url"]

    def get_description(self, endpoint):
        return endpoint.http_url


class VisualiseSubdomainSerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField("get_children")
    description = serializers.SerializerMethodField("get_description")
    title = serializers.SerializerMethodField("get_title")

    class Meta:
        model = Subdomain
        fields = ["description", "children", "http_status", "title"]

    def get_description(self, subdomain):
        return subdomain.name

    def get_title(self, subdomain):
        if get_interesting_subdomains(subdomain.scan_history.id).filter(name=subdomain.name).exists():
            return "Interesting"

    def get_children(self, subdomain_name):
        scan_history = self.context.get("scan_history")
        subdomains = Subdomain.objects.filter(scan_history=scan_history).filter(name=subdomain_name)

        ips = IpAddress.objects.filter(ip_addresses__in=subdomains)
        ip_serializer = VisualiseIpSerializer(ips, many=True, context={"scan_id": scan_history.id})

        # endpoint = EndPoint.objects.filter(
        #     scan_history=self.context.get('scan_history')).filter(
        #     subdomain__name=subdomain_name)
        # endpoint_serializer = VisualiseEndpointSerializer(endpoint, many=True)

        technologies = Technology.objects.filter(technologies__in=subdomains)
        tech_serializer = VisualiseTechnologySerializer(technologies, many=True)

        vulnerability = Vulnerability.objects.filter(scan_history=scan_history).filter(subdomain=subdomain_name)

        return_data = []
        if ip_serializer.data:
            return_data.append({"description": "IPs", "children": ip_serializer.data})
        # if endpoint_serializer.data:
        #     return_data.append({
        #         'description': 'Endpoints',
        #         'children': endpoint_serializer.data
        #     })
        if tech_serializer.data:
            return_data.append({"description": "Technologies", "children": tech_serializer.data})

        if vulnerability:
            self._group_vulnerabilities_by_severity_(vulnerability, return_data)

        # Get screenshots from endpoints instead of subdomains
        endpoints_with_screenshots = EndPoint.objects.filter(
            scan_history=scan_history, subdomain__name=subdomain_name.name, screenshot_path__isnull=False
        )
        if endpoints_with_screenshots.exists():
            screenshot_data = [
                {
                    "description": endpoint.http_url,
                    "screenshot_path": endpoint.screenshot_path,
                    "screenshot_url": build_scan_file_url(endpoint.screenshot_path),
                }
                for endpoint in endpoints_with_screenshots
            ]
            return_data.append({"description": "Screenshots", "children": screenshot_data})

        return return_data

    def _group_vulnerabilities_by_severity_(self, vulnerability, return_data):
        vulnerability_data = []
        if critical := vulnerability.filter(severity=4):
            critical_serializer = VisualiseVulnerabilitySerializer(critical, many=True)
            vulnerability_data.append({"description": "Critical", "children": critical_serializer.data})
        if high := vulnerability.filter(severity=3):
            high_serializer = VisualiseVulnerabilitySerializer(high, many=True)
            vulnerability_data.append({"description": "High", "children": high_serializer.data})
        if medium := vulnerability.filter(severity=2):
            medium_serializer = VisualiseVulnerabilitySerializer(medium, many=True)
            vulnerability_data.append({"description": "Medium", "children": medium_serializer.data})
        if low := vulnerability.filter(severity=1):
            low_serializer = VisualiseVulnerabilitySerializer(low, many=True)
            vulnerability_data.append({"description": "Low", "children": low_serializer.data})
        if info := vulnerability.filter(severity=0):
            info_serializer = VisualiseVulnerabilitySerializer(info, many=True)
            vulnerability_data.append({"description": "Informational", "children": info_serializer.data})
        if uknown := vulnerability.filter(severity=-1):
            uknown_serializer = VisualiseVulnerabilitySerializer(uknown, many=True)
            vulnerability_data.append({"description": "Unknown", "children": uknown_serializer.data})

        if vulnerability_data:
            return_data.append({"description": "Vulnerabilities", "children": vulnerability_data})


class VisualiseEmailSerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField("get_title")
    description = serializers.SerializerMethodField("get_description")

    class Meta:
        model = Email
        fields = ["description", "password", "title"]

    def get_description(self, email):
        if email.password:
            return f"{email.address} > {email.password}"
        return email.address

    def get_title(self, email):
        if email.password:
            return "Exposed Creds"


class VisualiseDorkSerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField("get_title")
    description = serializers.SerializerMethodField("get_description")
    http_url = serializers.SerializerMethodField("get_http_url")

    class Meta:
        model = Dork
        fields = ["title", "description", "http_url"]

    def get_title(self, dork):
        return dork.type

    def get_description(self, dork):
        return dork.type

    def get_http_url(self, dork):
        return dork.url


class VisualiseEmployeeSerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField("get_description")

    class Meta:
        model = Employee
        fields = ["description"]

    def get_description(self, employee):
        if employee.designation:
            return f"{employee.name}--{employee.designation}"
        return employee.name


class VisualiseDataSerializer(serializers.ModelSerializer):
    title = serializers.ReadOnlyField(default="Target")
    description = serializers.SerializerMethodField("get_description")
    children = serializers.SerializerMethodField("get_children")

    class Meta:
        model = ScanHistory
        fields = ["description", "title", "children"]

    def get_description(self, scan_history):
        return scan_history.target.value if scan_history.target else ""

    def get_children(self, history):
        scan_history = ScanHistory.objects.filter(id=history.id)

        subdomain = Subdomain.objects.filter(scan_history=history)
        subdomain_serializer = VisualiseSubdomainSerializer(subdomain, many=True, context={"scan_history": history})

        processed_subdomains = self.process_subdomains(subdomain_serializer.data)

        email = Email.objects.filter(emails__in=scan_history)
        email_serializer = VisualiseEmailSerializer(email, many=True)

        dork = Dork.objects.filter(dorks__in=scan_history)
        dork_serializer = VisualiseDorkSerializer(dork, many=True)
        processed_dorks = self.process_dorks(dork_serializer.data)

        employee = Employee.objects.filter(employees__in=scan_history)
        employee_serializer = VisualiseEmployeeSerializer(employee, many=True)

        metainfo = MetaFinderDocument.objects.filter(scan_history__id=history.id)

        return_data = []

        if processed_subdomains:
            return_data.append({"description": "Subdomains", "children": processed_subdomains})

        osint_data = []
        if email_serializer.data:
            osint_data.append({"description": "Emails", "children": email_serializer.data})
        if employee_serializer.data:
            osint_data.append({"description": "Employees", "children": employee_serializer.data})
        if processed_dorks:
            osint_data.append({"description": "Dorks", "children": processed_dorks})

        if metainfo:
            self._process_metainfo_for_osint(metainfo, osint_data, return_data)
        if osint_data:
            return_data.append({"description": "OSINT", "children": osint_data})

        return return_data

    def _process_metainfo_for_osint(self, metainfo, osint_data, return_data):
        metainfo_data = []
        if usernames := (
            metainfo.annotate(description=F("author"))
            .values("description")
            .distinct()
            .annotate(children=Value([], output_field=JSONField()))
            .filter(author__isnull=False)
        ):
            metainfo_data.append({"description": "Usernames", "children": usernames})

        if software := (
            metainfo.annotate(description=F("producer"))
            .values("description")
            .distinct()
            .annotate(children=Value([], output_field=JSONField()))
            .filter(producer__isnull=False)
        ):
            metainfo_data.append({"description": "Software", "children": software})

        if os := (
            metainfo.annotate(description=F("os"))
            .values("description")
            .distinct()
            .annotate(children=Value([], output_field=JSONField()))
            .filter(os__isnull=False)
        ):
            metainfo_data.append({"description": "OS", "children": os})

        if metainfo:
            osint_data.append({"description": "Metainfo", "children": metainfo_data})

        return_data.append({"description": "OSINT", "children": osint_data})
        return return_data

    def process_subdomains(self, subdomains):
        for subdomain in subdomains:
            if "children" in subdomain:
                vuln_dict = defaultdict(list)
                for child in subdomain["children"]:
                    if child.get("description") == "Vulnerabilities":
                        for vuln_severity in child["children"]:
                            severity = vuln_severity["description"]
                            for vuln in vuln_severity["children"]:
                                vuln_key = (vuln["description"], severity)
                                if vuln_key not in vuln_dict:
                                    vuln_dict[vuln_key] = vuln

                # Reconstruct vulnerabilities structure without duplicates
                new_vuln_structure = []
                for severity in ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]:
                    if severity_vulns := [v for k, v in vuln_dict.items() if k[1] == severity]:
                        new_vuln_structure.append({"description": severity, "children": severity_vulns})

                # Replace old structure with new
                subdomain["children"] = [
                    child for child in subdomain["children"] if child.get("description") != "Vulnerabilities"
                ]
                if new_vuln_structure:
                    subdomain["children"].append({"description": "Vulnerabilities", "children": new_vuln_structure})

        return subdomains

    def process_dorks(self, dorks):
        unique_dorks = {}
        for dork in dorks:
            dork_key = (dork["description"], dork.get("dork_type", ""))
            if dork_key not in unique_dorks:
                unique_dorks[dork_key] = dork

        return list(unique_dorks.values())


class SubdomainChangesSerializer(serializers.ModelSerializer):
    change = serializers.SerializerMethodField("get_change")
    is_interesting = serializers.SerializerMethodField("get_is_interesting")
    attack_surface = serializers.SerializerMethodField("get_attack_surface")
    attack_surface_count = serializers.SerializerMethodField("get_attack_surface_count")

    class Meta:
        model = Subdomain
        fields = [
            "id",
            "scan_history",
            "domain",
            "name",
            "is_imported_subdomain",
            "is_important",
            "http_url",
            "http_header_path",
            "discovered_date",
            "cname",
            "is_cdn",
            "cdn_name",
            "http_status",
            "content_type",
            "response_time",
            "webserver",
            "content_length",
            "page_title",
            "technologies",
            "ip_addresses",
            "directories",
            "waf",
            "attack_surface",
            "attack_surface_count",
            "change",
            "is_interesting",
        ]

    def get_change(self, Subdomain):
        return Subdomain.change

    def get_is_interesting(self, Subdomain):
        return get_interesting_subdomains(Subdomain.scan_history.id).filter(name=Subdomain.name).exists()

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        from reNgine.llm.attack_surface_storage import parent_has_llm_attack_surface_analyses

        return parent_has_llm_attack_surface_analyses(obj)

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        from reNgine.llm.attack_surface_storage import count_llm_attack_surface_analyses_for_parent

        return count_llm_attack_surface_analyses_for_parent(obj)


class EndPointChangesSerializer(serializers.ModelSerializer):
    change = serializers.SerializerMethodField("get_change")
    screenshot_url = serializers.SerializerMethodField()
    stored_response_url = serializers.SerializerMethodField()

    class Meta:
        model = EndPoint
        fields = [
            "id",
            "scan_history",
            "domain",
            "subdomain",
            "http_url",
            "page_title",
            "content_type",
            "webserver",
            "response_time",
            "http_status",
            "content_length",
            "techs",
            "screenshot_path",
            "screenshot_url",
            "stored_response_path",
            "stored_response_url",
            "matched_gf_patterns",
            "change",
        ]

    def get_change(self, EndPoint):
        return EndPoint.change

    def get_screenshot_url(self, obj):
        # Served with project-scoped access via api.scan_file.ServeScanFile
        return build_scan_file_url(obj.screenshot_path)

    def get_stored_response_url(self, obj):
        # Served with project-scoped access via api.scan_file.ServeScanFile
        return build_scan_file_url(obj.stored_response_path)


class InterestingSubdomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = ["name"]


class EmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = ["id", "address", "password"]


class DorkSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dork
        fields = ["id", "type", "url"]


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = ["id", "name", "designation"]


class MetafinderDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetaFinderDocument
        fields = [
            "id",
            "domain",
            "scan_history",
            "subdomain",
            "url",
            "doc_name",
            "title",
            "http_status",
            "producer",
            "creator",
            "creation_date",
            "modified_date",
            "author",
            "os",
        ]
        depth = 1


class MetafinderUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetaFinderDocument
        fields = ["author"]


class InterestingEndPointSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndPoint
        fields = ["http_url"]


class TechnologyCountSerializer(serializers.Serializer):
    count = serializers.CharField()
    name = serializers.CharField()


class DorkCountSerializer(serializers.Serializer):
    count = serializers.CharField()
    type = serializers.CharField()


class TechnologySerializer(serializers.ModelSerializer):
    stored_response_url = serializers.SerializerMethodField()

    class Meta:
        model = Technology
        fields = ["id", "name", "value", "category", "stored_response_path", "stored_response_url"]

    def get_stored_response_url(self, obj):
        # Served with project-scoped access via api.scan_file.ServeScanFile
        return build_scan_file_url(obj.stored_response_path)


class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = [
            "id",
            "number",
            "service_name",
            "description",
            "is_uncommon",
            "ip_address",
            "state",
            "cpes",
            "protocol",
            "host",
        ]


def _collect_sorted_service_labels_for_ip_port(
    ip_address: Any,
    port_num: int,
    cache: MutableMapping[Any, Any],
) -> tuple[str, ...]:
    """
    Unique service labels for ``ip_address`` at ``port_num``, cached per serializer context.

    Requires a persisted ``IpAddress`` (non-null primary key). Unsaved instances return ``()``
    without caching to avoid collisions on ``(None, port_num)``.

    Uses only prefetched ``ports`` when present to avoid lazy queries and N+1 patterns. If
    ``ports`` were not prefetched, logs once per ``cache`` and returns an empty tuple (callers
    should use ``prefetch_related('ports')`` / ``ip_addresses__ports`` when exposing port-filtered
    services).

    Relies on Django's ``_prefetched_objects_cache`` (private); re-check after ORM upgrades if
    prefetch behavior changes.
    """
    if getattr(ip_address, "pk", None) is None:
        return ()
    key = (ip_address.id, port_num)
    if key in cache:
        return cache[key]
    # Django internal: set when `prefetch_related("ports")` was applied on the queryset.
    prefetch_cache = getattr(ip_address, "_prefetched_objects_cache", None)
    if prefetch_cache is None or "ports" not in prefetch_cache:
        if not cache.get(_SERVICE_LABELS_BY_IP_PORT_CACHE_WARN_KEY):
            cache[_SERVICE_LABELS_BY_IP_PORT_CACHE_WARN_KEY] = True
            logger.log_line(
                PREFIX_API_SERIALIZERS,
                "SERVICE_LABELS_IP_PORT",
                "IpAddress id=%s: ports not prefetched while collecting service labels for port %s; "
                "expect empty service column unless queryset uses prefetch_related('ports')."
                % (getattr(ip_address, "pk", None), port_num),
                level="warning",
            )
        cache[key] = ()
        return cache[key]
    labels: list[str] = []
    seen: set[str] = set()
    for p in prefetch_cache["ports"]:
        if p.number != port_num:
            continue
        label = (p.service_name or "").strip() or (p.description or "").strip() or ""
        if label and label not in seen:
            seen.add(label)
            labels.append(label)
    out = tuple(sorted(labels))
    cache[key] = out
    return out


def _format_service_labels_tuple(labels: tuple[str, ...]) -> str:
    return ", ".join(labels) if labels else "-"


# Per-request serializer context keys (avoid mutable state on serializer instances).
_CTX_WARN_ENDPOINT_TECHS_NOT_PREFETCHED = "_warned_endpoint_techs_not_prefetched"
_CTX_WARN_DEFAULT_ENDPOINT_LIST_TECHS = "_warned_default_endpoint_list_missing_techs_prefetch"
_CTX_EVALUATED_DEFAULT_ENDPOINTS_BY_IP_ID = "_evaluated_default_endpoints_by_ip_id"
_SERVICE_LABELS_BY_IP_PORT_CACHE_WARN_KEY = "__ports_prefetch_warning_emitted__"


class DefaultEndpointTechnologyMixin:
    """
    Shared serialization for default ``EndPoint`` rows (``is_default=True``) and their ``techs``.

    Querysets are built via ``reNgine.services.default_endpoint_queryset.apply_endpoint_port_and_techs_related``
    so ``techs`` are always prefetched
    without relying on Django queryset internals. Lists from ``Subdomain.default_endpoint_list``
    must prefetch ``techs`` on the source queryset; otherwise a one-time warning is logged when
    that list is first built.

    List views should pass ``scan_id`` and ``target_id`` via ``api.helpers.query.datatable_ip_list_serializer_context``
    or ``datatable_subdomain_list_serializer_context`` so nested serializers and default-endpoint
    queries stay scoped consistently.

    Serializers that need the same default-endpoint technology payload should inherit this mixin
    rather than duplicating aggregation. Currently only ``IpSerializer`` and ``SubdomainSerializer``
    use it; thinner endpoint serializers (e.g. list-only) stay without it.

    **API / UI contract (keep in sync with ``web/static/custom/datatables/renderers_subdomain_endpoint.js``):**

    - ``endpoint_defaults_by_port`` (always serialize on affected DataTables rows): ``list[dict]`` ordered
      by port then endpoint id. Each dict has ``id``, ``http_url``, ``port`` (``int | None`` from the
      ``Port`` FK), ``content_type``, ``webserver``, and ``technologies`` (list of technology dicts:
      ``id``, ``name``, ``value``, ``category``, ``stored_response_path``, ``stored_response_url``).
    - ``technologies`` on the same serializers: flat aggregate of unique technologies across default
      endpoints (legacy / summary column). When ``endpoint_defaults_by_port`` is missing or not an
      array (older servers), the UI falls back to rendering this flat list once per row with a
      one-time console warning.
    """

    def _iter_endpoint_tech_instances_for_serialization(self, endpoint: Any) -> list[Any]:
        """
        Return ``Technology`` instances for ``endpoint.techs``, respecting prefetch when present.

        If ``techs`` is missing or not prefetched, logs at most once per serializer context;
        unprefetched access still runs queries so row data stays correct when the contract breaks.
        """
        techs_rel = getattr(endpoint, "techs", None)
        if techs_rel is None:
            return []
        # Django internal: presence indicates `prefetch_related("techs")` on the queryset.
        cache = getattr(endpoint, "_prefetched_objects_cache", None)
        if cache is None or "techs" not in cache:
            ctx = self.context
            if not ctx.get(_CTX_WARN_ENDPOINT_TECHS_NOT_PREFETCHED):
                ctx[_CTX_WARN_ENDPOINT_TECHS_NOT_PREFETCHED] = True
                logger.log_line(
                    PREFIX_API_SERIALIZERS,
                    "DEFAULT_ENDPOINT_TECHS",
                    "EndPoint id=%s: techs not prefetched during serialization; expect extra queries" % (endpoint.pk,),
                    level="warning",
                )
        return list(techs_rel.all())

    @staticmethod
    def _serialize_technology_payload(tech: Any) -> dict[str, Any]:
        return {
            "id": tech.id,
            "name": tech.name,
            "value": tech.value,
            "category": tech.category,
            "stored_response_path": tech.stored_response_path,
            "stored_response_url": build_scan_file_url(tech.stored_response_path),
        }

    def _default_endpoints_queryset_for_ip_address(self, ip_address: Any) -> QuerySet:
        query = apply_endpoint_port_and_techs_related(EndPoint.objects.filter(ip_address=ip_address, is_default=True))
        scan_id = self.context.get("scan_id")
        target_id = self.context.get("target_id")
        if scan_id:
            query = query.filter(scan_history_id=scan_id)
        elif target_id:
            query = query.filter(scan_history__target_id=target_id)
        return query

    def _evaluated_default_endpoints_for_ip_address(self, ip_address: Any) -> list[Any]:
        cache: dict[int, list[Any]] = self.context.setdefault(_CTX_EVALUATED_DEFAULT_ENDPOINTS_BY_IP_ID, {})
        iid = ip_address.id
        if iid not in cache:
            cache[iid] = list(self._default_endpoints_queryset_for_ip_address(ip_address))
        return cache[iid]

    def _default_endpoints_for_subdomain_serialization(self, subdomain: Any) -> list[Any]:
        cache_attr = "_cached_default_endpoints_for_serialization"
        if hasattr(subdomain, cache_attr):
            return getattr(subdomain, cache_attr)

        if hasattr(subdomain, "default_endpoint_list"):
            endpoints = list(subdomain.default_endpoint_list or [])
            if endpoints:
                self._warn_if_default_endpoint_list_missing_techs_prefetch(endpoints)
            setattr(subdomain, cache_attr, endpoints)
            return endpoints

        if not subdomain.scan_history or subdomain.scan_history.is_legacy_scan:
            setattr(subdomain, cache_attr, [])
            return []

        qs = apply_endpoint_port_and_techs_related(EndPoint.objects.filter(subdomain=subdomain, is_default=True))
        endpoints = list(qs)
        setattr(subdomain, cache_attr, endpoints)
        return endpoints

    def _warn_if_default_endpoint_list_missing_techs_prefetch(self, endpoints: Sequence[Any]) -> None:
        if not endpoints:
            return
        endpoint = endpoints[0]
        cache = getattr(endpoint, "_prefetched_objects_cache", None)
        if cache is not None and "techs" in cache:
            return
        ctx = self.context
        if ctx.get(_CTX_WARN_DEFAULT_ENDPOINT_LIST_TECHS):
            return
        ctx[_CTX_WARN_DEFAULT_ENDPOINT_LIST_TECHS] = True
        logger.log_line(
            PREFIX_API_SERIALIZERS,
            "DEFAULT_ENDPOINT_TECHS",
            'EndPoint id=%s in default_endpoint_list without prefetched techs; add prefetch_related("techs") on the source queryset'
            % (endpoint.pk,),
            level="warning",
        )

    def _serialize_endpoint_defaults_by_port(self, endpoints: Iterable[Any]) -> list[dict[str, Any]]:
        """
        Build the list consumed by DataTables and `renderEndpointDefaultsByPortBadges` (JS).

        Each item: ``id``, ``http_url``, ``port`` (int or None), ``content_type``, ``webserver``,
        ``technologies`` (list of dicts from `_serialize_technology_payload`: id, name, value,
        category, stored_response_path, stored_response_url). Sorted by port then id.
        """
        payload: list[dict[str, Any]] = []
        for endpoint in endpoints:
            payload.append(
                {
                    "id": endpoint.id,
                    "http_url": endpoint.http_url,
                    "port": endpoint.port.number if endpoint.port_id else None,
                    "content_type": endpoint.content_type or "",
                    "webserver": endpoint.webserver or "",
                    "technologies": [
                        self._serialize_technology_payload(tech)
                        for tech in self._iter_endpoint_tech_instances_for_serialization(endpoint)
                    ],
                }
            )
        payload.sort(key=lambda row: (row["port"] is None, row["port"] or 0, row["id"]))
        return payload

    def _serialize_unique_technologies(self, endpoints: Iterable[Any]) -> list[dict[str, Any]]:
        tech_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
        for endpoint in endpoints:
            for tech in self._iter_endpoint_tech_instances_for_serialization(endpoint):
                key = (tech.name or "", tech.value or "", tech.category or "")
                if key not in tech_by_key:
                    tech_by_key[key] = self._serialize_technology_payload(tech)
        return list(tech_by_key.values())


class IpSerializer(DefaultEndpointTechnologyMixin, serializers.ModelSerializer):
    """
    IP list/detail payload: ``endpoint_defaults_by_port`` is the canonical default-endpoint tech
    shape (see ``DefaultEndpointTechnologyMixin``); ``technologies`` is a flat aggregate for
    backward compatibility. Keep list views and ``datatables_always_serialize`` aligned when
    changing technology fields.
    """

    ports = PortSerializer(many=True)
    subdomain_count = serializers.SerializerMethodField()
    subdomain_names = serializers.SerializerMethodField()
    technologies = serializers.SerializerMethodField()
    endpoint_defaults_by_port = serializers.SerializerMethodField()
    attack_surface = serializers.SerializerMethodField()
    attack_surface_count = serializers.SerializerMethodField()
    services_for_request_port = serializers.SerializerMethodField()

    class Meta:
        model = IpAddress
        fields = [
            "id",
            "address",
            "ports",
            "reverse_pointer",
            "is_cdn",
            "geo_iso",
            "version",
            "is_private",
            "alive",
            "services_for_request_port",
            "is_important",
            "ip_subscan_ids",
            "subdomain_count",
            "subdomain_names",
            "technologies",
            "endpoint_defaults_by_port",
            "attack_surface",
            "attack_surface_count",
        ]
        datatables_always_serialize = ("endpoint_defaults_by_port",)

    def get_base_subdomain_query(self, obj):
        query = Subdomain.objects.filter(ip_addresses=obj)
        scan_id = self.context.get("scan_id")
        target_id = self.context.get("target_id")

        if scan_id:
            query = query.filter(scan_history_id=scan_id)
        elif target_id:
            query = query.filter(domain__scan_history__target_id=target_id)

        return query.distinct("name")

    def get_subdomain_count(self, obj):
        precomputed = self.context.get("ip_subdomain_data")
        if precomputed and obj.id in precomputed:
            return precomputed[obj.id]["count"]
        return self.get_base_subdomain_query(obj).count()

    def get_subdomain_names(self, obj):
        precomputed = self.context.get("ip_subdomain_data")
        if precomputed and obj.id in precomputed:
            return precomputed[obj.id]["names"]
        return list(self.get_base_subdomain_query(obj).values_list("name", flat=True))

    def get_services_for_request_port(self, obj):
        """
        Service labels for the request ``port`` query param.

        Contract (enforced by ``ListIPs`` via ``datatable_ip_list_serializer_context``): when a
        valid ``port`` query param is present, ``context["expose_ip_port_services"]`` is True,
        ``context["filter_port_number"]`` is that int, and the IP queryset uses
        ``prefetch_related("ports")``. Do not serialize this field from other entry points without
        mirroring that context and prefetch, or the column will be wrong or trigger prefetch
        warnings from ``_collect_sorted_service_labels_for_ip_port``.

        Returns ``"-"`` when the request is not filtered by port (aligned with subdomain rows and
        DataTables placeholders).
        """
        if not self.context.get("expose_ip_port_services"):
            return "-"
        pn = self.context.get("filter_port_number")
        if not isinstance(pn, int) or not (1 <= pn <= 65535):
            return "-"
        cache: MutableMapping[Any, Any] = self.context.setdefault("_service_labels_by_ip_port", {})
        tup = _collect_sorted_service_labels_for_ip_port(obj, pn, cache)
        return _format_service_labels_tuple(tup)

    def get_technologies(self, obj):
        return self._serialize_unique_technologies(self._evaluated_default_endpoints_for_ip_address(obj))

    def get_endpoint_defaults_by_port(self, obj):
        return self._serialize_endpoint_defaults_by_port(self._evaluated_default_endpoints_for_ip_address(obj))

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        from reNgine.llm.attack_surface_storage import parent_has_llm_attack_surface_analyses

        return parent_has_llm_attack_surface_analyses(obj)

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        from reNgine.llm.attack_surface_storage import count_llm_attack_surface_analyses_for_parent

        return count_llm_attack_surface_analyses_for_parent(obj)


class DirectoryFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DirectoryFile
        fields = ["id", "name", "url", "length", "lines", "http_status", "words", "content_type"]


class DirectoryScanSerializer(serializers.ModelSerializer):
    scanned_date = serializers.SerializerMethodField()
    formatted_date_for_id = serializers.SerializerMethodField()
    directory_files = DirectoryFileSerializer(many=True)

    class Meta:
        model = DirectoryScan
        fields = ["id", "scanned_date", "command_line", "directory_files", "dir_subscan_ids", "formatted_date_for_id"]

    def get_scanned_date(self, DirectoryScan):
        return DirectoryScan.scanned_date.strftime("%b %d, %Y %H:%M")

    def get_formatted_date_for_id(self, DirectoryScan):
        return DirectoryScan.scanned_date.strftime("%b_%d_%Y_%H_%M")


class IpSubdomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = ["name", "ip_addresses"]
        depth = 1


class WafSerializer(serializers.ModelSerializer):
    class Meta:
        model = Waf
        fields = ["id", "name", "manufacturer"]


class CertificateSerializer(serializers.ModelSerializer):
    """Serializer for certificate detail in modal (no raw_value by default)."""

    not_before_display = serializers.SerializerMethodField("get_not_before_display")
    not_after_display = serializers.SerializerMethodField("get_not_after_display")
    is_expired = serializers.SerializerMethodField("get_is_expired")

    class Meta:
        model = Certificate
        fields = [
            "id",
            "host",
            "subject_cn",
            "subject_an",
            "issuer_cn",
            "issuer_dn",
            "issuer",
            "not_before",
            "not_after",
            "not_before_display",
            "not_after_display",
            "is_expired",
            "self_signed",
            "trusted",
            "status",
            "fingerprint_sha256",
            "keysize",
            "ip",
        ]

    def get_not_before_display(self, obj):
        if obj.not_before is None:
            return None
        return obj.not_before.isoformat()

    def get_not_after_display(self, obj):
        if obj.not_after is None:
            return None
        return obj.not_after.isoformat()

    def get_is_expired(self, obj):
        return obj.is_expired() if obj.not_after else None


class SubdomainSerializer(DefaultEndpointTechnologyMixin, serializers.ModelSerializer):
    """
    Subdomain list/detail payload: ``endpoint_defaults_by_port`` is the source of truth for
    per-port default endpoint technologies in DataTables/UI; avoid regressing new work to flat
    ``technologies`` alone.
    """

    vuln_count = serializers.SerializerMethodField("get_vuln_count")
    services_for_request_port = serializers.SerializerMethodField()

    is_interesting = serializers.SerializerMethodField("get_is_interesting")
    attack_surface = serializers.SerializerMethodField("get_attack_surface")
    attack_surface_count = serializers.SerializerMethodField("get_attack_surface_count")

    endpoint_count = serializers.SerializerMethodField("get_endpoint_count")
    info_count = serializers.SerializerMethodField("get_info_count")
    low_count = serializers.SerializerMethodField("get_low_count")
    medium_count = serializers.SerializerMethodField("get_medium_count")
    high_count = serializers.SerializerMethodField("get_high_count")
    critical_count = serializers.SerializerMethodField("get_critical_count")
    todos_count = serializers.SerializerMethodField("get_todos_count")
    directories_count = serializers.SerializerMethodField("get_directories_count")
    subscan_count = serializers.SerializerMethodField("get_subscan_count")
    certificate_count = serializers.SerializerMethodField("get_certificate_count")
    ip_addresses = IpSerializer(many=True)
    ports = serializers.SerializerMethodField("get_ports")
    waf = WafSerializer(many=True)
    technologies = serializers.SerializerMethodField("get_technologies")
    endpoint_defaults_by_port = serializers.SerializerMethodField("get_endpoint_defaults_by_port")
    directories = DirectoryScanSerializer(many=True)

    # Use display properties for Secator scans (default endpoint values)
    http_status = serializers.SerializerMethodField("get_display_http_status")
    page_title = serializers.SerializerMethodField("get_display_page_title")
    content_length = serializers.SerializerMethodField("get_display_content_length")
    response_time = serializers.SerializerMethodField("get_display_response_time")

    class Meta:
        model = Subdomain
        fields = [
            "id",
            "scan_history",
            "domain",
            "name",
            "is_imported_subdomain",
            "is_important",
            "http_url",
            "http_header_path",
            "discovered_date",
            "cname",
            "is_cdn",
            "cdn_name",
            "http_status",
            "services_for_request_port",
            "content_type",
            "response_time",
            "webserver",
            "content_length",
            "page_title",
            "technologies",
            "endpoint_defaults_by_port",
            "ip_addresses",
            "ports",
            "directories",
            "waf",
            "attack_surface",
            "attack_surface_count",
            "verified",
            "sources",
            "vuln_count",
            "is_interesting",
            "endpoint_count",
            "info_count",
            "low_count",
            "medium_count",
            "high_count",
            "critical_count",
            "todos_count",
            "directories_count",
            "subscan_count",
            "certificate_count",
        ]
        datatables_always_serialize = ("certificate_count", "attack_surface_count", "endpoint_defaults_by_port")

    def get_is_interesting(self, subdomain):
        interesting_names = self.context.get("datatable_interesting_names")
        if interesting_names is not None:
            return subdomain.name in interesting_names
        scan_id = subdomain.scan_history.id if subdomain.scan_history else None
        return get_interesting_subdomains(scan_id).filter(name=subdomain.name).exists()

    def get_attack_surface(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c) > 0
        from reNgine.llm.attack_surface_storage import parent_has_llm_attack_surface_analyses

        return parent_has_llm_attack_surface_analyses(obj)

    def get_attack_surface_count(self, obj):
        c = getattr(obj, "llm_attack_surface_count", None)
        if c is not None:
            return int(c)
        from reNgine.llm.attack_surface_storage import count_llm_attack_surface_analyses_for_parent

        return count_llm_attack_surface_analyses_for_parent(obj)

    def get_services_for_request_port(self, obj):
        """
        Merged service labels for the filtered port across this subdomain's IPs.

        Contract (enforced by ``ListSubdomains`` via ``datatable_subdomain_list_serializer_context``):
        ``context["filter_port_number"]`` is set when ``port`` is a valid TCP/UDP port (else ``None``,
        and this method returns ``"-"``). The queryset must prefetch ``ip_addresses__ports`` so
        ``_collect_sorted_service_labels_for_ip_port`` does not warn and service labels are complete.
        """
        pn = self.context.get("filter_port_number")
        if not isinstance(pn, int) or not (1 <= pn <= 65535):
            return "-"
        cache: MutableMapping[Any, Any] = self.context.setdefault("_service_labels_by_ip_port", {})
        merged: list[str] = []
        seen: set[str] = set()
        for ip in obj.ip_addresses.all():
            for lab in _collect_sorted_service_labels_for_ip_port(ip, pn, cache):
                if lab not in seen:
                    seen.add(lab)
                    merged.append(lab)
        return ", ".join(sorted(merged)) if merged else "-"

    def get_ports(self, subdomain):
        """
        Flatten all ports from subdomain's ip_addresses for DataTables 'ports' column.

        ``prefetch_related("ports")`` on the relation manager is a no-op when the parent queryset
        already prefetched ``ip_addresses__ports``; otherwise it avoids N+1 on ``ip.ports``.
        """
        return [
            PortSerializer(port).data
            for ip in subdomain.ip_addresses.prefetch_related("ports").all()
            for port in ip.ports.all()
        ]

    def get_endpoint_count(self, subdomain):
        val = getattr(subdomain, "endpoint_count", None)
        return val if val is not None else subdomain.get_endpoint_count

    def get_info_count(self, subdomain):
        val = getattr(subdomain, "info_count", None)
        return val if val is not None else subdomain.get_info_count

    def get_low_count(self, subdomain):
        val = getattr(subdomain, "low_count", None)
        return val if val is not None else subdomain.get_low_count

    def get_medium_count(self, subdomain):
        val = getattr(subdomain, "medium_count", None)
        return val if val is not None else subdomain.get_medium_count

    def get_high_count(self, subdomain):
        val = getattr(subdomain, "high_count", None)
        return val if val is not None else subdomain.get_high_count

    def get_critical_count(self, subdomain):
        val = getattr(subdomain, "critical_count", None)
        return val if val is not None else subdomain.get_critical_count

    def get_directories_count(self, subdomain):
        return subdomain.get_directories_count

    def get_subscan_count(self, subdomain):
        val = getattr(subdomain, "subscan_count", None)
        return val if val is not None else subdomain.get_subscan_count

    def get_certificate_count(self, subdomain):
        val = getattr(subdomain, "certificate_count", None)
        return val if val is not None else subdomain.get_certificate_count()

    def get_todos_count(self, subdomain):
        val = getattr(subdomain, "todos_count", None)
        return len(subdomain.get_todos.filter(is_done=False)) if val is None else val

    def get_vuln_count(self, obj):
        val = getattr(obj, "vuln_count", None)
        if val is not None:
            return val
        try:
            return obj.vuln_count
        except Exception:
            return None

    def _get_default_endpoint(self, obj):
        """
        Get the default endpoint for this subdomain from prefetched data.
        Falls back to HybridProperty if prefetch was not used.
        """
        # Check if default_endpoint_list was prefetched
        if hasattr(obj, "default_endpoint_list") and obj.default_endpoint_list:
            return obj.default_endpoint_list[0]
        # Fallback to HybridProperty for backward compatibility
        return obj._default_endpoint

    def get_technologies(self, obj):
        endpoint_technologies = self._serialize_unique_technologies(self._default_endpoints_for_subdomain_serialization(obj))
        if endpoint_technologies:
            return endpoint_technologies
        # Fallback for Secator findings linked directly on SubdomainTechnology when no default endpoint exists.
        return [self._serialize_technology_payload(tech) for tech in obj.technologies.all()]

    def get_endpoint_defaults_by_port(self, obj):
        return self._serialize_endpoint_defaults_by_port(self._default_endpoints_for_subdomain_serialization(obj))

    def get_display_http_status(self, obj):
        """Return default endpoint http_status for Secator scans, otherwise subdomain http_status."""
        if obj.scan_history and not obj.scan_history.is_legacy_scan:
            if default_endpoint := self._get_default_endpoint(obj):
                return default_endpoint.http_status
        return obj.http_status

    def get_display_page_title(self, obj):
        """Return default endpoint page_title for Secator scans, otherwise subdomain page_title."""
        if obj.scan_history and not obj.scan_history.is_legacy_scan:
            if default_endpoint := self._get_default_endpoint(obj):
                return default_endpoint.page_title
        return obj.page_title

    def get_display_content_length(self, obj):
        """Return default endpoint content_length for Secator scans, otherwise subdomain content_length."""
        if obj.scan_history and not obj.scan_history.is_legacy_scan:
            if default_endpoint := self._get_default_endpoint(obj):
                return default_endpoint.content_length
        return obj.content_length

    def get_display_response_time(self, obj):
        """Return default endpoint response_time for Secator scans, otherwise subdomain response_time."""
        if obj.scan_history and not obj.scan_history.is_legacy_scan:
            if default_endpoint := self._get_default_endpoint(obj):
                return default_endpoint.response_time
        return obj.response_time


class EndpointSerializer(serializers.ModelSerializer):
    """Frontend uses screenshot_url (and stored_response_url) for display; screenshot_path is the stored path for backend/non-HTTP use."""

    techs = TechnologySerializer(many=True)
    subdomain_id = serializers.SerializerMethodField()
    scan_history_id = serializers.SerializerMethodField()
    domain_id = serializers.SerializerMethodField()
    subdomain_name = serializers.SerializerMethodField()
    screenshot_url = serializers.SerializerMethodField()
    stored_response_url = serializers.SerializerMethodField()

    class Meta:
        model = EndPoint
        fields = [
            "id",
            "scan_history",
            "domain",
            "subdomain",
            "source",
            "http_url",
            "content_length",
            "page_title",
            "http_status",
            "content_type",
            "discovered_date",
            "response_time",
            "webserver",
            "is_default",
            "matched_gf_patterns",
            "screenshot_path",
            "screenshot_url",
            "stored_response_path",
            "stored_response_url",
            "techs",
            "endpoint_subscan_ids",
            "method",
            "words",
            "lines",
            "headers",
            "subdomain_id",
            "scan_history_id",
            "domain_id",
            "subdomain_name",
        ]

    def get_subdomain_id(self, obj):
        return obj.subdomain.id if obj.subdomain else None

    def get_scan_history_id(self, obj):
        return obj.scan_history.id if obj.scan_history else None

    def get_domain_id(self, obj):
        return obj.domain.id if obj.domain else None

    def get_subdomain_name(self, obj):
        return obj.subdomain.name if obj.subdomain else None

    def get_screenshot_url(self, obj):
        # Served with project-scoped access via api.scan_file.ServeScanFile
        return build_scan_file_url(obj.screenshot_path)

    def get_stored_response_url(self, obj):
        # Served with project-scoped access via api.scan_file.ServeScanFile
        return build_scan_file_url(obj.stored_response_path)


class EndpointOnlyURLsSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndPoint
        fields = ["http_url"]


class VulnerabilitySerializer(serializers.ModelSerializer):
    discovered_date = serializers.SerializerMethodField()
    severity = serializers.SerializerMethodField()
    cve_ids = serializers.SerializerMethodField()
    cwe_ids = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    description_display = serializers.SerializerMethodField()
    impact_display = serializers.SerializerMethodField()
    remediation_display = serializers.SerializerMethodField()
    references_display = serializers.SerializerMethodField()

    def get_discovered_date(self, Vulnerability):
        return Vulnerability.discovered_date.strftime("%b %d, %Y %H:%M")

    def get_severity(self, Vulnerability):
        if Vulnerability.severity == 0:
            return "Info"
        elif Vulnerability.severity == 1:
            return "Low"
        elif Vulnerability.severity == 2:
            return "Medium"
        elif Vulnerability.severity == 3:
            return "High"
        elif Vulnerability.severity == 4:
            return "Critical"
        else:
            return "Unknown"

    def get_cve_ids(self, obj):
        # Use prefetched data to avoid additional queries
        return [{"name": cve.name} for cve in obj.cve_ids.all()]

    def get_cwe_ids(self, obj):
        # Use prefetched data to avoid additional queries
        return [{"name": cwe.name} for cwe in obj.cwe_ids.all()]

    def get_tags(self, obj):
        # Use prefetched data to avoid additional queries
        return [{"name": tag.name} for tag in obj.tags.all()]

    def get_description_display(self, obj):
        return obj.formatted_description

    def get_impact_display(self, obj):
        return obj.formatted_impact

    def get_remediation_display(self, obj):
        return obj.formatted_remediation

    def get_references_display(self, obj):
        return obj.formatted_references

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "scan_history",
            "source",
            "subdomain",
            "endpoint",
            "domain",
            "template",
            "template_url",
            "template_id",
            "matcher_name",
            "name",
            "severity",
            "description",
            "description_display",
            "impact",
            "impact_display",
            "remediation",
            "remediation_display",
            "references",
            "references_display",
            "extracted_results",
            "tags",
            "cve_ids",
            "cwe_ids",
            "cvss_metrics",
            "cvss_score",
            "curl_command",
            "type",
            "http_url",
            "discovered_date",
            "open_status",
            "hackerone_report_id",
            "request",
            "response",
            "is_llm_used",
            "vuln_subscan_ids",
            "cvss_vec",
            "epss_score",
            "confidence_nb",
            "severity_nb",
            "ip",
            "reference",
        ]
        depth = 1


class SecretSerializer(serializers.ModelSerializer):
    discovered_date = serializers.SerializerMethodField()

    def get_discovered_date(self, obj):
        if obj.discovered_date:
            return obj.discovered_date.strftime("%b %d, %Y %H:%M")
        return ""

    class Meta:
        model = Secret
        fields = [
            "id",
            "scan_history",
            "rule_name",
            "matched_at",
            "source",
            "value",
            "extra_data",
            "discovered_date",
        ]


class ExploitSerializer(serializers.ModelSerializer):
    discovered_date = serializers.SerializerMethodField()
    ip = serializers.SerializerMethodField()
    endpoint_url = serializers.SerializerMethodField()
    domain_name = serializers.SerializerMethodField()
    cve_ids = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")
    tags = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")

    def get_discovered_date(self, obj: Exploit) -> str:
        if obj.discovered_date:
            return obj.discovered_date.strftime("%b %d, %Y %H:%M")
        return ""

    def get_ip(self, obj: Exploit) -> str:
        if not obj.ip_address or not obj.ip_address.address:
            return ""
        ports = list(obj.ip_address.ports.all())
        if not ports:
            return str(obj.ip_address.address)
        # Keep it compact but include port information as requested.
        unique_ports = sorted({p.number for p in ports if p.number is not None})
        if not unique_ports:
            return str(obj.ip_address.address)
        ports_str = ",".join(str(p) for p in unique_ports[:5])
        suffix = f":{ports_str}"
        if len(unique_ports) > 5:
            suffix += ",..."
        return f"{obj.ip_address.address}{suffix}"

    def get_endpoint_url(self, obj: Exploit) -> str:
        if obj.endpoint and getattr(obj.endpoint, "http_url", None):
            return str(obj.endpoint.http_url)
        return ""

    def get_domain_name(self, obj: Exploit) -> str:
        if obj.domain and getattr(obj.domain, "name", None):
            return str(obj.domain.name)
        return ""

    class Meta:
        model = Exploit
        fields = [
            "id",
            "name",
            "exploit_id",
            "provider",
            "matched_at",
            "reference",
            "scan_history",
            "ip",
            "endpoint_url",
            "domain_name",
            "discovered_date",
            "extra_data",
            "cve_ids",
            "tags",
        ]


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "name", "slug", "description", "insert_date"]
