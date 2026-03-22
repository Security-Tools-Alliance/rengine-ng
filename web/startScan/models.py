from collections import defaultdict
import contextlib
from datetime import timedelta
from urllib.parse import urlparse

from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Count, Exists, OuterRef, Q
from django.db.models.functions import TruncDay
from django.utils import timezone

from reNgine.core.time import get_time_taken
from reNgine.definitions import (
    CONFIDENCE_CHOICES,
    ENGINE_DISPLAY_NAMES,
    IP_PROTOCOL_CHOICES,
    NUCLEI_REVERSE_SEVERITY_MAP,
    SCAN_STATUSES,
)
from reNgine.llm.utils import convert_markdown_to_html
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.time import date_to_aware_datetime
from scanEngine.models import EngineType
from targetApp.models import Target


PREFIX_SCAN = "[STARTSCAN]"
logger = get_module_logger(__name__)


class HybridProperty:
    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.exp = None

    def __get__(self, instance, owner):
        return self if instance is None else self.func(instance)

    def __set__(self, instance, value):
        pass

    def expression(self, exp):
        self.exp = exp
        return self


class ScanHistory(models.Model):
    id = models.AutoField(primary_key=True)
    start_scan_date = models.DateTimeField()
    scan_status = models.IntegerField(choices=SCAN_STATUSES, default=-1)
    results_dir = models.CharField(max_length=255, blank=True)
    target = models.ForeignKey(Target, on_delete=models.CASCADE, null=True, blank=True, related_name="scan_histories")
    scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE, null=True, blank=True)
    tasks = ArrayField(models.CharField(max_length=200), null=True)
    stop_scan_date = models.DateTimeField(null=True, blank=True)
    used_gf_patterns = models.CharField(max_length=500, null=True, blank=True)
    error_message = models.CharField(max_length=300, blank=True, null=True)
    emails = models.ManyToManyField("Email", related_name="emails", blank=True)
    employees = models.ManyToManyField("Employee", related_name="employees", blank=True)
    buckets = models.ManyToManyField("S3Bucket", related_name="buckets", blank=True)
    dorks = models.ManyToManyField("Dork", related_name="dorks", blank=True)
    initiated_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="initiated_scans", blank=True, null=True
    )
    aborted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="aborted_scans")
    is_legacy_scan = models.BooleanField(
        default=False, help_text="Whether this scan uses legacy EngineType (True) or new SecatorScan (False)"
    )
    scan_config = models.JSONField(
        null=True,
        blank=True,
        help_text="Effective scan parameters and profiles used for this scan",
    )

    def __str__(self):
        # Avoid hidden DB access (Domain/target) to prevent N+1 in admin, logs, serializers.
        return str(self.id)

    def get_subdomain_count(self):
        if hasattr(self, "subdomain_count"):
            return self.subdomain_count
        return Subdomain.objects.filter(scan_history__id=self.id).count()

    def get_subdomain_change_count(self):
        # Previous subdomain_discovery scan for the same target (not the current scan)
        last_scan_obj = (
            ScanHistory.objects.filter(target_id=self.target_id)
            .filter(tasks__overlap=["subdomain_discovery"])
            .filter(start_scan_date__lt=self.start_scan_date)
            .order_by("-start_scan_date")
            .first()
        )
        if last_scan_obj is None:
            return [0, 0]
        names_q1 = set(Subdomain.objects.filter(scan_history_id=self.id).values_list("name", flat=True))
        names_q2 = set(Subdomain.objects.filter(scan_history__id=last_scan_obj.id).values_list("name", flat=True))
        new_subdomains = len(names_q2 - names_q1)
        removed_subdomains = len(names_q1 - names_q2)
        return [new_subdomains, removed_subdomains]

    def get_endpoint_count(self):
        if hasattr(self, "endpoint_count"):
            return self.endpoint_count
        return EndPoint.objects.filter(scan_history__id=self.id).count()

    def get_vulnerability_count(self):
        if hasattr(self, "vuln_count"):
            return self.vuln_count
        return Vulnerability.objects.filter(scan_history__id=self.id).count()

    def get_secret_count(self):
        if hasattr(self, "secret_count"):
            return self.secret_count
        return Secret.objects.filter(scan_history__id=self.id).count()

    def get_exploit_count(self):
        if hasattr(self, "exploit_count"):
            return self.exploit_count
        return Exploit.objects.filter(scan_history__id=self.id).count()

    def get_domain_count(self):
        if hasattr(self, "domain_count"):
            return self.domain_count
        return self.discovered_domains.count()

    def get_unknown_vulnerability_count(self):
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=-1).count()

    def get_info_vulnerability_count(self):
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=0).count()

    def get_low_vulnerability_count(self):
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=1).count()

    def get_medium_vulnerability_count(self):
        if hasattr(self, "vuln_medium_count"):
            return self.vuln_medium_count
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=2).count()

    def get_high_vulnerability_count(self):
        if hasattr(self, "vuln_high_count"):
            return self.vuln_high_count
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=3).count()

    def get_critical_vulnerability_count(self):
        if hasattr(self, "vuln_critical_count"):
            return self.vuln_critical_count
        return Vulnerability.objects.filter(scan_history__id=self.id).filter(severity=4).count()

    def get_progress(self):
        """Calculate scan progress percentage based on completed steps vs total steps."""
        from reNgine.definitions import SUCCESS_TASK
        from reNgine.secator import SecatorProgressSync

        def _has_secator_runners(scan_history) -> bool:
            """
            Return True if this scan has any related SecatorRunner rows.

            Uses the related manager's prefetch indicator when available and falls back
            to an existence query otherwise, so any future Django API changes are handled
            in one place.
            """
            manager = scan_history.secatorrunner_set
            if getattr(manager, "_prefetch_done", False):
                return bool(manager.all())
            return SecatorRunner.objects.filter(scan_history=scan_history).exists()

        if _has_secator_runners(self):
            return SecatorProgressSync.calculate_workflow_progress(self.id)

        # Legacy scan: calculate based on completed steps vs total steps
        number_of_steps = len(self.tasks) if self.tasks else 0
        if number_of_steps == 0:
            return 0

        # Get unique completed task names (avoid counting duplicates if tasks are retried)
        completed_task_names = (
            self.scanactivity_set.filter(status=SUCCESS_TASK).values_list("name", flat=True).distinct()
        )
        steps_completed = len(completed_task_names)

        # Ensure we don't exceed 100%
        progress = min((steps_completed / number_of_steps) * 100, 100)
        return round(progress, 2)

    @property
    def status_string(self):
        """
        Get status as string. For legacy scans, returns status code as string.
        For Secator scans, returns status string from runner.

        To avoid N+1 queries when accessing this for many instances, a controller
        can pre-populate `self._main_runner` (e.g. via `prefetch_related`) and
        this method will use it instead of querying per-instance.
        """
        if self.is_legacy_scan:
            return str(self.scan_status)

        # Prefer a cached main runner if one has been set by the caller
        main_runner = getattr(self, "_main_runner", None)

        if main_runner is None:
            # Fallback: query for the main runner when not provided
            from startScan.models import SecatorRunner

            runners = SecatorRunner.objects.filter(scan_history=self)
            main_runner = runners.filter(runner_type__in=["workflow", "scan"]).first()

        if main_runner and main_runner.status:
            return str(main_runner.status).upper()
        # Fallback: try to get from runner_data
        if main_runner and getattr(main_runner, "runner_data", None):
            return str(main_runner.runner_data.get("status", "")).upper()
        # Final fallback: use scan_status
        return str(self.scan_status).upper()

    @property
    def status(self):
        """
        Get status as integer code (for compatibility with JavaScript).
        For legacy scans, returns integer status code.
        For Secator scans, maps status string to code.
        """
        if self.is_legacy_scan:
            return self.scan_status
        # For Secator scans, map status string to code
        from reNgine.secator import SecatorProgressSync

        status_str = self.status_string
        if isinstance(status_str, str):
            return SecatorProgressSync.map_secator_status_to_rengine(status_str)
        # Fallback: try to convert to int, but handle non-numeric strings safely
        if status_str:
            try:
                return int(status_str)
            except (ValueError, TypeError):
                # If conversion fails, return INITIATED_TASK as safe default
                from reNgine.definitions import INITIATED_TASK

                return INITIATED_TASK
        return -1

    @property
    def status_code(self):
        """Alias for status (for compatibility)."""
        return self.status

    def get_status_display(self):
        """Get human-readable status display."""
        from reNgine.definitions import SCAN_STATUS_DISPLAY_MAP

        status_code = self.status_code
        return SCAN_STATUS_DISPLAY_MAP.get(status_code, "UNKNOWN")

    def get_current_task(self):
        """Get the current running task name, formatted for display."""
        from reNgine.definitions import RUNNING_TASK
        from reNgine.secator import SecatorProgressSync

        # Check if this is a Secator scan (has SecatorRunner); use prefetch when available
        from startScan.models import SecatorRunner

        prefetched = getattr(self, "_prefetched_objects_cache", None)
        if prefetched and "secatorrunner_set" in prefetched:
            has_secator = bool(list(self.secatorrunner_set.all()))
        else:
            has_secator = SecatorRunner.objects.filter(scan_history=self).exists()
        if has_secator:
            if current_runner := SecatorProgressSync.get_current_running_runner(self.id):
                runner_name = current_runner.runner_name or current_runner.runner_data.get("name", "Unknown")
                runner_type = current_runner.runner_type or current_runner.runner_data.get("config", {}).get(
                    "type", "task"
                )
                # Format for display
                if runner_type in ["workflow", "scan"]:
                    return f"{runner_type.title()}: {runner_name}"
                else:
                    return f"Task: {runner_name}"

        if current_activity := self.scanactivity_set.filter(status=RUNNING_TASK).order_by("-time").first():
            # Format task name for display
            task_name = current_activity.name

            # Map technical names to user-friendly names
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
                "waf_detection": "WAF Detection",
                "dir_file_fuzz": "Directory Fuzzing",
                "dalfox_xss_scan": "XSS Scanning",
                "crlfuzz_scan": "CRLF Injection Scan",
                "post_crawl": "Post-crawl Analysis",
            }

            return task_display_names.get(task_name, task_name.replace("_", " ").title())

        return None

    def get_completed_ago(self):
        if self.stop_scan_date:
            return self.get_time_ago(self.stop_scan_date)

    def get_total_scan_time_in_sec(self):
        if self.stop_scan_date:
            return (self.stop_scan_date - self.start_scan_date).seconds

    def get_elapsed_time(self):
        return self.get_time_ago(self.start_scan_date)

    def _get_main_runner(self):
        """
        Get the main SecatorRunner for this scan (workflow or scan type).
        Returns None for legacy scans or if no runner is found.
        Caches the result to avoid multiple queries.
        Uses prefetched secatorrunner_set when available to avoid N+1.
        """
        if self.is_legacy_scan:
            return None

        if not hasattr(self, "_cached_main_runner"):
            prefetched = getattr(self, "_prefetched_objects_cache", None)
            if prefetched and "secatorrunner_set" in prefetched:
                runners = [r for r in self.secatorrunner_set.all() if r.runner_type in ("workflow", "scan")]
                self._cached_main_runner = min(runners, key=lambda r: r.id) if runners else None
            else:
                from startScan.models import SecatorRunner

                main_runner = (
                    SecatorRunner.objects.filter(scan_history=self, runner_type__in=["workflow", "scan"])
                    .select_related("worker")
                    .order_by("id")
                    .first()
                )
                self._cached_main_runner = main_runner

        return self._cached_main_runner

    @staticmethod
    def _format_display_label(value: str) -> str:
        """Normalize a label for UI display."""
        return value.replace("_", " ").strip().title()

    @staticmethod
    def _format_task_display_label(value: str) -> str:
        """
        Normalize a task label for UI display.

        Task names are often tool identifiers (e.g. `httpx`, `nuclei`) and should
        keep their original casing.
        """
        return value.replace("_", " ").strip()

    @property
    def uses_legacy_engine_profile(self) -> bool:
        """
        True when this scan is tied to an EngineType (legacy engine UI).

        Includes rows where ``is_legacy_scan`` was not backfilled but ``scan_type_id`` is still set.
        """
        return bool(self.is_legacy_scan or self.scan_type_id)

    def _get_task_runner_display_names(self) -> list[str]:
        """
        Return the ordered, de-duplicated list of task names for Secator task-only scans.

        This is used only for display purposes when no workflow/scan runner exists.
        """
        if self.uses_legacy_engine_profile:
            return []

        cached = getattr(self, "_cached_task_runner_display_names", None)
        if cached is not None:
            return cached

        # Import here to avoid circular import
        from startScan.models import SecatorRunner

        runners = SecatorRunner.objects.filter(scan_history=self, runner_type="task").order_by("id")

        names: list[str] = []
        seen: set[str] = set()
        for runner in runners:
            raw_name = runner.runner_name
            if not raw_name and isinstance(getattr(runner, "runner_data", None), dict):
                runner_data = runner.runner_data
                raw_name = runner_data.get("name") or runner_data.get("runner_name")
                config = runner_data.get("config")
                if isinstance(config, dict):
                    raw_name = raw_name or config.get("name")

            if not raw_name:
                continue

            display_name = self._format_task_display_label(str(raw_name))
            if not display_name or display_name in seen:
                continue

            names.append(display_name)
            seen.add(display_name)

        self._cached_task_runner_display_names = names
        return names

    @property
    def scan_name(self):
        """Get scan name: engine_name for legacy scans, runner_name for Secator scans."""
        if self.uses_legacy_engine_profile:
            engine_type = getattr(self, "scan_type", None)
            if engine_type is not None:
                return engine_type.engine_name
            return ""

        main_runner = self._get_main_runner()
        return (main_runner.runner_name or "Secator") if main_runner else "Secator"

    @property
    def runner_type(self):
        """Get runner type: 'legacy' for legacy scans, runner_type for Secator scans."""
        if self.is_legacy_scan:
            return "legacy"

        main_runner = self._get_main_runner()
        return main_runner.runner_type if main_runner else None

    @property
    def display_scan_name(self):
        """
        Human-friendly scan name for UI.

        - For workflow/scan: use the main runner name.
        - For task-only: show the list of tasks (so UI renders `Task: task1, task2`).
        """
        if self.uses_legacy_engine_profile:
            scan_name = self.scan_name
            return self._format_display_label(scan_name) if scan_name else ""

        if main_runner := self._get_main_runner():
            scan_name = main_runner.runner_name or "Secator"
            return self._format_display_label(scan_name) if scan_name else ""

        if task_names := self._get_task_runner_display_names():
            return ", ".join(task_names)

        scan_name = self.scan_name
        return self._format_display_label(scan_name) if scan_name else ""

    @property
    def display_runner_type(self):
        """
        Human-friendly runner type for UI.

        - For workflow/scan: use the main runner type.
        - For task-only: always return `Task`.
        """
        if self.uses_legacy_engine_profile:
            return "Legacy"

        main_runner = self._get_main_runner()
        if main_runner and main_runner.runner_type:
            return self._format_display_label(main_runner.runner_type)

        return "Task" if self._get_task_runner_display_names() else ""

    @property
    def scan_engine_used(self) -> str:
        """
        Unified display string for the "Scan engine used" column: "Type: Name"
        (e.g. "Workflow: recon", "Legacy: EngineName"). Single source for DataTables and WebSocket.
        """
        runner = self.display_runner_type or ""
        scan_name = self.display_scan_name or ""
        return f"{runner}: {scan_name}" if runner or scan_name else ""

    @property
    def secator_worker_name(self) -> str:
        """
        Human-friendly worker name for UI (where the scan runs).
        Returns the main runner's worker name, or 'Local' if no remote worker.
        """
        if self.is_legacy_scan:
            return "Local"
        main_runner = self._get_main_runner()
        if main_runner and main_runner.worker_id and getattr(main_runner, "worker", None):
            return main_runner.worker.name or "Local"
        prefetched = getattr(self, "_prefetched_objects_cache", None)
        if prefetched and "secatorrunner_set" in prefetched:
            if task_runners := [
                runner
                for runner in self.secatorrunner_set.all()
                if runner.runner_type == "task" and runner.worker_id and getattr(runner, "worker", None)
            ]:
                task_runner = min(task_runners, key=lambda runner: runner.id)
                return task_runner.worker.name or "Local"
        else:
            from startScan.models import SecatorRunner

            task_runner = (
                SecatorRunner.objects.filter(scan_history=self, runner_type="task", worker__isnull=False)
                .select_related("worker")
                .order_by("id")
                .first()
            )
            if task_runner and task_runner.worker:
                return task_runner.worker.name or "Local"
        return "Local"

    def get_time_ago(self, time):
        duration = timezone.now() - time
        days, seconds = duration.days, duration.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        if not hours and not minutes:
            return f"{seconds} seconds"
        elif not hours:
            return f"{minutes} minutes"
        elif not minutes:
            return f"{hours} hours"
        return f"{hours} hours {minutes} minutes"

    @classmethod
    def get_all_counts(cls, queryset):
        """Aggregate total scans and status distribution"""
        from reNgine.definitions import (
            SCAN_STATUS_COMPLETED,
            SCAN_STATUS_FAILED,
            SCAN_STATUS_QUEUED,
            SCAN_STATUS_RUNNING,
            SCAN_STATUS_RUNNING_BACKGROUND,
        )

        return queryset.aggregate(
            total=Count("id"),
            pending=Count("id", filter=models.Q(scan_status=SCAN_STATUS_QUEUED)),
            running=Count("id", filter=models.Q(scan_status=SCAN_STATUS_RUNNING)),
            completed=Count("id", filter=models.Q(scan_status=SCAN_STATUS_COMPLETED)),
            failed=Count("id", filter=models.Q(scan_status=SCAN_STATUS_FAILED)),
            running_background=Count("id", filter=models.Q(scan_status=SCAN_STATUS_RUNNING_BACKGROUND)),
        )

    @classmethod
    def get_project_counts(cls, project):
        """Get scan statistics for a specific project"""
        return cls.get_all_counts(cls.objects.filter(target__project=project))

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        """Get daily scan counts for a queryset"""
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range, status=None):
        """Get scan timeline data with optional status filter"""
        queryset = cls.objects.filter(target__project=project)

        if status is not None:
            queryset = queryset.filter(scan_status=status)

        raw_data = cls.get_counts_by_date(queryset, "start_scan_date", date_range[0])

        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))

        return results[::-1]


# Domain-related models (tables startScan_*). Domain is a finding; link to scan via scan_history.
class HistoricalIP(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.CharField(max_length=150)
    location = models.CharField(max_length=500)
    owner = models.CharField(max_length=500)
    last_seen = models.CharField(max_length=500)

    class Meta:
        managed = False
        db_table = "startScan_historicalip"

    def __str__(self):
        return self.ip


class RelatedDomain(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250)

    class Meta:
        managed = False
        db_table = "startScan_relateddomain"

    def __str__(self):
        return self.name


class Registrar(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500, null=True, blank=True)
    phone = models.CharField(max_length=150, null=True, blank=True)
    email = models.CharField(max_length=350, null=True, blank=True)
    url = models.CharField(max_length=1000, null=True, blank=True)
    address = models.CharField(max_length=1000, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    fax = models.CharField(max_length=150, null=True, blank=True)

    class Meta:
        managed = False
        db_table = "startScan_registrar"

    def __str__(self):
        return self.name


class DomainRegistration(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500, null=True, blank=True)
    organization = models.CharField(max_length=500, null=True, blank=True)
    contact = models.CharField(max_length=500, null=True, blank=True)
    type = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=500, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    zip_code = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    email = models.CharField(max_length=500, null=True, blank=True)
    phone = models.CharField(max_length=150, null=True, blank=True)
    fax = models.CharField(max_length=150, null=True, blank=True)
    id_str = models.CharField(max_length=500, null=True, blank=True)

    class Meta:
        managed = False
        db_table = "startScan_domainregistration"

    def __str__(self):
        return self.name


class WhoisStatus(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500)

    class Meta:
        managed = False
        db_table = "startScan_whoisstatus"

    def __str__(self):
        return self.name


class NameServer(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500)

    class Meta:
        managed = False
        db_table = "startScan_nameserver"

    def __str__(self):
        return self.name


class DNSRecord(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField()
    type = models.CharField(max_length=50)
    extra_data = models.JSONField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "startScan_dnsrecord"

    def __str__(self):
        return self.name


class DomainInfoStatusThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    whoisstatus = models.ForeignKey(WhoisStatus, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_status"


class DomainInfoNameServersThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    nameserver = models.ForeignKey(NameServer, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_name_servers"


class DomainInfoDnsRecordsThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    dnsrecord = models.ForeignKey(DNSRecord, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_dns_records"


class DomainInfoRelatedDomainsThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    relateddomain = models.ForeignKey(RelatedDomain, on_delete=models.CASCADE, related_name="+")

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_related_domains"


class DomainInfoRelatedTldsThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    relateddomain = models.ForeignKey(RelatedDomain, on_delete=models.CASCADE, related_name="+")

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_related_tlds"


class DomainInfoSimilarDomainsThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    relateddomain = models.ForeignKey(RelatedDomain, on_delete=models.CASCADE, related_name="+")

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_similar_domains"


class DomainInfoHistoricalIpsThrough(models.Model):
    domaininfo = models.ForeignKey("DomainInfo", on_delete=models.CASCADE)
    historicalip = models.ForeignKey(HistoricalIP, on_delete=models.CASCADE)

    class Meta:
        managed = False
        db_table = "startScan_domaininfo_historical_ips"


class DomainInfo(models.Model):
    id = models.AutoField(primary_key=True)
    dnssec = models.BooleanField(default=False)
    created = models.DateTimeField(null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    expires = models.DateTimeField(null=True, blank=True)
    geolocation_iso = models.CharField(max_length=10, null=True, blank=True)
    registrar = models.ForeignKey(Registrar, blank=True, on_delete=models.CASCADE, null=True)
    registrant = models.ForeignKey(
        DomainRegistration,
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        related_name="registrant",
    )
    admin = models.ForeignKey(
        DomainRegistration,
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        related_name="admin",
    )
    tech = models.ForeignKey(
        DomainRegistration,
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        related_name="tech",
    )
    status = models.ManyToManyField(
        WhoisStatus,
        blank=True,
        through=DomainInfoStatusThrough,
        related_name="+",
    )
    name_servers = models.ManyToManyField(
        NameServer,
        blank=True,
        through=DomainInfoNameServersThrough,
        related_name="+",
    )
    dns_records = models.ManyToManyField(
        DNSRecord,
        blank=True,
        through=DomainInfoDnsRecordsThrough,
        related_name="+",
    )
    whois_server = models.CharField(max_length=150, null=True, blank=True)
    related_domains = models.ManyToManyField(
        RelatedDomain,
        blank=True,
        related_name="associated_domains",
        through=DomainInfoRelatedDomainsThrough,
    )
    related_tlds = models.ManyToManyField(
        RelatedDomain,
        blank=True,
        related_name="related_tlds",
        through=DomainInfoRelatedTldsThrough,
    )
    similar_domains = models.ManyToManyField(
        RelatedDomain,
        blank=True,
        related_name="similar_domains",
        through=DomainInfoSimilarDomainsThrough,
    )
    historical_ips = models.ManyToManyField(
        HistoricalIP,
        blank=True,
        related_name="similar_domains",
        through=DomainInfoHistoricalIpsThrough,
    )
    extra_data = models.JSONField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "startScan_domaininfo"

    def __str__(self):
        return str(self.id)


class Domain(models.Model):
    """Domain is a finding; discovered in a scan. Linked to scan via scan_history (not target/project)."""

    ORGANIZATIONS_REVERSE_RELATION = "domains"

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300)
    h1_team_handle = models.CharField(max_length=100, blank=True, null=True)
    ip_address_cidr = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    insert_date = models.DateTimeField(null=True)
    request_headers = models.JSONField(null=True, blank=True)
    domain_info = models.ForeignKey(DomainInfo, on_delete=models.CASCADE, null=True, blank=True)
    scan_history = models.ForeignKey(
        ScanHistory,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="discovered_domains",
    )
    custom_dns_servers = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        managed = False
        db_table = "startScan_domain"
        unique_together = [["scan_history", "name"]]

    @property
    def start_scan_date(self):
        """
        Return the start date of the most recent scan for this domain.

        When scan_history is set on the domain, this simply returns the
        ScanHistory.start_scan_date; when it is null, the method returns None.
        """
        if self.scan_history is None:
            return None
        return self.scan_history.start_scan_date

    def get_recent_scan_id(self):
        if not self.scan_history_id:
            return None
        return self.scan_history_id

    def get_dns_servers(self):
        if self.custom_dns_servers:
            return [dns.strip() for dns in self.custom_dns_servers.split(",") if dns.strip()]
        return []

    def set_dns_servers(self, dns_servers):
        if isinstance(dns_servers, list):
            self.custom_dns_servers = ",".join(dns_servers)
        elif isinstance(dns_servers, str):
            self.custom_dns_servers = dns_servers
        else:
            self.custom_dns_servers = None

    def __str__(self):
        return str(self.name)

    @classmethod
    def get_all_counts(cls, queryset):
        return queryset.aggregate(total=Count("id"))

    @classmethod
    def get_project_counts(cls, project):
        return cls.get_all_counts(cls.objects.filter(scan_history__target__project=project))

    @classmethod
    def get_project_data(cls, project):
        queryset = cls.objects.filter(scan_history__target__project=project)
        return {
            "total_count": queryset.count(),
            "recent_domains": queryset.order_by("-insert_date")[:10],
        }

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )
        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range):
        raw_data = cls.get_counts_by_date(
            cls.objects.filter(scan_history__target__project=project), "insert_date", date_range[0]
        )
        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))
        return results[::-1]


class Subdomain(models.Model):
    # TODO: Add endpoint property instead of replicating endpoint fields here
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=1000)
    is_imported_subdomain = models.BooleanField(default=False)
    is_important = models.BooleanField(default=False, null=True, blank=True)
    http_url = models.CharField(max_length=10000, null=True, blank=True)
    http_header_path = models.CharField(max_length=1000, null=True, blank=True)
    discovered_date = models.DateTimeField(blank=True, null=True)
    cname = models.CharField(max_length=5000, blank=True, null=True)
    is_cdn = models.BooleanField(default=False, blank=True, null=True)
    cdn_name = models.CharField(max_length=200, blank=True, null=True)
    http_status = models.IntegerField(default=0)
    content_type = models.CharField(max_length=100, null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    webserver = models.CharField(max_length=1000, blank=True, null=True)
    content_length = models.IntegerField(default=0, blank=True, null=True)
    page_title = models.CharField(max_length=1000, blank=True, null=True)
    technologies = models.ManyToManyField("Technology", related_name="technologies", blank=True)
    ip_addresses = models.ManyToManyField("IPAddress", related_name="ip_addresses", blank=True)
    directories = models.ManyToManyField("DirectoryScan", related_name="directories", blank=True)
    waf = models.ManyToManyField("Waf", related_name="waf", blank=True)
    attack_surface = models.TextField(null=True, blank=True)
    verified = models.BooleanField(default=False, null=True, blank=True)
    sources = ArrayField(models.CharField(max_length=200), null=True, blank=True)

    def __str__(self):
        return str(self.name)

    @property
    def get_endpoint_count(self):
        ip_ids = list(self.ip_addresses.values_list("id", flat=True))
        q = Q(subdomain_id=self.id)
        if ip_ids:
            q |= Q(ip_address_id__in=ip_ids)
        endpoints = EndPoint.objects.filter(q)
        if self.scan_history:
            endpoints = endpoints.filter(scan_history=self.scan_history)
        return endpoints.distinct().count()

    @property
    def get_unknown_vulnerability_count(self):
        return self.get_vulnerabilities.filter(severity=-1).count()

    @property
    def get_info_count(self):
        return self.get_vulnerabilities.filter(severity=0).count()

    @property
    def get_low_count(self):
        return self.get_vulnerabilities.filter(severity=1).count()

    @property
    def get_medium_count(self):
        return self.get_vulnerabilities.filter(severity=2).count()

    @property
    def get_high_count(self):
        return self.get_vulnerabilities.filter(severity=3).count()

    @property
    def get_critical_count(self):
        return self.get_vulnerabilities.filter(severity=4).count()

    @property
    def get_total_vulnerability_count(self):
        return self.get_vulnerabilities.count()

    @property
    def get_vulnerabilities(self):
        vulns = Vulnerability.objects.filter(subdomain__name=self.name).prefetch_related(
            "cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "domain", "scan_history"
        )
        if self.scan_history:
            vulns = vulns.filter(scan_history=self.scan_history)
        return vulns

    @property
    def get_vulnerabilities_without_info(self):
        vulns = (
            Vulnerability.objects.filter(subdomain__name=self.name)
            .exclude(severity=0)
            .prefetch_related("cve_ids", "cwe_ids", "tags", "subdomain", "endpoint", "domain", "scan_history")
        )
        if self.scan_history:
            vulns = vulns.filter(scan_history=self.scan_history)
        return vulns

    @property
    def get_directories_count(self):
        subdomains = Subdomain.objects.filter(id=self.id)
        dirscan = DirectoryScan.objects.filter(directories__in=subdomains)
        return DirectoryFile.objects.filter(directory_files__in=dirscan).distinct().count()

    @property
    def get_todos(self):
        TodoNote = apps.get_model("recon_note", "TodoNote")
        notes = TodoNote.objects
        if self.scan_history:
            notes = notes.filter(scan_history=self.scan_history)
        notes = notes.filter(subdomain__id=self.id)
        return notes.values()

    @property
    def get_subscan_count(self):
        return SubScan.objects.filter(subdomain__id=self.id).distinct().count()

    def get_certificate_count(self):
        if hasattr(self, "certificate_count"):
            return self.certificate_count
        return Certificate.objects.filter(subdomain=self).count()

    @property
    def formatted_attack_surface(self):
        """Format description as HTML with proper styling"""
        return convert_markdown_to_html(self.attack_surface)

    @property
    def get_ports(self):
        """
        Get all unique ports associated with this subdomain's IP addresses.
        Uses a single Port queryset to avoid N+1 queries.
        """
        ip_qs = self.ip_addresses.all()
        port_numbers = Port.objects.filter(ip_address__in=ip_qs).values_list("number", flat=True).distinct()
        return sorted(port_numbers)

    @property
    def get_ports_by_ip(self):
        """
        Get ports grouped by IP address for this subdomain.
        Returns a dict mapping IP address (string) -> {ports: [...], is_cdn: bool}.
        Uses a single Port queryset with select_related to avoid N+1 queries.
        """
        ip_qs = self.ip_addresses.all().only("id", "address", "is_cdn")
        result = {ip.address: {"ports": [], "is_cdn": ip.is_cdn} for ip in ip_qs}
        if not result:
            return {}
        port_list = Port.objects.filter(ip_address__in=ip_qs).select_related("ip_address").order_by("number")
        for port in port_list:
            addr = port.ip_address.address if port.ip_address else None
            if addr is not None and addr in result:
                result[addr]["ports"].append(
                    {
                        "number": port.number,
                        "service_name": port.service_name,
                        "description": port.description,
                        "is_uncommon": port.is_uncommon,
                    }
                )
        return result

    @property
    def _default_endpoint(self):
        """
        Get the default endpoint for this subdomain (cached per instance).
        This property is used internally by display_* properties to avoid N+1 queries.
        """
        if not hasattr(self, "_cached_default_endpoint"):
            if self.scan_history and not self.scan_history.is_legacy_scan:
                self._cached_default_endpoint = EndPoint.objects.filter(subdomain=self, is_default=True).first()
            else:
                self._cached_default_endpoint = None
        return self._cached_default_endpoint

    @HybridProperty
    def display_http_status(self):
        """Return default endpoint http_status for Secator scans, otherwise subdomain http_status."""
        default_endpoint = self._default_endpoint
        return default_endpoint.http_status if default_endpoint else self.http_status

    @HybridProperty
    def display_page_title(self):
        """Return default endpoint page_title for Secator scans, otherwise subdomain page_title."""
        default_endpoint = self._default_endpoint
        return default_endpoint.page_title if default_endpoint else self.page_title

    @HybridProperty
    def display_content_length(self):
        """Return default endpoint content_length for Secator scans, otherwise subdomain content_length."""
        default_endpoint = self._default_endpoint
        if default_endpoint:
            return default_endpoint.content_length
        return self.content_length

    @HybridProperty
    def display_response_time(self):
        """Return default endpoint response_time for Secator scans, otherwise subdomain response_time."""
        default_endpoint = self._default_endpoint
        if default_endpoint:
            return default_endpoint.response_time
        return self.response_time

    @classmethod
    def get_counts(cls, queryset):
        """Get various subdomain counts. IP vs hostname is detected in Python for portability."""
        import ipaddress

        total_count = queryset.count()
        with_ip_count = queryset.filter(ip_addresses__isnull=False).distinct().count()
        alive_count = queryset.exclude(http_status__exact=0).count()

        ip_count = 0
        for name in queryset.values_list("name", flat=True).iterator():
            if not name:
                continue
            with contextlib.suppress(ValueError):
                ipaddress.ip_address(str(name).strip())
                ip_count += 1
        hostname_count = total_count - ip_count

        return {
            "total": total_count,
            "with_ip": with_ip_count,
            "alive": alive_count,
            "hostnames": hostname_count,
            "ip_addresses": ip_count,
        }

    @classmethod
    def get_all_counts(cls, queryset):
        """Get all vulnerability counts. Vuln counts are scoped to the given queryset (e.g. latest subdomains per project)."""
        subdomain_ids = list(queryset.values_list("id", flat=True))
        if not subdomain_ids:
            return {
                "total": 0,
                "with_ip": 0,
                "alive": 0,
                "vuln_info": 0,
                "vuln_low": 0,
                "vuln_medium": 0,
                "vuln_high": 0,
                "vuln_critical": 0,
                "vuln_unknown": 0,
                "total_vuln_count": 0,
                "total_vuln_ignore_info_count": 0,
            }

        # Use Exists subquery for with_ip to avoid heavy M2M distinct count
        through = cls.ip_addresses.through
        has_ip = Exists(through.objects.filter(subdomain_id=OuterRef("pk")))
        base_counts = queryset.annotate(_has_ip=has_ip).aggregate(
            total=Count("id"),
            with_ip=Count("id", filter=Q(_has_ip=True)),
            alive=Count("id", filter=~Q(http_status=0)),
        )

        vuln_counts_raw = Vulnerability.objects.filter(subdomain__in=subdomain_ids).aggregate(
            vuln_info=Count("id", filter=Q(severity=0)),
            vuln_low=Count("id", filter=Q(severity=1)),
            vuln_medium=Count("id", filter=Q(severity=2)),
            vuln_high=Count("id", filter=Q(severity=3)),
            vuln_critical=Count("id", filter=Q(severity=4)),
            vuln_unknown=Count("id", filter=Q(severity=-1)),
        )

        # Combine and calculate totals
        total_vuln_count = sum(v or 0 for v in vuln_counts_raw.values())
        total_vuln_ignore_info_count = (
            (vuln_counts_raw["vuln_low"] or 0)
            + (vuln_counts_raw["vuln_medium"] or 0)
            + (vuln_counts_raw["vuln_high"] or 0)
            + (vuln_counts_raw["vuln_critical"] or 0)
        )

        return {
            **base_counts,
            **vuln_counts_raw,
            "total_vuln_count": total_vuln_count,
            "total_vuln_ignore_info_count": total_vuln_ignore_info_count,
        }

    @classmethod
    def get_project_counts(cls, project):
        """Get all counts for a specific project with unique subdomains by name"""
        # Get unique subdomains by name for the project, keeping the latest (highest ID)
        from django.db.models import Max

        latest_subdomain_ids = (
            cls.objects.filter(domain__scan_history__target__project=project)
            .values("name")
            .annotate(max_id=Max("id"))
            .values_list("max_id", flat=True)
        )
        queryset = cls.objects.filter(id__in=latest_subdomain_ids)
        return cls.get_all_counts(queryset)

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        """Get daily subdomain counts for a queryset"""
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range):
        """Get subdomain timeline data for a specific project"""
        raw_data = cls.get_counts_by_date(
            cls.objects.filter(scan_history__target__project=project), "discovered_date", date_range[0]
        )

        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))

        return results[::-1]

    class Meta:
        indexes = [
            models.Index(fields=["scan_history_id", "content_length"], name="ss_sub_scan_content_len"),
        ]


class SubScan(models.Model):
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=100, blank=True, null=True)
    start_scan_date = models.DateTimeField()
    status = models.IntegerField()
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.ForeignKey(
        "IpAddress",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="subscans",
    )
    stop_scan_date = models.DateTimeField(null=True, blank=True)
    error_message = models.CharField(max_length=300, blank=True, null=True)
    engine = models.ForeignKey(EngineType, on_delete=models.CASCADE, blank=True, null=True)
    subdomain_subscan_ids = models.ManyToManyField("Subdomain", related_name="subdomain_subscan_ids", blank=True)
    secator_runner = models.OneToOneField(
        "SecatorRunner",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subscan",
        help_text="Secator runner linked to this subscan (Secator scans only)",
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(subdomain__isnull=False, ip_address__isnull=False),
                name="subscan_subdomain_ip_xor",
            ),
        ]
        indexes = [
            models.Index(fields=["scan_history_id", "status"]),
            models.Index(fields=["scan_history_id", "stop_scan_date"], name="ss_subscan_scan_stop_idx"),
        ]

    def get_completed_ago(self):
        if self.stop_scan_date:
            return get_time_taken(timezone.now(), self.stop_scan_date)

    def get_total_time_taken(self):
        if self.stop_scan_date:
            return get_time_taken(self.stop_scan_date, self.start_scan_date)

    def get_elapsed_time(self):
        return get_time_taken(timezone.now(), self.start_scan_date)

    def get_task_name_str(self):
        return dict(ENGINE_DISPLAY_NAMES).get(self.type, "Unknown")

    @property
    def display_runner_type(self):
        """
        Human-friendly runner type for UI (Task, Workflow, Scan, or Legacy).
        Aligns with ScanHistory.display_runner_type for consistent column display.
        """
        if self.engine:
            return "Legacy"
        runner = getattr(self, "secator_runner", None)
        if runner and runner.runner_type:
            return runner.runner_type.replace("_", " ").strip().title()
        return "Task" if (runner or self.type) else ""

    @property
    def display_scan_name(self):
        """
        Human-friendly scan/engine name for UI.
        Aligns with ScanHistory.display_scan_name for consistent column display.
        """
        if self.engine:
            return self.engine.engine_name or "—"
        if getattr(self, "secator_runner", None) and self.secator_runner.runner_name:
            return self.secator_runner.runner_name
        return self.type or self.get_task_name_str() or "—"

    @property
    def scan_engine_used(self):
        """
        Unified display string for the "Scan engine used" column: "Type: Name"
        (e.g. "Task: nuclei", "Legacy: EngineName"), like ScanHistory in history.html.
        Used for the single column and real-time WebSocket updates.
        """
        runner_type = self.display_runner_type
        scan_name = self.display_scan_name
        if runner_type and scan_name:
            return f"{runner_type}: {scan_name}"
        return scan_name or runner_type or "—"

    @property
    def secator_worker_name(self) -> str:
        """
        Human-friendly worker name for UI (where the subscan runs).
        Uses secator_runner.worker if set, else the parent scan's main runner worker.
        Uses scan_history._get_main_runner() so prefetch_related on scan_history is used.
        """
        runner = getattr(self, "secator_runner", None)
        if runner and runner.worker_id and getattr(runner, "worker", None):
            return runner.worker.name or "Local"
        if not self.scan_history:
            return "Local"
        main_runner = self.scan_history._get_main_runner()
        if main_runner and main_runner.worker_id and getattr(main_runner, "worker", None):
            return main_runner.worker.name or "Local"
        return "Local"

    def _get_status_field_value(self):
        """Get the raw status field value to avoid recursion."""
        return self._meta.get_field("status").value_from_object(self)

    @property
    def status_string(self):
        """
        Get status as string. For legacy scans, returns status code as string.
        For Secator scans, returns status string from runner.

        To avoid N+1 queries when accessing this for many instances, a controller
        can pre-populate `self.scan_history._main_runner` (e.g. via `prefetch_related`) and
        this method will use it instead of querying per-instance.
        """
        if not self.scan_history:
            return str(self._get_status_field_value())
        if self.scan_history.is_legacy_scan:
            return str(self._get_status_field_value())
        # For Secator scans, get status from parent scan's main runner
        # Prefer a cached main runner if one has been set on scan_history
        main_runner = getattr(self.scan_history, "_main_runner", None)

        if main_runner is None:
            # Fallback: query for the main runner when not provided
            from startScan.models import SecatorRunner

            runners = SecatorRunner.objects.filter(scan_history=self.scan_history)
            main_runner = runners.filter(runner_type__in=["workflow", "scan"]).first()

        if main_runner and main_runner.status:
            return str(main_runner.status).upper()
        # Fallback: try to get from runner_data
        if main_runner and getattr(main_runner, "runner_data", None):
            return str(main_runner.runner_data.get("status", "")).upper()
        # Task-only scan (no workflow/scan runner): use this subscan's secator_runner
        if getattr(self, "secator_runner", None) and self.secator_runner.runner_data:
            return str(self.secator_runner.runner_data.get("status", "")).upper()
        if getattr(self, "secator_runner", None) and self.secator_runner.status:
            return str(self.secator_runner.status).upper()
        # Final fallback: use the field value
        return str(self._get_status_field_value()).upper()

    @property
    def status_code(self):
        """
        Get status as integer code (for compatibility with JavaScript).
        For legacy scans, returns integer status code from field.
        For Secator scans, maps status string to code.
        """
        if not self.scan_history:
            return self._get_status_field_value()
        if self.scan_history.is_legacy_scan:
            return self._get_status_field_value()
        # For Secator scans, map status string to code
        from reNgine.secator import SecatorProgressSync

        status_str = self.status_string
        if isinstance(status_str, str):
            return SecatorProgressSync.map_secator_status_to_rengine(status_str)
        # Fallback: try to convert to int, but handle non-numeric strings safely
        if status_str:
            try:
                return int(status_str)
            except (ValueError, TypeError):
                # If conversion fails, return INITIATED_TASK as safe default
                from reNgine.definitions import INITIATED_TASK

                return INITIATED_TASK
        return -1

    def get_status_display(self):
        """Get human-readable status display."""
        from reNgine.definitions import TASK_STATUS_MAP

        status_code = self.status_code
        return TASK_STATUS_MAP.get(status_code, "UNKNOWN")

    @classmethod
    def get_all_counts(cls, queryset):
        """Aggregate total subscans and status distribution"""
        return queryset.aggregate(
            total=Count("id"),
            pending=Count("id", filter=models.Q(status=-1)),
            running=Count("id", filter=models.Q(status=1)),
            completed=Count("id", filter=models.Q(status=2)),
            failed=Count("id", filter=models.Q(status=0)),
            aborted=Count("id", filter=models.Q(status=3)),
            finalizing=Count("id", filter=models.Q(status=4)),
        )

    @classmethod
    def get_project_counts(cls, project):
        """Get subscan statistics for a specific project"""
        return cls.get_all_counts(cls.objects.filter(scan_history__target__project=project))

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        """Get daily subscan counts for a queryset"""
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range, status=None):
        """Get subscan timeline data with optional status filter"""
        queryset = cls.objects.filter(scan_history__target__project=project)

        if status is not None:
            queryset = queryset.filter(status=status)

        raw_data = cls.get_counts_by_date(queryset, "start_scan_date", date_range[0])

        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))

        return results[::-1]


class EndPoint(models.Model):
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.ForeignKey(
        "IpAddress",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="ip_endpoints",
    )
    source = models.CharField(max_length=200, null=True, blank=True)
    http_url = models.CharField(max_length=30000)
    content_length = models.IntegerField(default=0, null=True, blank=True)
    page_title = models.CharField(max_length=30000, null=True, blank=True)
    http_status = models.IntegerField(default=0, null=True, blank=True)
    content_type = models.CharField(max_length=100, null=True, blank=True)
    discovered_date = models.DateTimeField(blank=True, null=True)
    response_time = models.FloatField(null=True, blank=True)
    webserver = models.CharField(max_length=1000, blank=True, null=True)
    is_default = models.BooleanField(null=True, blank=True, default=False)
    matched_gf_patterns = models.CharField(max_length=10000, null=True, blank=True)
    screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
    techs = models.ManyToManyField("Technology", related_name="techs", blank=True)
    # used for subscans
    endpoint_subscan_ids = models.ManyToManyField("SubScan", related_name="endpoint_subscan_ids", blank=True)
    # Secator fields
    method = models.CharField(max_length=10, null=True, blank=True, help_text="HTTP method: GET, POST, etc.")
    words = models.IntegerField(default=0, null=True, blank=True, help_text="Number of words in the response")
    lines = models.IntegerField(default=0, null=True, blank=True, help_text="Number of lines in the response")
    headers = models.JSONField(null=True, blank=True, help_text="HTTP headers (response_headers and request_headers)")
    is_directory = models.BooleanField(
        null=True, blank=True, default=False, help_text="Whether the endpoint is a directory listing"
    )
    stored_response_path = models.CharField(
        max_length=1000, null=True, blank=True, help_text="Path to stored response file"
    )
    confidence = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        choices=CONFIDENCE_CHOICES,
        help_text="Confidence level: low, medium, high",
    )

    def __str__(self):
        return self.http_url

    @HybridProperty
    def is_alive(self):
        return self.http_status

    @classmethod
    def get_counts(cls, queryset):
        """Get endpoint counts in a single query"""
        return {"total": queryset.count(), "alive": queryset.filter(http_status__gt=0).count()}

    @classmethod
    def get_project_counts(cls, project):
        """Get endpoint counts for a specific project with unique URLs"""
        # Get unique endpoints by http_url for the project, keeping the latest (highest ID)
        from django.db.models import Max

        latest_endpoint_ids = (
            cls.objects.filter(scan_history__target__project=project)
            .values("http_url")
            .annotate(max_id=Max("id"))
            .values_list("max_id", flat=True)
        )
        queryset = cls.objects.filter(id__in=latest_endpoint_ids)
        return cls.get_counts(queryset)

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        """Get daily vulnerability counts for a queryset"""
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range):
        """Get vulnerability timeline data for a specific project"""
        raw_data = cls.get_counts_by_date(
            cls.objects.filter(scan_history__target__project=project), "discovered_date", date_range[0]
        )

        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))

        return results[::-1]

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(subdomain__isnull=False, ip_address__isnull=True)
                    | models.Q(subdomain__isnull=True, ip_address__isnull=False)
                ),
                name="endpoint_exactly_one_host",
            ),
        ]
        indexes = [
            models.Index(fields=["scan_history_id", "content_length"], name="ss_ep_scan_content_len"),
        ]


class VulnerabilityTags(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

    @classmethod
    def get_most_common(cls, vulnerabilities, limit=7):
        """Get most common vulnerability tags"""
        return (
            cls.objects.filter(vuln_tags__in=vulnerabilities)
            .values("name")
            .distinct()
            .annotate(nused=Count("vuln_tags", filter=Q(vuln_tags__in=vulnerabilities)))
            .order_by("-nused")[:limit]
        )


class CveId(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

    @classmethod
    def get_most_common(cls, vulnerabilities, limit=7):
        """Get most common CVEs in vulnerabilities"""
        return (
            cls.objects.filter(cve_ids__in=vulnerabilities)
            .values("name")
            .distinct()
            .annotate(nused=Count("cve_ids", filter=Q(cve_ids__in=vulnerabilities)))
            .order_by("-nused")[:limit]
        )


class CweId(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

    @classmethod
    def get_most_common(cls, vulnerabilities, limit=7):
        """Get most common CWEs in vulnerabilities"""
        return (
            cls.objects.filter(cwe_ids__in=vulnerabilities)
            .values("name")
            .distinct()
            .annotate(nused=Count("cwe_ids", filter=Q(cwe_ids__in=vulnerabilities)))
            .order_by("-nused")[:limit]
        )


class LLMVulnerabilityReport(models.Model):
    url_path = models.CharField(max_length=2000)
    title = models.CharField(max_length=2500)
    description = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    remediation = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.title

    @property
    def formatted_description(self):
        """Format description as HTML with proper styling. Returns None when description is None."""
        if self.description is None:
            return None
        return convert_markdown_to_html(self.description)

    @property
    def formatted_impact(self):
        """Format impact as HTML with proper styling. Returns None when impact is None."""
        if self.impact is None:
            return None
        return convert_markdown_to_html(self.impact)

    @property
    def formatted_remediation(self):
        """Format remediation as HTML with proper styling. Returns None when remediation is None."""
        if self.remediation is None:
            return None
        return convert_markdown_to_html(self.remediation)

    @property
    def formatted_references(self):
        """Format references as HTML with proper styling. Returns None when references is None."""
        if self.references is None:
            return None
        return convert_markdown_to_html(self.references)


class Vulnerability(models.Model):
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    source = models.CharField(max_length=200, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, blank=True, null=True)
    ip_address = models.ForeignKey(
        "IpAddress",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )
    port = models.ForeignKey(
        "Port",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    template = models.CharField(max_length=100, null=True, blank=True)
    template_url = models.CharField(max_length=2500, null=True, blank=True)
    template_id = models.CharField(max_length=200, null=True, blank=True)
    matcher_name = models.CharField(max_length=500, null=True, blank=True)
    name = models.CharField(max_length=2500)
    severity = models.IntegerField()
    description = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    remediation = models.TextField(null=True, blank=True)

    extracted_results = ArrayField(models.CharField(max_length=5000), blank=True, null=True)

    tags = models.ManyToManyField("VulnerabilityTags", related_name="vuln_tags", blank=True)
    references = models.TextField(null=True, blank=True)
    cve_ids = models.ManyToManyField("CveId", related_name="cve_ids", blank=True)
    cwe_ids = models.ManyToManyField("CweId", related_name="cwe_ids", blank=True)

    cvss_metrics = models.CharField(max_length=500, null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True, default=None)
    curl_command = models.CharField(max_length=15000, null=True, blank=True)
    type = models.CharField(max_length=100, null=True, blank=True)
    http_url = models.CharField(max_length=10000, null=True)
    discovered_date = models.DateTimeField(null=True)
    open_status = models.BooleanField(null=True, blank=True, default=True)
    hackerone_report_id = models.CharField(max_length=50, null=True, blank=True)
    request = models.TextField(blank=True, null=True)
    response = models.TextField(blank=True, null=True)
    is_llm_used = models.BooleanField(null=True, blank=True, default=False)
    # used for subscans
    vuln_subscan_ids = models.ManyToManyField("SubScan", related_name="vuln_subscan_ids", blank=True)
    cvss_vec = models.CharField(max_length=200, null=True, blank=True)
    epss_score = models.FloatField(null=True, blank=True)
    confidence_nb = models.IntegerField(default=0, null=True, blank=True)
    severity_nb = models.IntegerField(default=0, null=True, blank=True)
    ip = models.CharField(max_length=100, null=True, blank=True)
    reference = models.CharField(max_length=10000, null=True, blank=True)

    def __str__(self):
        cve_str = ", ".join(f"`{cve.name}`" for cve in self.cve_ids.all())
        severity = NUCLEI_REVERSE_SEVERITY_MAP[self.severity]
        return f"{self.http_url} | `{severity.upper()}` | `{self.name}` | `{cve_str}`"

    def get_severity(self):
        return self.severity

    def get_cve_str(self):
        return ", ".join(f"`{cve.name}`" for cve in self.cve_ids.all())

    def get_cwe_str(self):
        return ", ".join(f"`{cwe.name}`" for cwe in self.cwe_ids.all())

    def get_tags_str(self):
        return ", ".join(f"`{tag.name}`" for tag in self.tags.all())

    def get_refs_str(self):
        return self.references

    def get_path(self):
        return urlparse(self.http_url).path

    @classmethod
    def get_project_data(cls, project):
        """Get vulnerability data for a specific project"""
        queryset = cls.objects.filter(scan_history__target__project=project).order_by("-discovered_date")[:50]

        feed = queryset.select_related("subdomain", "endpoint", "domain", "scan_history").prefetch_related(
            "cve_ids", "cwe_ids", "tags"
        )

        return {
            "feed": feed,
            "most_common_cve": CveId.get_most_common(queryset),
            "most_common_cwe": CweId.get_most_common(queryset),
            "most_common_tags": VulnerabilityTags.get_most_common(queryset),
        }

    @staticmethod
    def get_counts_by_date(queryset, date_field, since_date):
        """Get daily vulnerability counts for a queryset"""
        counts = (
            queryset.filter(**{f"{date_field}__gte": since_date})
            .annotate(date=TruncDay(date_field))
            .values("date")
            .annotate(count=Count("id"))
            .order_by("date")
        )

        return {item["date"]: item["count"] for item in counts}

    @classmethod
    def get_project_timeline(cls, project, date_range):
        """Get vulnerability timeline data for a specific project"""
        raw_data = cls.get_counts_by_date(
            cls.objects.filter(scan_history__target__project=project), "discovered_date", date_range[0]
        )

        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(raw_data.get(aware_date, 0))

        return results[::-1]

    @property
    def formatted_description(self):
        """Format description as HTML with proper styling. Returns None when description is None."""
        if self.description is None:
            return None
        return convert_markdown_to_html(self.description)

    @property
    def formatted_impact(self):
        """Format impact as HTML with proper styling. Returns None when impact is None."""
        if self.impact is None:
            return None
        return convert_markdown_to_html(self.impact)

    @property
    def formatted_remediation(self):
        """Format remediation as HTML with proper styling. Returns None when remediation is None."""
        if self.remediation is None:
            return None
        return convert_markdown_to_html(self.remediation)

    @property
    def formatted_references(self):
        """Format references as HTML with proper styling. Returns None when references is None."""
        if self.references is None:
            return None
        return convert_markdown_to_html(self.references)

    class Meta:
        indexes = [
            models.Index(fields=["scan_history_id", "cvss_score"], name="ss_vuln_scan_cvss_idx"),
            models.Index(fields=["scan_history_id", "severity"], name="ss_vuln_scan_severity_idx"),
            models.Index(fields=["scan_history_id", "name"], name="ss_vuln_scan_name_idx"),
            models.Index(fields=["domain_id", "name"], name="ss_vuln_target_name_idx"),
            models.Index(fields=["subdomain_id", "severity"], name="ss_vuln_subdomain_severity_idx"),
        ]


class Secret(models.Model):
    """Secret finding from Secator tasks (gitleaks, trufflehog, trivy). Stored in plain text for reconnaissance context."""

    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
    rule_name = models.CharField(max_length=500)
    matched_at = models.CharField(max_length=2000)
    source = models.CharField(max_length=100, null=True, blank=True)
    value = models.TextField()
    extra_data = models.JSONField(null=True, blank=True)
    discovered_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.rule_name} @ {self.matched_at}"

    class Meta:
        indexes = [
            models.Index(fields=["scan_history_id"], name="ss_secret_scan_idx"),
        ]


class ScanActivity(models.Model):
    id = models.AutoField(primary_key=True)
    scan_of = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
    title = models.CharField(max_length=1000)
    name = models.CharField(max_length=1000)
    time = models.DateTimeField()
    status = models.IntegerField()
    error_message = models.CharField(max_length=300, blank=True, null=True)
    traceback = models.TextField(blank=True, null=True)
    runner_id = models.ForeignKey(
        "SecatorRunner",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="SecatorRunner associated with this activity",
    )
    results_dir = models.CharField(
        max_length=500,
        blank=True,
        help_text="Results directory path for this activity (extracted from Secator run_opts.reports_folder)",
    )

    class Meta:
        indexes = [
            models.Index(fields=["scan_of_id", "status"]),
            models.Index(fields=["scan_of_id", "runner_id", "time"]),
        ]

    @property
    def celery_id(self):
        """Get celery_id from associated runner if available."""
        if self.runner_id and self.runner_id.celery_id:
            return self.runner_id.celery_id
        return None

    def _get_status_field_value(self):
        """Get the raw status field value to avoid recursion."""
        return self._meta.get_field("status").value_from_object(self)

    @property
    def status_string(self):
        """
        Get status as string. For legacy scans, returns status code as string.
        For Secator scans, returns status string from runner.
        """
        if not self.scan_of:
            return str(self._get_status_field_value())
        if self.scan_of.is_legacy_scan:
            return str(self._get_status_field_value())
        # For Secator scans, get status from runner
        if self.runner_id and self.runner_id.status:
            return str(self.runner_id.status).upper()
        # Fallback: try to get from runner_data
        if self.runner_id and self.runner_id.runner_data:
            return str(self.runner_id.runner_data.get("status", "")).upper()
        # Final fallback: use the field value
        return str(self._get_status_field_value()).upper()

    @property
    def status_code(self):
        """
        Get status as integer code (for compatibility with JavaScript).
        For legacy scans, returns integer status code from field.
        For Secator scans, maps status string to code.
        """
        if not self.scan_of:
            return self._get_status_field_value()
        if self.scan_of.is_legacy_scan:
            return self._get_status_field_value()
        # For Secator scans, map status string to code
        from reNgine.secator import SecatorProgressSync

        status_str = self.status_string
        if isinstance(status_str, str):
            return SecatorProgressSync.map_secator_status_to_rengine(status_str)
        # Fallback: try to convert to int, but handle non-numeric strings safely
        if status_str:
            try:
                return int(status_str)
            except (ValueError, TypeError):
                # If conversion fails, return INITIATED_TASK as safe default
                from reNgine.definitions import INITIATED_TASK

                return INITIATED_TASK
        return -1

    def get_status_display(self):
        """Get human-readable status display."""
        from reNgine.definitions import TASK_STATUS_MAP

        status_code = self.status_code
        return TASK_STATUS_MAP.get(status_code, "UNKNOWN")

    def __str__(self):
        return str(self.title)


class Command(models.Model):
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
    activity = models.ForeignKey(ScanActivity, on_delete=models.CASCADE, blank=True, null=True)
    command = models.TextField(blank=True, null=True)
    return_code = models.IntegerField(blank=True, null=True)
    output = models.TextField(blank=True, null=True)
    time = models.DateTimeField()
    end_time = models.DateTimeField(blank=True, null=True)
    elapsed = models.FloatField(blank=True, null=True)
    errors = models.JSONField(default=list, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=200, blank=True, null=True)
    status = models.CharField(max_length=50, blank=True, null=True)
    cwd = models.CharField(max_length=500, blank=True, null=True)
    runner_type = models.CharField(max_length=50, blank=True, null=True)
    has_parent = models.BooleanField(default=False)
    has_children = models.BooleanField(default=False)
    workflow_name = models.CharField(max_length=200, blank=True, null=True)
    node_id = models.CharField(max_length=500, blank=True, null=True)
    ancestor_id = models.CharField(max_length=500, blank=True, null=True)
    scan_type = models.CharField(max_length=50, blank=True, null=True, help_text="Scan type from run_opts.scan_type")

    class Meta:
        indexes = [
            models.Index(fields=["scan_history_id", "name", "time"]),
        ]

    def _get_status_field_value(self):
        """Get the raw status field value to avoid recursion."""
        return self._meta.get_field("status").value_from_object(self)

    @property
    def status_string(self):
        """
        Get status as string. For legacy scans, returns status string from field.
        For Secator scans, returns status string from runner.
        """
        if not self.scan_history:
            return self._get_status_field_value() or ""
        if self.scan_history.is_legacy_scan:
            return self._get_status_field_value() or ""
        # For Secator scans, get status from activity's runner
        if self.activity and self.activity.runner_id and self.activity.runner_id.status:
            return str(self.activity.runner_id.status).upper()
        # Fallback: try to get from activity's runner_data
        if self.activity and self.activity.runner_id and self.activity.runner_id.runner_data:
            return str(self.activity.runner_id.runner_data.get("status", "")).upper()
        # Final fallback: use the field value
        status_value = self._get_status_field_value()
        return str(status_value).upper() if status_value else ""

    def __str__(self):
        return str(self.command)

    def get_formatted_output(self):
        """
        Get formatted output using the output formatter utility.
        Returns a dictionary with formatted output and metadata.
        """
        from html import escape

        from reNgine.utilities.output_formatter import format_output

        if not self.output:
            return {
                "formatted": "",
                "is_json": False,
                "has_ansi": False,
                "raw": "",
            }

        try:
            return format_output(self.output)
        except Exception as exc:
            logger.log_line(
                PREFIX_SCAN,
                "MODEL",
                "Output formatting failed for command %s: %s" % (self.command, exc),
                level="warning",
                exc_info=True,
            )
            escaped_output = escape(self.output)
            return {
                "formatted": escaped_output,
                "is_json": False,
                "has_ansi": False,
                "raw": self.output,
            }


class Waf(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500)
    manufacturer = models.CharField(max_length=500, blank=True, null=True)

    def __str__(self):
        return str(self.name)


class Technology(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500, blank=True, null=True)
    value = models.CharField(max_length=500, null=True, blank=True)
    category = models.CharField(max_length=200, null=True, blank=True)
    stored_response_path = models.CharField(max_length=1000, null=True, blank=True)

    def __str__(self):
        return str(self.name)

    @classmethod
    def get_project_data(cls, project):
        """Get technology data for a specific project"""
        subdomain_ids = Subdomain.objects.filter(scan_history__target__project=project).values_list("id", flat=True)

        return {
            "most_used": cls.objects.filter(technologies__in=subdomain_ids)
            .values("name")
            .annotate(count=Count("name"))
            .order_by("-count")[:10]
        }

    @classmethod
    def get_most_used(cls, subdomains, limit=10):
        """Get most used technologies"""
        return (
            cls.objects.filter(technologies__in=subdomains)
            .values("name")
            .annotate(count=Count("name"))
            .order_by("-count")[:limit]
        )


class CountryISO(models.Model):
    id = models.AutoField(primary_key=True)
    iso = models.CharField(max_length=10, blank=True)
    name = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return str(self.name)

    @classmethod
    def get_project_data(cls, project):
        """Get country data for a specific project - OPTIMIZED"""
        subdomains = Subdomain.objects.filter(scan_history__target__project=project).values_list("id", flat=True)

        ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct()

        return {"asset_countries": cls.get_asset_countries(ip_addresses)}

    @classmethod
    def get_asset_countries(cls, ip_addresses):
        """Get countries for assets"""
        return cls.objects.filter(ipaddress__in=ip_addresses).annotate(count=Count("iso")).order_by("-count")


class IpAddress(models.Model):
    id = models.AutoField(primary_key=True)
    address = models.CharField(max_length=100, blank=True, null=True)
    is_cdn = models.BooleanField(default=False)
    geo_iso = models.ForeignKey(CountryISO, on_delete=models.CASCADE, null=True, blank=True)
    version = models.IntegerField(blank=True, null=True)
    is_private = models.BooleanField(default=False)
    reverse_pointer = models.CharField(max_length=100, blank=True, null=True)
    # this is used for querying which ip was discovered during subcan
    ip_subscan_ids = models.ManyToManyField("SubScan", related_name="ip_subscan_ids")
    alive = models.BooleanField(default=False, null=True, blank=True)
    protocol = models.CharField(
        max_length=10, null=True, blank=True, choices=IP_PROTOCOL_CHOICES, help_text="IP protocol: IPv4 or IPv6"
    )
    extra_data = models.JSONField(null=True, blank=True, help_text="Optional data e.g. ASN from getasn")
    is_important = models.BooleanField(default=False, null=True, blank=True)
    attack_surface = models.TextField(null=True, blank=True)

    def __str__(self):
        return str(self.address)

    @property
    def formatted_attack_surface(self):
        return convert_markdown_to_html(self.attack_surface)

    @classmethod
    def get_project_data(cls, project):
        """Get IP address data for a specific project"""
        subdomains = Subdomain.objects.filter(scan_history__target__project=project).values_list("id", flat=True)

        base_query = cls.objects.filter(ip_addresses__in=subdomains).distinct()

        return {"total_count": base_query.count(), "most_used": cls.get_most_used(base_query)}

    @classmethod
    def get_counts(cls, queryset):
        """Distinct IP rows in queryset; alive = rows with alive=True."""
        return {"total": queryset.count(), "alive": queryset.filter(alive=True).count()}

    @classmethod
    def get_counts_for_scan_histories(cls, scan_ids):
        """Distinct IPs linked to any of the given scans (subdomain M2M or endpoint FK)."""
        scan_id_list = list(scan_ids)
        if not scan_id_list:
            return {"total": 0, "alive": 0}
        queryset = cls.objects.filter(
            Q(ip_addresses__scan_history_id__in=scan_id_list) | Q(ip_endpoints__scan_history_id__in=scan_id_list)
        ).distinct()
        return cls.get_counts(queryset)

    @classmethod
    def get_project_counts(cls, project):
        """Distinct IP counts for all scans in the project (same semantics as EndPoint.get_project_counts)."""
        scan_ids = ScanHistory.objects.filter(target__project=project).values_list("id", flat=True)
        return cls.get_counts_for_scan_histories(scan_ids)

    @classmethod
    def get_project_timeline(cls, project, date_range):
        """Per-day counts of distinct IPs linked to subdomains discovered that day (7-day window)."""
        if not date_range:
            return []
        since = date_range[0]
        qs = (
            Subdomain.objects.filter(
                scan_history__target__project=project,
                discovered_date__gte=since,
            )
            .exclude(ip_addresses__isnull=True)
            .annotate(day=TruncDay("discovered_date"))
            .values_list("day", "ip_addresses__id")
            .distinct()
        )
        counts_by_day: dict = defaultdict(int)
        for day, _ip_id in qs.iterator(chunk_size=5000):
            if day is not None:
                counts_by_day[day] += 1
        results = []
        for date in date_range:
            aware_date = date_to_aware_datetime(date)
            results.append(counts_by_day.get(aware_date, 0))
        return results[::-1]

    @classmethod
    def get_most_used(cls, queryset, subdomains=None, limit=7):
        """Get most common IP addresses with count annotation"""
        return (
            queryset.annotate(count=Count("ip_addresses")).order_by("-count").exclude(ip_addresses__isnull=True)[:limit]
        )


class Port(models.Model):
    id = models.AutoField(primary_key=True)
    number = models.IntegerField(default=0)
    is_uncommon = models.BooleanField(default=False)
    service_name = models.CharField(max_length=255, blank=True, null=True)
    description = models.CharField(max_length=1000, blank=True, null=True)
    ip_address = models.ForeignKey("IpAddress", on_delete=models.CASCADE, related_name="ports", null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    cpes = ArrayField(models.CharField(max_length=500), null=True, blank=True)
    protocol = models.CharField(max_length=10, null=True, blank=True)
    host = models.CharField(max_length=1000, null=True, blank=True)
    confidence = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        choices=CONFIDENCE_CHOICES,
        help_text="Confidence level: low, medium, high",
    )
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        help_text="Secator tool-specific port metadata (e.g. nmap service block)",
    )

    class Meta:
        unique_together = ("ip_address", "number")

    def __str__(self):
        return str(self.number)

    @classmethod
    def get_project_data(cls, project):
        """Get port data for a specific project"""
        subdomains = Subdomain.objects.filter(scan_history__target__project=project).values_list("id", flat=True)

        ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct()

        return {"most_used": cls.get_most_used(ip_addresses)}

    @classmethod
    def get_most_used(cls, ip_addresses, limit=10):
        """Get most used ports"""
        return (
            cls.objects.filter(ip_address__in=ip_addresses)
            .values("number", "service_name")
            .annotate(count=Count("number"))
            .order_by("-count")[:limit]
        )


class DirectoryFile(models.Model):
    id = models.AutoField(primary_key=True)
    length = models.IntegerField(default=0)
    lines = models.IntegerField(default=0)
    http_status = models.IntegerField(default=0)
    words = models.IntegerField(default=0)
    name = models.CharField(max_length=500, blank=True, null=True)
    url = models.CharField(max_length=5000, blank=True, null=True)
    content_type = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        # Indexes for performance without unique constraints
        indexes = [
            models.Index(fields=["name", "url", "http_status"]),
            models.Index(fields=["http_status"]),
        ]

    def __str__(self):
        return str(self.name)


class DirectoryScan(models.Model):
    id = models.AutoField(primary_key=True)
    command_line = models.CharField(max_length=5000, blank=True, null=True)
    directory_files = models.ManyToManyField("DirectoryFile", related_name="directory_files", blank=True)
    scanned_date = models.DateTimeField(null=True)
    # this is used for querying which ip was discovered during subcan
    dir_subscan_ids = models.ManyToManyField("SubScan", related_name="dir_subscan_ids", blank=True)


class MetaFinderDocument(models.Model):
    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    doc_name = models.CharField(max_length=1000, null=True, blank=True)
    url = models.CharField(max_length=10000, null=True, blank=True)
    title = models.CharField(max_length=1000, null=True, blank=True)
    author = models.CharField(max_length=1000, null=True, blank=True)
    producer = models.CharField(max_length=1000, null=True, blank=True)
    creator = models.CharField(max_length=1000, null=True, blank=True)
    os = models.CharField(max_length=1000, null=True, blank=True)
    http_status = models.IntegerField(default=0, null=True, blank=True)
    creation_date = models.CharField(max_length=1000, blank=True, null=True)
    modified_date = models.CharField(max_length=1000, blank=True, null=True)


class Email(models.Model):
    id = models.AutoField(primary_key=True)
    address = models.CharField(max_length=200, blank=True, null=True)
    password = models.CharField(max_length=200, blank=True, null=True)


class Employee(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=1000, null=True, blank=True)
    designation = models.CharField(max_length=1000, null=True, blank=True)
    # Secator UserAccount fields
    username = models.CharField(max_length=500, null=True, blank=True)
    site_name = models.CharField(max_length=500, null=True, blank=True)
    url = models.CharField(max_length=10000, null=True, blank=True)
    # Associations
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
    discovered_date = models.DateTimeField(null=True, blank=True)
    extra_data = models.JSONField(null=True, blank=True)
    # Email association
    emails = models.ManyToManyField(Email, related_name="employees", blank=True)

    def __str__(self):
        return self.username or self.name or str(self.id)


class Exploit(models.Model):
    """Model for storing exploit information from Secator."""

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=1000)
    exploit_id = models.CharField(max_length=200, null=True, blank=True)
    provider = models.CharField(max_length=200, null=True, blank=True)
    matched_at = models.CharField(max_length=10000, null=True, blank=True)
    reference = models.CharField(max_length=10000, null=True, blank=True)
    # Associations - primary link to IP as per Secator design
    ip_address = models.ForeignKey(IpAddress, on_delete=models.CASCADE, null=True, blank=True)
    # Optional links to subdomain/endpoint for additional context
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    # Additional data
    discovered_date = models.DateTimeField(null=True, blank=True)
    extra_data = models.JSONField(null=True, blank=True)
    # CVE associations
    cve_ids = models.ManyToManyField("CveId", related_name="exploit_cves", blank=True)
    # Tags
    tags = models.ManyToManyField("VulnerabilityTags", related_name="exploit_tags", blank=True)

    def __str__(self):
        return f"{self.name} ({self.exploit_id or 'N/A'})"

    class Meta:
        ordering = ["-discovered_date", "name"]


class Dork(models.Model):
    id = models.AutoField(primary_key=True)
    type = models.CharField(max_length=500, null=True, blank=True)
    url = models.CharField(max_length=10000, null=True, blank=True)


class S3Bucket(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=500, null=True, blank=True)
    region = models.CharField(max_length=500, null=True, blank=True)
    provider = models.CharField(max_length=100, null=True, blank=True)
    owner_id = models.CharField(max_length=250, null=True, blank=True)
    owner_display_name = models.CharField(max_length=250, null=True, blank=True)
    perm_auth_users_read = models.IntegerField(default=0)
    perm_auth_users_write = models.IntegerField(default=0)
    perm_auth_users_read_acl = models.IntegerField(default=0)
    perm_auth_users_write_acl = models.IntegerField(default=0)
    perm_auth_users_full_control = models.IntegerField(default=0)
    perm_all_users_read = models.IntegerField(default=0)
    perm_all_users_write = models.IntegerField(default=0)
    perm_all_users_read_acl = models.IntegerField(default=0)
    perm_all_users_write_acl = models.IntegerField(default=0)
    perm_all_users_full_control = models.IntegerField(default=0)
    num_objects = models.IntegerField(default=0)
    size = models.IntegerField(default=0)


class SecatorRunner(models.Model):
    """Model for storing Secator runner data from API hooks."""

    id = models.AutoField(primary_key=True)
    runner_type = models.CharField(max_length=50, help_text="Type of runner: workflow, scan, or task")
    runner_name = models.CharField(max_length=500, null=True, blank=True)
    workspace_name = models.CharField(
        max_length=500, null=True, blank=True, help_text="Secator workspace (e.g. project_slug/domain_name)"
    )
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
    worker = models.ForeignKey(
        "scanEngine.SecatorWorker",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="secatorrunner_set",
    )
    runner_data = models.JSONField(default=dict, help_text="Full runner data from Secator")
    celery_id = models.CharField(max_length=100, blank=True, null=True, help_text="Celery task ID for this runner")
    status = models.CharField(
        max_length=50, blank=True, null=True, help_text="Status from Secator (RUNNING, SUCCESS, FAILURE, REVOKED, etc.)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.runner_type} - {self.runner_name or 'N/A'} (ID: {self.id})"

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_history_id", "runner_type"]),
            models.Index(
                fields=["scan_history_id", "runner_type", "-created_at"],
                name="ss_runner_scan_type_created",
            ),
            models.Index(
                fields=["scan_history_id", "-created_at"],
                name="ss_runner_scan_created_cov",
                include=[
                    "id",
                    "runner_type",
                    "runner_name",
                    "workspace_name",
                    "domain_id",
                    "worker_id",
                    "celery_id",
                    "status",
                    "updated_at",
                ],
            ),
        ]


class Certificate(models.Model):
    """
    Model to store SSL/TLS certificates discovered by Secator.
    """

    id = models.AutoField(primary_key=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.ForeignKey(IpAddress, on_delete=models.CASCADE, null=True, blank=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)

    host = models.CharField(max_length=1000, help_text="Hostname for the certificate")
    fingerprint_sha256 = models.CharField(
        max_length=64, null=True, blank=True, help_text="SHA256 fingerprint of the certificate"
    )
    ip = models.CharField(max_length=100, null=True, blank=True, help_text="IP address where certificate was found")
    raw_value = models.TextField(null=True, blank=True, help_text="Raw certificate value")
    subject_cn = models.CharField(max_length=500, null=True, blank=True, help_text="Subject Common Name")
    subject_an = ArrayField(
        models.CharField(max_length=500), null=True, blank=True, help_text="Subject Alternative Names"
    )
    not_before = models.DateTimeField(null=True, blank=True, help_text="Certificate validity start date")
    not_after = models.DateTimeField(null=True, blank=True, help_text="Certificate validity end date")
    issuer_dn = models.CharField(max_length=1000, null=True, blank=True, help_text="Issuer Distinguished Name")
    issuer_cn = models.CharField(max_length=500, null=True, blank=True, help_text="Issuer Common Name")
    issuer = models.CharField(max_length=500, null=True, blank=True, help_text="Issuer name")
    self_signed = models.BooleanField(
        default=False, null=True, blank=True, help_text="Whether the certificate is self-signed"
    )
    trusted = models.BooleanField(default=False, null=True, blank=True, help_text="Whether the certificate is trusted")
    status = models.CharField(max_length=50, null=True, blank=True, help_text="Certificate status")
    keysize = models.IntegerField(null=True, blank=True, help_text="Certificate key size in bits")
    serial_number = models.CharField(max_length=200, null=True, blank=True, help_text="Certificate serial number")
    ciphers = ArrayField(models.CharField(max_length=200), null=True, blank=True, help_text="Supported ciphers")

    discovered_date = models.DateTimeField(auto_now_add=True, help_text="Date when certificate was discovered")

    class Meta:
        db_table = "certificate"
        ordering = ["-discovered_date"]
        unique_together = [["host", "fingerprint_sha256", "scan_history"]]

    def __str__(self):
        return f"{self.host} - {self.subject_cn or 'N/A'}"

    def is_expired(self):
        """Check if certificate is expired."""
        return self.not_after < timezone.now() if self.not_after else False

    def is_expired_soon(self, months=1):
        """Check if certificate expires soon."""
        if self.not_after:
            from datetime import timedelta

            return self.not_after < timezone.now() + timedelta(days=months * 30)
        return False


class ScanSchedule(models.Model):
    """
    Stores scheduled scan configuration for CRON-driven execution.

    Replaces django_celery_beat PeriodicTask for scan scheduling.
    Run the management command run_scheduled_scans (e.g. via CRON every minute).

    Note on validation:
    -------------------
    save() supports a ``validate`` kwarg (default: True) which controls whether
    full_clean() is called before persisting. Hot paths (e.g. the scheduler
    updating next_run/last_run_at) can pass validate=False to avoid validation
    overhead; creation and admin/form flows keep validation enabled by default.
    """

    SCHEDULE_MODE_PERIODIC = "periodic"
    SCHEDULE_MODE_CLOCKED = "clocked"
    SCHEDULE_MODE_CHOICES = [
        (SCHEDULE_MODE_PERIODIC, "Periodic"),
        (SCHEDULE_MODE_CLOCKED, "One-off (clocked)"),
    ]

    FREQUENCY_MINUTES = "minutes"
    FREQUENCY_HOURS = "hours"
    FREQUENCY_DAYS = "days"
    FREQUENCY_WEEKS = "weeks"
    FREQUENCY_MONTHS = "months"
    FREQUENCY_TYPE_CHOICES = [
        (FREQUENCY_MINUTES, "Minutes"),
        (FREQUENCY_HOURS, "Hours"),
        (FREQUENCY_DAYS, "Days"),
        (FREQUENCY_WEEKS, "Weeks"),
        (FREQUENCY_MONTHS, "Months"),
    ]

    name = models.CharField(max_length=255)
    target = models.ForeignKey("targetApp.Target", on_delete=models.CASCADE)
    scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE, null=True, blank=True)
    secator_kwargs = models.JSONField(null=True, blank=True)
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="scheduled_scans")
    imported_subdomains = ArrayField(models.CharField(max_length=255), blank=True, default=list)
    out_of_scope_subdomains = ArrayField(models.CharField(max_length=255), blank=True, default=list)

    schedule_mode = models.CharField(max_length=20, choices=SCHEDULE_MODE_CHOICES, default=SCHEDULE_MODE_PERIODIC)
    frequency_value = models.PositiveIntegerField(null=True, blank=True)
    frequency_type = models.CharField(max_length=20, choices=FREQUENCY_TYPE_CHOICES, null=True, blank=True)
    scheduled_time = models.DateTimeField(null=True, blank=True)

    next_run = models.DateTimeField(db_index=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    total_run_count = models.PositiveIntegerField(default=0)
    one_off = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "scan_schedule"
        ordering = ["next_run"]

    def clean(self):
        """Enforce required fields per schedule_mode and initiated_by for audit trail."""
        super().clean()
        if self.initiated_by_id is None:
            raise ValidationError({"initiated_by": "Scheduled scans require an initiated_by user for audit trail."})
        if self.schedule_mode == self.SCHEDULE_MODE_PERIODIC:
            if self.frequency_value is None or self.frequency_value < 1:
                raise ValidationError({"frequency_value": "Periodic schedules require a positive frequency value."})
            if not self.frequency_type or self.frequency_type not in {c[0] for c in self.FREQUENCY_TYPE_CHOICES}:
                raise ValidationError({"frequency_type": "Periodic schedules require a valid frequency type."})
        elif self.schedule_mode == self.SCHEDULE_MODE_CLOCKED:
            if self.scheduled_time is None:
                raise ValidationError({"scheduled_time": "One-time (clocked) schedules require a scheduled time."})

    def save(self, *args, **kwargs):
        """
        Persist the schedule.

        By default runs full_clean() before saving. Callers on hot paths (e.g.
        the scheduler loop) can pass validate=False to skip validation:

            schedule.save(validate=False)
        """
        if kwargs.pop("validate", True):
            self.full_clean()
        super().save(*args, **kwargs)

    def get_frequency_type_display_for_value(self) -> str:
        """Return frequency type label with correct singular/plural for current frequency_value."""
        display = self.get_frequency_type_display() or ""
        if self.frequency_value == 1 and display.endswith("s"):
            return display[:-1]
        return display

    @staticmethod
    def compute_next_run_from_frequency(from_time, value: int, frequency_type):
        """
        Compute next run datetime from a base time and frequency (value + type).
        Single place for frequency→next_run logic; used when creating schedules and when
        rescheduling after a periodic run.

        Note on FREQUENCY_MONTHS: months are implemented as fixed 30-day blocks
        (value * 30 days), not calendar months. This avoids a dependency on
        dateutil.relativedelta and keeps behavior simple; long-running schedules
        may drift relative to calendar month boundaries. For calendar-aligned
        monthly runs, use a one-off (clocked) schedule or external cron.
        """
        if frequency_type == ScanSchedule.FREQUENCY_MINUTES:
            return from_time + timedelta(minutes=value)
        if frequency_type == ScanSchedule.FREQUENCY_HOURS:
            return from_time + timedelta(hours=value)
        if frequency_type == ScanSchedule.FREQUENCY_DAYS:
            return from_time + timedelta(days=value)
        if frequency_type == ScanSchedule.FREQUENCY_WEEKS:
            return from_time + timedelta(weeks=value)
        if frequency_type == ScanSchedule.FREQUENCY_MONTHS:
            # Fixed 30-day blocks; see docstring for calendar-month caveat.
            return from_time + timedelta(days=value * 30)
        return from_time + timedelta(days=1)

    @staticmethod
    def compute_initial_next_run(
        schedule_mode: str,
        from_time=None,
        *,
        frequency_value: int | None = None,
        frequency_type: str | None = None,
        scheduled_time=None,
    ):
        """
        Return the initial next_run for a new schedule. Use when creating schedules
        outside the UI (e.g. shell, fixtures) to avoid missing or inconsistent next_run.

        For periodic mode, pass frequency_value and frequency_type; for clocked mode,
        pass scheduled_time. from_time defaults to timezone.now().
        """
        now = from_time if from_time is not None else timezone.now()
        if schedule_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC and frequency_value and frequency_type:
            return ScanSchedule.compute_next_run_from_frequency(now, frequency_value, frequency_type)
        if schedule_mode == ScanSchedule.SCHEDULE_MODE_CLOCKED and scheduled_time is not None:
            return scheduled_time
        return now + timedelta(days=1)

    def __str__(self):
        return self.name
