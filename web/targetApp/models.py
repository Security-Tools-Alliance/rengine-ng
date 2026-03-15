from django.db import models

from dashboard.models import Project
from reNgine.utilities.logger import get_module_logger
from targetApp.constants import SCOPE_TYPE_CHOICES, TARGET_TYPE_CHOICES


_scope_logger = get_module_logger(__name__)


class TargetQuerySet(models.QuerySet):
    """QuerySet with project-scoped filtering."""

    def for_project(self, project_or_slug):
        """Return targets for the given project (Project instance or slug string)."""
        if hasattr(project_or_slug, "pk"):
            return self.filter(project=project_or_slug)
        return self.filter(project__slug=project_or_slug)


class TargetManager(models.Manager):
    """Manager that uses TargetQuerySet and exposes for_project."""

    def get_queryset(self):
        return TargetQuerySet(self.model, using=self._db)

    def for_project(self, project_or_slug):
        return self.get_queryset().for_project(project_or_slug)


class Target(models.Model):
    """
    Entity representing a scannable target (domain, IP, URL, email, etc.).
    Project is linked exclusively to Target; Domain lives in startScan and optionally belongs to a Target.
    """

    id = models.AutoField(primary_key=True)
    value = models.CharField(max_length=2000)
    target_type = models.CharField(max_length=50, choices=TARGET_TYPE_CHOICES)
    port = models.CharField(max_length=20, blank=True, null=True)
    custom_dns_servers = models.CharField(max_length=500, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    h1_team_handle = models.CharField(max_length=100, blank=True, null=True)
    insert_date = models.DateTimeField(null=True)
    start_scan_date = models.DateTimeField(null=True, blank=True)
    scan_config = models.JSONField(
        null=True,
        blank=True,
        help_text="Per-target scan parameter overrides and profiles",
    )
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

    objects = TargetManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["project_id", "value", "target_type"],
                name="targetApp_target_project_value_type_uniq",
            )
        ]
        ordering = ["-insert_date"]

    def __str__(self):
        return f"{self.value} ({self.target_type})"

    def get_organization(self):
        return self.organizations.all()


class OrganizationQuerySet(models.QuerySet):
    """QuerySet with project-scoped filtering."""

    def for_project(self, project_or_slug):
        """Return organizations for the given project (Project instance or slug string)."""
        if hasattr(project_or_slug, "pk"):
            return self.filter(project=project_or_slug)
        return self.filter(project__slug=project_or_slug)


class OrganizationManager(models.Manager):
    """Manager that uses OrganizationQuerySet and exposes for_project."""

    def get_queryset(self):
        return OrganizationQuerySet(self.model, using=self._db)

    def for_project(self, project_or_slug):
        return self.get_queryset().for_project(project_or_slug)


class Organization(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300, unique=True)
    description = models.TextField(blank=True, null=True)
    insert_date = models.DateTimeField()
    scan_config = models.JSONField(
        null=True,
        blank=True,
        help_text="Organization-level scan parameter defaults and profiles",
    )
    targets = models.ManyToManyField("Target", related_name="organizations", blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

    objects = OrganizationManager()

    def __str__(self):
        return self.name

    def get_domains(self):
        from startScan.models import Domain

        return Domain.objects.filter(scan_history__target__organizations=self)

    def get_targets(self):
        return self.targets.all()


class Scope(models.Model):
    """
    Groups targets under an organization with shared scan parameters.
    Represents a bug bounty program, an engagement (internal/external/OSINT/red team), etc.

    scan_config is a JSON object with the same structure as Organization.scan_config
    and Target.scan_config: keys from PARAM_KEYS + "profiles" + "extra_config".
    Only present keys act as overrides for this scope.
    """

    id = models.AutoField(primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scopes")
    name = models.CharField(max_length=300)
    scope_type = models.CharField(max_length=30, choices=SCOPE_TYPE_CHOICES)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    scan_config = models.JSONField(
        null=True,
        blank=True,
        help_text="Scope-level scan parameter defaults and profiles",
    )

    targets = models.ManyToManyField("Target", related_name="scopes", blank=True)
    workers = models.ManyToManyField(
        "scanEngine.SecatorWorker",
        related_name="scopes",
        blank=True,
    )
    allow_local_worker = models.BooleanField(
        default=True,
        help_text="If True, Local (this server) is in the allowed workers list for this scope.",
    )
    default_worker = models.ForeignKey(
        "scanEngine.SecatorWorker",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scopes_as_default",
        help_text="Default worker when the scope has 2+ allowed workers; null means Local.",
    )
    restrict_findings_to_target = models.BooleanField(
        default=False,
        help_text="If True, only findings whose domain/host is the target or in the allowed list are created.",
    )
    allowed_finding_domains = models.JSONField(
        default=list,
        blank=True,
        help_text="List of domain names (e.g. ['easi-services.fr']) allowed in addition to the target when restrict_findings_to_target is True.",
    )
    allowed_finding_hosts = models.JSONField(
        default=list,
        blank=True,
        help_text="When restrict_findings_to_target is True and this list is non-empty, only these hostnames and IPs are accepted for Subdomain/Domain creation.",
    )
    insert_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="targetapp_scope_org_name_uniq",
            )
        ]
        ordering = ["-insert_date"]

    def __str__(self):
        return f"{self.name} ({self.get_scope_type_display()})"

    def save(self, *args, **kwargs):
        from reNgine.utilities.domain import normalize_allowed_hosts_from_list

        if isinstance(self.allowed_finding_hosts, list):
            self.allowed_finding_hosts = normalize_allowed_hosts_from_list(self.allowed_finding_hosts)
        elif isinstance(self.allowed_finding_hosts, str) and self.allowed_finding_hosts.strip():
            parts = []
            for line in self.allowed_finding_hosts.splitlines():
                parts.extend(line.split(","))
            items = [p.strip() for p in parts if p.strip()]
            self.allowed_finding_hosts = normalize_allowed_hosts_from_list(items)
        else:
            if self.allowed_finding_hosts is not None and not isinstance(self.allowed_finding_hosts, list):
                _scope_logger.log_line(
                    "[SCOPE]",
                    "SAVE",
                    "Scope.allowed_finding_hosts was not a list or string (type=%s), reset to []"
                    % (type(self.allowed_finding_hosts).__name__,),
                    level="warning",
                )
            self.allowed_finding_hosts = []
        super().save(*args, **kwargs)
