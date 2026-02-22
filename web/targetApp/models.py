from django.db import models

from dashboard.models import Project
from targetApp.constants import SCOPE_TYPE_CHOICES, TARGET_TYPE_CHOICES
from targetApp.services.scan_param_definitions import REQUEST_HEADERS_HELP_TEXT


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
    request_headers = models.JSONField(null=True, blank=True, help_text=REQUEST_HEADERS_HELP_TEXT)
    scan_config_override = models.JSONField(
        null=True,
        blank=True,
        help_text="Per-target scan parameter overrides (threads, rate_limit, timeout, etc.)",
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

    default_profiles is stored as a JSON object mapping category (speed, evasion,
    general, network) to profile name; see scope_params._profiles_to_list.
    """

    id = models.AutoField(primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scopes")
    name = models.CharField(max_length=300)
    scope_type = models.CharField(max_length=30, choices=SCOPE_TYPE_CHOICES)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True, null=True)

    # Secator meta-option fields (all nullable: only set values act as defaults)
    threads = models.PositiveIntegerField(null=True, blank=True)
    rate_limit = models.PositiveIntegerField(null=True, blank=True, help_text="Requests per second")
    timeout = models.PositiveIntegerField(null=True, blank=True, help_text="HTTP timeout in seconds")
    retries = models.PositiveIntegerField(null=True, blank=True)
    delay = models.FloatField(null=True, blank=True, help_text="Delay between requests in seconds")
    proxy = models.CharField(max_length=500, blank=True, null=True)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    request_headers = models.JSONField(null=True, blank=True, help_text=REQUEST_HEADERS_HELP_TEXT)
    follow_redirect = models.BooleanField(null=True, blank=True)
    depth = models.PositiveIntegerField(null=True, blank=True)
    default_profiles = models.JSONField(
        null=True,
        blank=True,
        help_text="JSON object mapping category (speed, evasion, general, network) to profile name",
    )
    extra_config = models.JSONField(
        null=True,
        blank=True,
        help_text="Advanced options (method, data, wordlist, ports, match/filter regex, etc.)",
    )

    targets = models.ManyToManyField("Target", related_name="scopes", blank=True)
    workers = models.ManyToManyField(
        "scanEngine.SecatorWorker",
        related_name="scopes",
        blank=True,
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
