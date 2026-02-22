from django.db import models

from dashboard.models import Project
from targetApp.constants import TARGET_TYPE_CHOICES


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
    request_headers = models.JSONField(null=True, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

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


class Organization(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300, unique=True)
    description = models.TextField(blank=True, null=True)
    insert_date = models.DateTimeField()
    targets = models.ManyToManyField("Target", related_name="organizations", blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

    def __str__(self):
        return self.name

    def get_domains(self):
        from startScan.models import Domain

        return Domain.objects.filter(scan_history__target__organizations=self)

    def get_targets(self):
        return self.targets.all()
