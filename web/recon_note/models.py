from django.db import models

from dashboard.models import Project
from startScan.models import IpAddress, ScanHistory, Subdomain


class TodoNote(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=1000, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, null=True, blank=True, related_name="recon_notes"
    )
    is_done = models.BooleanField(default=False)
    is_important = models.BooleanField(default=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)

    class Meta:
        indexes = [
            models.Index(fields=["subdomain_id", "is_done"], name="recon_todonote_sub_done_idx"),
        ]
