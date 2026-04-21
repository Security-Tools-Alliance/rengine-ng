"""Add Secret model for Secator secret findings (gitleaks, trufflehog, trivy)."""

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0114_ipaddress_extra_data"),
    ]

    operations = [
        migrations.CreateModel(
            name="Secret",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("rule_name", models.CharField(max_length=500)),
                ("matched_at", models.CharField(max_length=2000)),
                ("source", models.CharField(blank=True, max_length=100, null=True)),
                ("value", models.TextField()),
                ("extra_data", models.JSONField(blank=True, null=True)),
                ("discovered_date", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "scan_history",
                    models.ForeignKey(on_delete=models.CASCADE, to="startScan.scanhistory"),
                ),
            ],
            options={},
        ),
        migrations.AddIndex(
            model_name="secret",
            index=models.Index(fields=["scan_history_id"], name="ss_secret_scan_idx"),
        ),
    ]
