"""Add scan_config JSONField to ScanHistory to persist effective parameters."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0112_scanschedule_remove_domain_require_target"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanhistory",
            name="scan_config",
            field=models.JSONField(
                blank=True,
                help_text="Effective scan parameters and profiles used for this scan",
                null=True,
            ),
        ),
    ]
