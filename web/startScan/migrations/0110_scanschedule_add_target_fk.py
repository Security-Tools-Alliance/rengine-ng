# Dev notes: Add target FK to ScanSchedule.
# - Before: ScanSchedule.domain (FK to Domain) is the scan entry point.
# - This migration: adds nullable target FK. Next: 0111 backfills target from domain, 0112 drops domain.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0109_domain_unique_scan_history_name"),
        ("targetApp", "0051_move_domain_tables_to_startscan"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanschedule",
            name="target",
            field=models.ForeignKey(
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="targetApp.target",
            ),
        ),
    ]
