# Dev notes: Finalize ScanSchedule migration from domain to target.
# - Before: ScanSchedule has both domain FK and target FK (backfilled in 0111).
# - This migration: drops domain FK, makes target NOT NULL.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0111_backfill_scanschedule_target"),
        ("targetApp", "0051_move_domain_tables_to_startscan"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="scanschedule",
            name="domain",
        ),
        migrations.AlterField(
            model_name="scanschedule",
            name="target",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to="targetApp.target",
            ),
        ),
    ]
