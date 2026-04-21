# Remove ScanHistory.domain; use target_id + get_first_domain_for_target() for domain context.

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0100_backfill_scan_history_target"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="scanhistory",
            name="domain",
        ),
    ]
