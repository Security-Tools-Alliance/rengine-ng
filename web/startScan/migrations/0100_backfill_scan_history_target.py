# Data migration: set ScanHistory.target_id from ScanHistory.domain.target_id

from django.db import migrations


def backfill_scan_history_target(apps, schema_editor):
    ScanHistory = apps.get_model("startScan", "ScanHistory")
    for scan in ScanHistory.objects.select_related("domain").all():
        if scan.domain_id and getattr(scan.domain, "target_id", None):
            scan.target_id = scan.domain.target_id
            scan.save(update_fields=["target_id"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0102_alter_metafinderdocument_target_domain_fk"),
    ]

    operations = [
        migrations.RunPython(backfill_scan_history_target, noop_reverse),
    ]
