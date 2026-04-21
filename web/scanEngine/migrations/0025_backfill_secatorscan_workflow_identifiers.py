# Data migration: backfill workflow_identifiers for existing SecatorScan records

from django.db import migrations
import yaml


def backfill_workflow_identifiers(apps, schema_editor):
    SecatorScan = apps.get_model("scanEngine", "SecatorScan")

    for scan in SecatorScan.objects.all():
        if not scan.yaml_configuration:
            scan.workflow_identifiers = []
            scan.save(update_fields=["workflow_identifiers"])
            continue
        try:
            config = yaml.safe_load(scan.yaml_configuration)
            workflows = config.get("workflows", {}) if isinstance(config, dict) else {}
            scan.workflow_identifiers = list(workflows.keys())
        except Exception:
            scan.workflow_identifiers = []
        scan.save(update_fields=["workflow_identifiers"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("scanEngine", "0024_secatorscan_workflow_identifiers"),
    ]

    operations = [
        migrations.RunPython(backfill_workflow_identifiers, noop),
    ]
