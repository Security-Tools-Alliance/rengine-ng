"""
Data migration: rename scan_config key 'request_headers' to 'header' in all models
that carry a scan_config JSONField (Organization, Scope, Target, ScanHistory).
"""

from django.db import migrations


def rename_key_forward(apps, schema_editor):
    models_to_migrate = [
        ("targetApp", "Organization"),
        ("targetApp", "Scope"),
        ("targetApp", "Target"),
        ("startScan", "ScanHistory"),
    ]
    for app_label, model_name in models_to_migrate:
        Model = apps.get_model(app_label, model_name)
        for obj in Model.objects.filter(scan_config__has_key="request_headers"):
            obj.scan_config["header"] = obj.scan_config.pop("request_headers")
            obj.save(update_fields=["scan_config"])


def rename_key_backward(apps, schema_editor):
    models_to_migrate = [
        ("targetApp", "Organization"),
        ("targetApp", "Scope"),
        ("targetApp", "Target"),
        ("startScan", "ScanHistory"),
    ]
    for app_label, model_name in models_to_migrate:
        Model = apps.get_model(app_label, model_name)
        for obj in Model.objects.filter(scan_config__has_key="header"):
            obj.scan_config["request_headers"] = obj.scan_config.pop("header")
            obj.save(update_fields=["scan_config"])


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0057_alter_target_scan_config"),
    ]

    operations = [
        migrations.RunPython(rename_key_forward, rename_key_backward),
    ]
