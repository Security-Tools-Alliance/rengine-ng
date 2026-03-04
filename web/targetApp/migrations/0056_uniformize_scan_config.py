"""
Uniformize scan_config as a single JSONField on Organization, Scope, and Target.

- Organization: add scan_config
- Scope: add scan_config, consolidate 12 individual fields, remove them
- Target: merge request_headers into scan_config_override, rename to scan_config
"""

import logging

from django.db import migrations, models, transaction


logger = logging.getLogger(__name__)


def consolidate_scope_fields(apps, schema_editor):
    """Move Scope individual fields into Scope.scan_config JSONField."""
    Scope = apps.get_model("targetApp", "Scope")
    individual_fields = [
        "threads",
        "rate_limit",
        "timeout",
        "retries",
        "delay",
        "proxy",
        "user_agent",
        "follow_redirect",
        "depth",
    ]

    with transaction.atomic():
        for scope in Scope.objects.iterator(chunk_size=1000):
            config = {}
            for field in individual_fields:
                val = getattr(scope, field, None)
                if val is not None:
                    config[field] = val
            if getattr(scope, "request_headers", None):
                config["request_headers"] = scope.request_headers
            if getattr(scope, "default_profiles", None):
                config["profiles"] = scope.default_profiles
            if getattr(scope, "extra_config", None):
                config["extra_config"] = scope.extra_config
            scope.scan_config = config or None
            scope.save(update_fields=["scan_config"])


def merge_target_request_headers(apps, schema_editor):
    """Merge Target.request_headers into Target.scan_config_override['request_headers']."""
    Target = apps.get_model("targetApp", "Target")
    queryset = Target.objects.exclude(request_headers__isnull=True).exclude(request_headers={})
    for target in queryset.iterator(chunk_size=1000):
        config = target.scan_config_override or {}
        if "request_headers" not in config:
            config["request_headers"] = target.request_headers
            target.scan_config_override = config
            target.save(update_fields=["scan_config_override"])
        elif config.get("request_headers") != target.request_headers:
            logger.warning(
                "Target id=%s: scan_config_override.request_headers already set, legacy request_headers discarded.",
                target.pk,
            )


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0055_alter_scope_request_headers_and_more"),
    ]

    operations = [
        # Step 1: Add new scan_config fields
        migrations.AddField(
            model_name="organization",
            name="scan_config",
            field=models.JSONField(
                blank=True,
                help_text="Organization-level scan parameter defaults and profiles",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="scope",
            name="scan_config",
            field=models.JSONField(
                blank=True,
                help_text="Scope-level scan parameter defaults and profiles",
                null=True,
            ),
        ),
        # Step 2: Data migrations
        migrations.RunPython(
            consolidate_scope_fields,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunPython(
            merge_target_request_headers,
            reverse_code=migrations.RunPython.noop,
        ),
        # Step 3: Rename Target.scan_config_override -> scan_config
        migrations.RenameField(
            model_name="target",
            old_name="scan_config_override",
            new_name="scan_config",
        ),
        # Step 4: Remove Target.request_headers
        migrations.RemoveField(
            model_name="target",
            name="request_headers",
        ),
        # Step 5: Remove Scope individual fields
        migrations.RemoveField(model_name="scope", name="threads"),
        migrations.RemoveField(model_name="scope", name="rate_limit"),
        migrations.RemoveField(model_name="scope", name="timeout"),
        migrations.RemoveField(model_name="scope", name="retries"),
        migrations.RemoveField(model_name="scope", name="delay"),
        migrations.RemoveField(model_name="scope", name="proxy"),
        migrations.RemoveField(model_name="scope", name="user_agent"),
        migrations.RemoveField(model_name="scope", name="request_headers"),
        migrations.RemoveField(model_name="scope", name="follow_redirect"),
        migrations.RemoveField(model_name="scope", name="depth"),
        migrations.RemoveField(model_name="scope", name="default_profiles"),
        migrations.RemoveField(model_name="scope", name="extra_config"),
    ]
