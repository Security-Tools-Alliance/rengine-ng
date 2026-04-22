# Dev notes: Backfill Target from Domain and Organization.targets.
# - Before: Target exists (0049); Domain has nullable target_id; Organization has M2M targets (empty).
# - This migration: for each (project_id, name) creates one Target; sets domain.target_id; links org.targets from domains.
# - Irreversible (reverse is noop). Run before 0051 (table renames). After 0051, startScan 0101 adds domain state in startScan.

from django.db import migrations, transaction
from django.db.utils import IntegrityError

from reNgine.core.validators import is_valid_ip


def create_targets_and_backfill_domain(apps, schema_editor):
    Domain = apps.get_model("targetApp", "Domain")
    Target = apps.get_model("targetApp", "Target")

    # Group by (project_id, name) so one Target per logical domain.
    # Use (project_id, name) to deduplicate; only first domain per key gets Target created.
    # Legacy system only treated IP and hostname: detect via validators.
    seen = {}
    for domain in Domain.objects.all().order_by("id"):
        key = (domain.project_id, domain.name)
        if key not in seen:
            target_type = "ip" if is_valid_ip(domain.name) else "host"
            target, _ = Target.objects.get_or_create(
                project_id=domain.project_id,
                value=domain.name,
                target_type=target_type,
                defaults={
                    "description": domain.description,
                    "h1_team_handle": domain.h1_team_handle,
                    "insert_date": domain.insert_date,
                    "start_scan_date": domain.start_scan_date,
                    "custom_dns_servers": domain.custom_dns_servers,
                    "request_headers": domain.request_headers,
                },
            )
            seen[key] = target.id
        try:
            with transaction.atomic():
                Domain.objects.filter(pk=domain.pk).update(target_id=seen[key])
        except IntegrityError:
            # Duplicate domain names: skip this row.
            pass


def backfill_organization_targets(apps, schema_editor):
    Organization = apps.get_model("targetApp", "Organization")
    Domain = apps.get_model("targetApp", "Domain")

    for org in Organization.objects.prefetch_related("domains").all():
        target_ids = set(
            Domain.objects.filter(domains=org).exclude(target_id__isnull=True).values_list("target_id", flat=True)
        )
        if target_ids:
            org.targets.add(*target_ids)


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0049_add_target_and_domain_target_fk"),
    ]

    operations = [
        migrations.RunPython(create_targets_and_backfill_domain, noop_reverse),
        migrations.RunPython(backfill_organization_targets, noop_reverse),
    ]
