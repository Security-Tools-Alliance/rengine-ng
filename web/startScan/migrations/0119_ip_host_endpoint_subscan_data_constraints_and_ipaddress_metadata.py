"""
Squashed migration (replaces 0119–0122):

- Endpoint.ip_address and SubScan.ip_address FKs
- Data migration: IP-labeled subdomains → IpAddress, endpoint/subscan host fixes
- Check constraints on Endpoint and SubScan hosts
- IpAddress.is_important and IpAddress.attack_surface

Data steps run sequentially in forwards_migrate_ip_host_data (atomic=False on the migration).
Malformed IP strings that pass the literal check but fail normalization are skipped with a
warning log line to ease post-deploy debugging.

Operational note: with atomic=False, steps already applied stay committed if a later step fails;
use logger ``startScan.migration.0119_ip_host`` (preflight row counts and per-step markers) to
assess progress on large databases. Data migration logic lives in
``startScan.services.ip_host_migration`` so future schema tweaks avoid editing large RunPython blocks.
"""

from django.db import migrations, models
from django.db.models import Q
import django.db.models.deletion

from startScan.services.ip_host_migration import (
    backwards_migrate_ip_host_data,
    forwards_migrate_ip_host_data,
)


class Migration(migrations.Migration):
    # Each operation runs in its own transaction so ALTER on IpAddress does not follow
    # RunPython/FK work in one transaction (PostgreSQL: pending trigger events on table).
    atomic = False

    dependencies = [
        ("startScan", "0118_remove_domain_start_scan_date"),
    ]

    operations = [
        migrations.AddField(
            model_name="endpoint",
            name="ip_address",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="ip_endpoints",
                to="startScan.ipaddress",
            ),
        ),
        migrations.AddField(
            model_name="subscan",
            name="ip_address",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="subscans",
                to="startScan.ipaddress",
            ),
        ),
        migrations.RunPython(forwards_migrate_ip_host_data, backwards_migrate_ip_host_data),
        migrations.AddConstraint(
            model_name="endpoint",
            constraint=models.CheckConstraint(
                condition=Q(subdomain__isnull=False, ip_address__isnull=True)
                | Q(subdomain__isnull=True, ip_address__isnull=False),
                name="endpoint_exactly_one_host",
            ),
        ),
        migrations.AddConstraint(
            model_name="subscan",
            constraint=models.CheckConstraint(
                condition=~Q(subdomain__isnull=False, ip_address__isnull=False),
                name="subscan_subdomain_ip_xor",
            ),
        ),
        migrations.AddField(
            model_name="ipaddress",
            name="is_important",
            field=models.BooleanField(blank=True, default=False, null=True),
        ),
        migrations.AddField(
            model_name="ipaddress",
            name="attack_surface",
            field=models.TextField(blank=True, null=True),
        ),
    ]
