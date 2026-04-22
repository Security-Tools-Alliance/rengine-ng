# Dev notes: Backfill ScanSchedule.target_id from Domain.scan_history.target_id.
# - Before: ScanSchedule has domain FK and nullable target FK (added in 0110).
# - This migration: sets target_id by traversing domain -> scan_history -> target.
# - Schedules whose domain has no scan_history or no target are logged and deleted.
# - After this, 0112 drops the domain FK and makes target NOT NULL.

import logging

from django.db import migrations


logger = logging.getLogger("rengine.migrations")


def backfill_target(apps, schema_editor):
    """Set ScanSchedule.target_id from domain.scan_history.target."""
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE "scan_schedule" ss
            SET target_id = sh.target_id
            FROM "startScan_domain" d
            JOIN "startScan_scanhistory" sh ON sh.id = d.scan_history_id
            WHERE ss.domain_id = d.id
              AND ss.target_id IS NULL
              AND sh.target_id IS NOT NULL
            """
        )
        updated = cursor.rowcount
        if updated:
            logger.info("[0111] Backfilled target_id for %s schedule(s).", updated)

        cursor.execute('SELECT COUNT(*) FROM "scan_schedule" WHERE target_id IS NULL')
        orphan_count = cursor.fetchone()[0]
        if orphan_count:
            logger.warning(
                "[0111] Deleting %s schedule(s) with no resolvable target (domain has no scan_history or target).",
                orphan_count,
            )
            cursor.execute('DELETE FROM "scan_schedule" WHERE target_id IS NULL')


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0110_scanschedule_add_target_fk"),
    ]

    operations = [
        migrations.RunPython(backfill_target, noop_reverse),
    ]
