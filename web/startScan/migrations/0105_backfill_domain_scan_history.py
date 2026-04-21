# Dev notes: Backfill Domain.scan_history_id from Subdomain.
# - Before: startScan_domain has nullable scan_history_id (added in 0104). Many rows still NULL.
#   A legacy unique constraint on name alone (targetApp_domain_name_key or startScan_domain_name_key)
#   may still exist, preventing updates on rows with duplicate names across scans.
# - This migration first drops that legacy constraint (needed before backfill because existing data
#   may contain duplicate domain names from different scans). Then for each domain, sets
#   scan_history_id from its subdomains: most recent scan (MAX) as deterministic tie-break.
# - Batched by domain id range to reduce lock duration on large tables.
# - Irreversible: reverse is noop; do not rely on unapply. After this, 0106 can safely drop project_id/target_id from Domain.

import logging

from django.db import migrations


BATCH_SIZE = 500

logger = logging.getLogger("rengine.migrations")


def backfill_scan_history_id(apps, schema_editor):
    """
    Drop the legacy unique constraint on Domain.name alone, then set domain.scan_history_id
    from subdomains.

    - Single-scan domains: scan_history_id is set from the unique linked scan.
    - Multi-scan domains (subdomains reference more than one scan): we apply a deterministic
      tie-break by assigning the most recent scan (MAX(scan_history_id)) so no domain is
      left in an ambiguous state. A warning is logged with the count of such domains.
    - Domains with no subdomains or only subdomains with NULL scan_history_id are left
      NULL and a warning is logged with their count.
    """
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute('ALTER TABLE "startScan_domain" DROP CONSTRAINT IF EXISTS "targetApp_domain_name_key"')
        cursor.execute('ALTER TABLE "startScan_domain" DROP CONSTRAINT IF EXISTS "startScan_domain_name_key"')
        cursor.execute('DROP INDEX IF EXISTS "targetApp_domain_name_24bceeb1_like"')

        cursor.execute(
            """
            SELECT MIN(id), MAX(id) FROM "startScan_domain" WHERE scan_history_id IS NULL
            """
        )
        if not (row := cursor.fetchone()) or row[0] is None:
            return
        min_id, max_id = row[0], row[1]

        current = min_id
        while current is not None and current <= max_id:
            batch_end = current + BATCH_SIZE - 1
            cursor.execute(
                """
                UPDATE "startScan_domain" d
                SET scan_history_id = (
                    SELECT MAX(ss.scan_history_id)
                    FROM "startScan_subdomain" ss
                    WHERE ss.target_domain_id = d.id
                      AND ss.scan_history_id IS NOT NULL
                )
                WHERE d.scan_history_id IS NULL
                  AND d.id BETWEEN %s AND %s
                  AND EXISTS (
                      SELECT 1 FROM "startScan_subdomain" ss2
                      WHERE ss2.target_domain_id = d.id AND ss2.scan_history_id IS NOT NULL
                  )
                """,
                [current, batch_end],
            )
            current = batch_end + 1

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM "startScan_domain" d
            WHERE d.scan_history_id IS NOT NULL
              AND (
                  SELECT COUNT(DISTINCT ss.scan_history_id)
                  FROM "startScan_subdomain" ss
                  WHERE ss.target_domain_id = d.id AND ss.scan_history_id IS NOT NULL
              ) > 1
            """
        )
        if multi_scan_count := cursor.fetchone()[0]:
            logger.warning(
                "[0105] %s domain(s) had subdomains from multiple scans; "
                "assigned to the most recent scan (MAX scan_history_id) as tie-break.",
                multi_scan_count,
            )

        cursor.execute(
            """
            SELECT COUNT(*) FROM "startScan_domain" d
            WHERE d.scan_history_id IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM "startScan_subdomain" ss
                  WHERE ss.target_domain_id = d.id AND ss.scan_history_id IS NOT NULL
              )
            """
        )
        if left_null_count := cursor.fetchone()[0]:
            logger.warning(
                "[0105] %s domain(s) left with scan_history_id NULL (no subdomains or "
                "subdomains have NULL scan_history_id); cannot infer scan.",
                left_null_count,
            )


def noop_reverse(apps, schema_editor):
    """Cannot reliably reverse backfill; leave scan_history_id as is."""
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0104_domain_add_scan_history_fk"),
    ]

    operations = [
        migrations.RunPython(backfill_scan_history_id, noop_reverse),
    ]
