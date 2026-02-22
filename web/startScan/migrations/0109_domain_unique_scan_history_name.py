# Dev notes: Domain uniqueness by (scan_history_id, name).
# - The legacy unique constraint on name alone and the like index are already dropped by 0105
#   (before the backfill, to allow duplicate names across scans). The DROP IF EXISTS statements
#   here are kept for idempotency in case 0105 was applied before that fix.
# - This migration: creates the composite unique index on (scan_history_id, name).
# - State: Meta.unique_together = [("scan_history", "name")].

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0108_remove_vulnerability_ss_vuln_target_name_idx_and_more"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=(
                        'ALTER TABLE "startScan_domain" DROP CONSTRAINT IF EXISTS "targetApp_domain_name_key";'
                        ' ALTER TABLE "startScan_domain" DROP CONSTRAINT IF EXISTS "startScan_domain_name_key";'
                        ' DROP INDEX IF EXISTS "targetApp_domain_name_24bceeb1_like";'
                        ' CREATE UNIQUE INDEX IF NOT EXISTS "startScan_domain_scan_history_id_name_uniq"'
                        ' ON "startScan_domain" ("scan_history_id", "name");'
                    ),
                    reverse_sql=(
                        'DROP INDEX IF EXISTS "startScan_domain_scan_history_id_name_uniq";'
                        ' ALTER TABLE "startScan_domain" ADD CONSTRAINT "targetApp_domain_name_key"'
                        ' UNIQUE ("name");'
                    ),
                ),
            ],
            state_operations=[
                migrations.AlterField(
                    model_name="domain",
                    name="name",
                    field=models.CharField(max_length=300),
                ),
                migrations.AlterUniqueTogether(
                    name="domain",
                    unique_together={("scan_history", "name")},
                ),
            ],
        ),
    ]
