# Dev notes: Remove project_id and target_id from Domain.
# - Before: startScan_domain has project_id, target_id, scan_history_id (backfilled in 0105).
# - This migration: drops columns project_id and target_id. Domain is linked to scan only via scan_history_id.
# - Upgrade path: run after 0105. Later 0109 changes Domain uniqueness to (scan_history_id, name).

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0105_backfill_domain_scan_history"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=(
                        'ALTER TABLE "startScan_domain" '
                        'DROP COLUMN IF EXISTS "project_id", '
                        'DROP COLUMN IF EXISTS "target_id"'
                    ),
                    reverse_sql=(
                        'ALTER TABLE "startScan_domain" '
                        'ADD COLUMN IF NOT EXISTS "project_id" integer NULL REFERENCES "dashboard_project"("id") ON DELETE CASCADE; '
                        'ALTER TABLE "startScan_domain" '
                        'ADD COLUMN IF NOT EXISTS "target_id" integer NULL REFERENCES "targetApp_target"("id") ON DELETE SET NULL'
                    ),
                ),
            ],
            state_operations=[
                migrations.RemoveField(
                    model_name="domain",
                    name="project",
                ),
                migrations.RemoveField(
                    model_name="domain",
                    name="target",
                ),
            ],
        ),
    ]
