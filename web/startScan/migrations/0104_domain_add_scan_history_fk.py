# Dev notes: Add scan_history_id to Domain.
# - Before: startScan_domain has no scan_history_id; Domain was linked via project/target (removed in 0106).
# - This migration: adds nullable column scan_history_id (FK to startScan_scanhistory) via RunSQL. State updated accordingly.
# - Upgrade path: after 0101 (state only). Next: 0105 backfills scan_history_id from Subdomain; 0106 then drops project_id/target_id.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0102_alter_metafinderdocument_target_domain_fk"),
        ("startScan", "0103_remove_scanhistory_domain"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=(
                        'ALTER TABLE "startScan_domain" '
                        'ADD COLUMN IF NOT EXISTS "scan_history_id" integer NULL '
                        'REFERENCES "startScan_scanhistory"("id") ON DELETE CASCADE'
                    ),
                    reverse_sql='ALTER TABLE "startScan_domain" DROP COLUMN IF EXISTS "scan_history_id"',
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name="domain",
                    name="scan_history",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="discovered_domains",
                        to="startScan.scanhistory",
                    ),
                ),
            ],
        ),
    ]
