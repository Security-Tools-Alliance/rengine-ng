from django.db import migrations, models


def _add_scan_name_unique_constraint_if_missing(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_class
                    WHERE relkind = 'i'
                      AND relname = 'ss_technology_scan_name_uniq'
                ) THEN
                    CREATE UNIQUE INDEX "ss_technology_scan_name_uniq"
                    ON "startScan_technology" ("scan_history_id", "name")
                    WHERE ("scan_history_id" IS NOT NULL AND "name" IS NOT NULL);
                END IF;
            END $$;
            """
        )


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0132_technology_scan_scope"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(_add_scan_name_unique_constraint_if_missing, migrations.RunPython.noop),
            ],
            state_operations=[
                migrations.AddConstraint(
                    model_name="technology",
                    constraint=models.UniqueConstraint(
                        condition=models.Q(name__isnull=False, scan_history__isnull=False),
                        fields=("scan_history", "name"),
                        name="ss_technology_scan_name_uniq",
                    ),
                ),
            ],
        ),
    ]
