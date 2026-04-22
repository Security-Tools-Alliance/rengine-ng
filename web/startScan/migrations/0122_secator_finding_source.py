from django.db import migrations, models


def copy_subdomain_technology_links(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO "startScan_subdomaintechnology" ("subdomain_id", "technology_id", "source")
            SELECT st."subdomain_id", st."technology_id", NULL
            FROM "startScan_subdomain_technologies" AS st
            ON CONFLICT ("subdomain_id", "technology_id") DO NOTHING
            """
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0121_port_extra_data_non_null_default_dict"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql=(
                        'ALTER TABLE "startScan_domaininfo" ADD COLUMN IF NOT EXISTS "source" varchar(200) NULL;',
                        'ALTER TABLE "startScan_dnsrecord" ADD COLUMN IF NOT EXISTS "source" varchar(200) NULL;',
                        'CREATE INDEX IF NOT EXISTS "ss_domaininfo_source_idx" ON "startScan_domaininfo" ("source");',
                        'CREATE INDEX IF NOT EXISTS "ss_dnsrecord_source_idx" ON "startScan_dnsrecord" ("source");',
                    ),
                    reverse_sql=(
                        'DROP INDEX IF EXISTS "ss_dnsrecord_source_idx";',
                        'DROP INDEX IF EXISTS "ss_domaininfo_source_idx";',
                        'ALTER TABLE "startScan_dnsrecord" DROP COLUMN IF EXISTS "source";',
                        'ALTER TABLE "startScan_domaininfo" DROP COLUMN IF EXISTS "source";',
                    ),
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name="domaininfo",
                    name="source",
                    field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
                ),
                migrations.AddField(
                    model_name="dnsrecord",
                    name="source",
                    field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
                ),
            ],
        ),
        migrations.AddField(
            model_name="certificate",
            name="source",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Secator task/tool that produced this finding (_source)",
                max_length=200,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="ipaddress",
            name="source",
            field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name="port",
            name="source",
            field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name="employee",
            name="source",
            field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name="exploit",
            name="source",
            field=models.CharField(blank=True, db_index=True, max_length=200, null=True),
        ),
        migrations.CreateModel(
            name="SubdomainTechnology",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(blank=True, db_index=True, max_length=200, null=True)),
                (
                    "subdomain",
                    models.ForeignKey(on_delete=models.deletion.CASCADE, to="startScan.subdomain"),
                ),
                (
                    "technology",
                    models.ForeignKey(on_delete=models.deletion.CASCADE, to="startScan.technology"),
                ),
            ],
            options={
                "db_table": "startScan_subdomaintechnology",
            },
        ),
        migrations.AddConstraint(
            model_name="subdomaintechnology",
            constraint=models.UniqueConstraint(
                fields=("subdomain", "technology"),
                name="ss_subdom_tech_sub_tech_uniq",
            ),
        ),
        migrations.RunPython(copy_subdomain_technology_links, noop_reverse),
        migrations.RemoveField(
            model_name="subdomain",
            name="technologies",
        ),
        migrations.AddField(
            model_name="subdomain",
            name="technologies",
            field=models.ManyToManyField(
                blank=True,
                related_name="technologies",
                through="SubdomainTechnology",
                to="startScan.technology",
            ),
        ),
    ]
