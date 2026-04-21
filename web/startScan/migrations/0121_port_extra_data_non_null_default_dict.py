from django.db import migrations, models


def backfill_null_port_extra_data(apps, schema_editor):
    Port = apps.get_model("startScan", "Port")
    Port.objects.filter(extra_data__isnull=True).update(extra_data={})


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0120_port_extra_data"),
    ]

    operations = [
        migrations.RunPython(backfill_null_port_extra_data, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="port",
            name="extra_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="Secator tool-specific port metadata (e.g. nmap service block)",
            ),
        ),
    ]
