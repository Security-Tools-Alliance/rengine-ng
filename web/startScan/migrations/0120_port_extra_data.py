from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0119_ip_host_endpoint_subscan_data_constraints_and_ipaddress_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="port",
            name="extra_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="Secator tool-specific port metadata (e.g. nmap service block)",
            ),
        ),
    ]
