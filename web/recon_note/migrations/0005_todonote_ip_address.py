# Generated manually — optional recon note linked to an IP address

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0119_ip_host_endpoint_subscan_data_constraints_and_ipaddress_metadata"),
        ("recon_note", "0004_perf_indexes_subscan_todonote_vulnerability"),
    ]

    operations = [
        migrations.AddField(
            model_name="todonote",
            name="ip_address",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="recon_notes",
                to="startScan.ipaddress",
            ),
        ),
    ]
