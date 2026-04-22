"""Add extra_data JSONField to IpAddress for ASN and other optional data from Secator."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0113_scanhistory_scan_config"),
    ]

    operations = [
        migrations.AddField(
            model_name="ipaddress",
            name="extra_data",
            field=models.JSONField(blank=True, null=True),
        ),
    ]
