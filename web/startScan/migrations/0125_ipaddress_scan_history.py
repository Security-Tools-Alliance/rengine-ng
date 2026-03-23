from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0124_cleanup_ip_domains"),
    ]

    operations = [
        migrations.AddField(
            model_name="ipaddress",
            name="scan_history",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.SET_NULL,
                related_name="ip_rows",
                to="startScan.scanhistory",
            ),
        ),
    ]
