from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0117_alter_ipaddress_extra_data"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="domain",
            name="start_scan_date",
        ),
    ]
