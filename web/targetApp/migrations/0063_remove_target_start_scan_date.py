from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0062_alter_scope_allowed_finding_domains"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="target",
            name="start_scan_date",
        ),
    ]
