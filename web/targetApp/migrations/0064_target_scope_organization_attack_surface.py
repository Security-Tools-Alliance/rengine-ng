from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0063_remove_target_start_scan_date"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="attack_surface",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="scope",
            name="attack_surface",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="target",
            name="attack_surface",
            field=models.TextField(blank=True, null=True),
        ),
    ]
