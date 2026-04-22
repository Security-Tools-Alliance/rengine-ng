from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0128_migrate_legacy_attack_surface_to_llm_table"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="subdomain",
            name="attack_surface",
        ),
        migrations.RemoveField(
            model_name="ipaddress",
            name="attack_surface",
        ),
    ]
