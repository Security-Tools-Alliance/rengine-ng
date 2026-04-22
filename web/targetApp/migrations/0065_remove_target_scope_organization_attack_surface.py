from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0064_target_scope_organization_attack_surface"),
        ("startScan", "0128_migrate_legacy_attack_surface_to_llm_table"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="target",
            name="attack_surface",
        ),
        migrations.RemoveField(
            model_name="scope",
            name="attack_surface",
        ),
        migrations.RemoveField(
            model_name="organization",
            name="attack_surface",
        ),
    ]
