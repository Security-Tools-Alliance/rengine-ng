# Repoint MetaFinderDocument.target_domain from targetApp.domain to startScan.domain (state only).
# FK column unchanged; 0101 missed this model.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0101_add_domain_models_state_only"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="metafinderdocument",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
            ],
            database_operations=[],
        ),
    ]
