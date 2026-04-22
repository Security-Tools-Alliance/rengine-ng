# Add SecatorRunner.worker FK to scanEngine.SecatorWorker

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanEngine", "0026_secatorworker"),
        ("startScan", "0094_alter_scanschedule_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="secatorrunner",
            name="worker",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.SET_NULL,
                related_name="secatorrunner_set",
                to="scanEngine.secatorworker",
            ),
        ),
    ]
