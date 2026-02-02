from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0086_add_results_dir_to_scanactivity"),
    ]

    operations = [
        migrations.AlterField(
            model_name="subscan",
            name="subdomain",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="startScan.subdomain",
            ),
        ),
        migrations.AddField(
            model_name="subscan",
            name="secator_runner",
            field=models.OneToOneField(
                blank=True,
                help_text="Secator runner linked to this subscan (Secator scans only)",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="subscan",
                to="startScan.secatorrunner",
            ),
        ),
    ]
