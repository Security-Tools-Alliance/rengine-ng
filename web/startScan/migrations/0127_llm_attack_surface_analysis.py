from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("startScan", "0126_backfill_ipaddress_scan_history"),
    ]

    operations = [
        migrations.CreateModel(
            name="LlmAttackSurfaceAnalysis",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("object_id", models.PositiveIntegerField()),
                ("llm_model", models.CharField(max_length=512)),
                ("body_markdown", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "content_type",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="contenttypes.contenttype"),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["content_type", "object_id"], name="startScan_llm_at_content_16e0db_idx")
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="llmattacksurfaceanalysis",
            constraint=models.UniqueConstraint(
                fields=("content_type", "object_id", "llm_model"),
                name="startscan_llm_attack_surface_ct_obj_model_uniq",
            ),
        ),
    ]
