import secrets
import uuid

from django.db import migrations, models
import django.db.models.deletion


def populate_pull_tokens(apps, schema_editor):
    SecatorWorker = apps.get_model("scanEngine", "SecatorWorker")
    for w in SecatorWorker.objects.all():
        if not (getattr(w, "pull_token", None) or "").strip():
            w.pull_token = secrets.token_urlsafe(32)
            w.save(update_fields=["pull_token"])


class Migration(migrations.Migration):
    dependencies = [
        ("scanEngine", "0027_add_scanengine_audit_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="secatorworker",
            name="https_pull_agent",
            field=models.BooleanField(
                default=False,
                help_text="When HTTPS classic: worker pulls jobs via API (no SSH for run/revoke).",
            ),
        ),
        migrations.AddField(
            model_name="secatorworker",
            name="pull_token",
            field=models.CharField(blank=True, default="", editable=False, max_length=64),
            preserve_default=False,
        ),
        migrations.RunPython(populate_pull_tokens, migrations.RunPython.noop),
        migrations.CreateModel(
            name="SecatorWorkerQueuedCommand",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("kind", models.CharField(choices=[("run_job", "Run job"), ("revoke", "Revoke")], max_length=16)),
                ("payload", models.JSONField(default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("error_message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "worker",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="queued_commands",
                        to="scanEngine.secatorworker",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="secatorworkerqueuedcommand",
            index=models.Index(fields=["worker", "status", "created_at"], name="scan_swq_worker_stat_cr"),
        ),
    ]
