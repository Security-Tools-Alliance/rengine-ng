from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanEngine", "0028_secatorworker_pull_agent_and_queued_command"),
    ]

    operations = [
        migrations.AddField(
            model_name="secatorworker",
            name="https_pull_verify_ssl",
            field=models.BooleanField(
                default=True,
                help_text="When pull agent: verify reNgine TLS certificate (disable for self-signed).",
            ),
        ),
    ]
