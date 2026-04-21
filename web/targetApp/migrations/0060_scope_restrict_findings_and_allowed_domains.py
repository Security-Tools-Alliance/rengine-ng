# Scope finding restriction (whitelist)

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0059_scope_allow_local_and_default_worker"),
    ]

    operations = [
        migrations.AddField(
            model_name="scope",
            name="restrict_findings_to_target",
            field=models.BooleanField(
                default=False,
                help_text="If True, only findings whose domain/host is the target or in the allowed list are created.",
            ),
        ),
        migrations.AddField(
            model_name="scope",
            name="allowed_finding_domains",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of domain names (e.g. ['easi-services.fr']) allowed in addition to the target when restrict_findings_to_target is True.",
            ),
        ),
    ]
