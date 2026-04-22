# Scope normalizer: allowed_finding_hosts

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0060_scope_restrict_findings_and_allowed_domains"),
    ]

    operations = [
        migrations.AddField(
            model_name="scope",
            name="allowed_finding_hosts",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="When restrict_findings_to_target is True and this list is non-empty, only these hostnames and IPs are accepted for Subdomain/Domain creation.",
            ),
        ),
    ]
