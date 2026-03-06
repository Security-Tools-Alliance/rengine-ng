# Generated manually for scope workers business rules

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0058_rename_request_headers_to_header_in_scan_config"),
        ("scanEngine", "0027_add_scanengine_audit_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="scope",
            name="allow_local_worker",
            field=models.BooleanField(
                default=True,
                help_text="If True, Local (this server) is in the allowed workers list for this scope.",
            ),
        ),
        migrations.AddField(
            model_name="scope",
            name="default_worker",
            field=models.ForeignKey(
                blank=True,
                help_text="Default worker when the scope has 2+ allowed workers; null means Local.",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="scopes_as_default",
                to="scanEngine.secatorworker",
            ),
        ),
    ]
