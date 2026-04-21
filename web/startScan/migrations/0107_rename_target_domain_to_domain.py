# Rename FK target_domain -> domain on Subdomain, EndPoint, Vulnerability,
# MetaFinderDocument, Employee, Exploit.

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0106_domain_remove_project_target"),
    ]

    operations = [
        migrations.RenameField(
            model_name="subdomain",
            old_name="target_domain",
            new_name="domain",
        ),
        migrations.RenameField(
            model_name="endpoint",
            old_name="target_domain",
            new_name="domain",
        ),
        migrations.RenameField(
            model_name="vulnerability",
            old_name="target_domain",
            new_name="domain",
        ),
        migrations.RenameField(
            model_name="metafinderdocument",
            old_name="target_domain",
            new_name="domain",
        ),
        migrations.RenameField(
            model_name="employee",
            old_name="target_domain",
            new_name="domain",
        ),
        migrations.RenameField(
            model_name="exploit",
            old_name="target_domain",
            new_name="domain",
        ),
    ]
