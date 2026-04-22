# Generated manually for removing InstalledExternalTool model

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("scanEngine", "0013_alter_secatorscan_options_alter_secatortask_options_and_more"),
    ]

    operations = [
        migrations.DeleteModel(
            name="InstalledExternalTool",
        ),
    ]
