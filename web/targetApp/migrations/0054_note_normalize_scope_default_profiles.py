"""
Note for future data migration: Scope.default_profiles may be stored as a list (legacy).
To normalize list-form values to dict, use normalize_scope_default_profiles_to_dict()
from targetApp.services.scope_params and update each Scope where default_profiles
is a list. Then resolution code can assume dict-only and _profiles_to_list can be simplified.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0053_scope_default_profiles_help_text"),
    ]

    operations = []
