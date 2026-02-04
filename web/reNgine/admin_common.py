"""
Shared admin fieldset definitions and mixins for reNgine admin interfaces.

Centralizes common fieldsets (timestamps, YAML configuration) so they can be
reused and updated in one place across scanEngine, startScan, and other apps.

Provides model._meta-driven helpers and SimpleLookupModelAdmin for small/lookup
models so admin list_display and fieldsets stay in sync when models evolve.
"""

from django.contrib import admin


# Common readonly fields for models with auto-managed timestamps
READONLY_TIMESTAMPS = ("created_at", "updated_at")

# Reusable fieldset tuple for timestamps (collapsed by default)
FIELDSET_TIMESTAMPS = (
    "Timestamps",
    {
        "fields": READONLY_TIMESTAMPS,
        "classes": ("collapse",),
    },
)

# Reusable fieldset tuple for YAML configuration (wide layout)
FIELDSET_CONFIGURATION_YAML = (
    "Configuration",
    {
        "fields": ("yaml_configuration",),
        "classes": ("wide",),
    },
)


def build_fieldsets_with_timestamps(*base_fieldsets, model=None):
    """
    Build a fieldsets tuple by appending the central Timestamps fieldset
    when the model has created_at and updated_at fields.

    Args:
        *base_fieldsets: Variable number of (title, options_dict) fieldset tuples.
        model: Django model class to check for timestamp fields. If None, timestamps are not added.

    Returns:
        Tuple of fieldsets suitable for ModelAdmin.fieldsets.
    """
    fieldsets = list(base_fieldsets)
    if model is not None and hasattr(model, "_meta"):
        field_names = {f.name for f in model._meta.get_fields()}
        if "created_at" in field_names and "updated_at" in field_names:
            fieldsets.append(FIELDSET_TIMESTAMPS)
    return tuple(fieldsets)


def get_concrete_field_names(model, exclude=None, include_m2m=False):
    """
    Return list of concrete field names from model._meta for use in list_display or fieldsets.
    Excludes reverse relations. Optionally excludes M2M so list_display stays simple.
    """
    exclude = set(exclude or [])
    names = []
    for f in model._meta.get_fields():
        if f.name in exclude:
            continue
        if getattr(f, "remote_field", None) and getattr(f.remote_field, "parent_link", False):
            continue
        if f.many_to_many and not include_m2m:
            continue
        if f.concrete:
            names.append(f.name)
    return names


def get_searchable_field_names(model, exclude=None):
    """
    Return field names that are typically searchable (CharField, TextField, etc.).
    Exclude list avoids adding non-indexed or rarely-searched fields that can hurt
    admin search performance on large tables.
    """
    exclude = set(exclude or [])
    searchable_internal_types = {"CharField", "TextField", "SlugField", "EmailField"}
    result = []
    for f in model._meta.get_fields():
        if f.name in exclude or not getattr(f, "concrete", True):
            continue
        internal_type = getattr(f, "get_internal_type", lambda: None)()
        if internal_type in searchable_internal_types:
            result.append(f.name)
    return result


def build_single_fieldset_from_model(model, title="Details", exclude=None):
    """Build a single (title, {"fields": (...)}) fieldset from model's concrete fields."""
    fields = tuple(get_concrete_field_names(model, exclude=exclude, include_m2m=True))
    return (title, {"fields": fields}) if fields else (title, {"fields": ("id",)})


class SimpleLookupModelAdmin(admin.ModelAdmin):
    """
    ModelAdmin that derives list_display and fieldsets from model._meta so they stay
    in sync when the model changes. Suited to small lookup-style models (e.g. CveId,
    CweId, VulnerabilityTags, Technology, Waf).

    Class attributes for customization:
    - list_display_include_id: if True (default), prepend "id" to list_display
    - list_display_exclude: set/list of field names to omit from list_display
    - fieldset_title: title for the single fieldset (default "Details")
    - fieldset_exclude: set/list of field names to omit from the fieldset
    - search_fields_override: if set, used as search_fields instead of _meta-derived
    - search_fields_exclude: set/list of field names to omit from auto-derived
      search_fields (e.g. long/unindexed CharField/TextField to avoid expensive LIKE).
    """

    list_display_include_id = True
    list_display_exclude = None
    fieldset_title = "Details"
    fieldset_exclude = None
    search_fields_override = None
    search_fields_exclude = None

    def __init__(self, model, admin_site):
        super().__init__(model, admin_site)
        exclude = set(self.list_display_exclude or [])
        names = get_concrete_field_names(self.model, exclude=exclude, include_m2m=False)
        if (
            self.list_display_include_id
            and "id" not in names
            and hasattr(self.model._meta, "pk")
            and self.model._meta.pk.name == "id"
        ):
            names.insert(0, "id")
        self.list_display = names
        self.fieldsets = (
            build_single_fieldset_from_model(self.model, title=self.fieldset_title, exclude=self.fieldset_exclude),
        )
        if self.search_fields_override is None:
            search_exclude = set(self.search_fields_exclude or [])
            self.search_fields = get_searchable_field_names(self.model, exclude=search_exclude) or ["id"]


class TimestampedModelAdminMixin(admin.ModelAdmin):
    """
    Mixin that adds created_at and updated_at to readonly_fields when the model has these fields.
    Uses get_readonly_fields so subclasses that override readonly_fields still get timestamps.
    """

    def get_readonly_fields(self, request, obj=None):
        base = super().get_readonly_fields(request, obj)
        base_list = list(base) if isinstance(base, (list, tuple)) else [base]
        field_names = {f.name for f in self.model._meta.get_fields()}
        if "created_at" in field_names and "created_at" not in base_list:
            base_list.append("created_at")
        if "updated_at" in field_names and "updated_at" not in base_list:
            base_list.append("updated_at")
        return base_list
