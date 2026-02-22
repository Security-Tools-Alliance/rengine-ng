from django.contrib import admin

from .models import Organization, Target


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    """Admin interface for Target model."""

    list_display = [
        "value",
        "target_type",
        "project",
        "insert_date",
        "start_scan_date",
    ]
    list_filter = [
        "target_type",
        "insert_date",
        "start_scan_date",
    ]
    search_fields = [
        "value",
        "description",
        "h1_team_handle",
    ]
    readonly_fields = [
        "insert_date",
        "start_scan_date",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("value", "target_type", "project", "description")},
        ),
        (
            "Optional",
            {"fields": ("port", "custom_dns_servers", "h1_team_handle", "insert_date", "start_scan_date")},
        ),
        (
            "Advanced",
            {"fields": ("request_headers",), "classes": ("collapse",)},
        ),
    )


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    """Admin interface for Organization model."""

    list_display = [
        "name",
        "project",
        "insert_date",
    ]
    list_filter = [
        "insert_date",
    ]
    search_fields = [
        "name",
        "description",
    ]
    readonly_fields = [
        "insert_date",
    ]
    filter_horizontal = [
        "targets",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "description", "project", "insert_date")},
        ),
        (
            "Targets",
            {"fields": ("targets",)},
        ),
    )
