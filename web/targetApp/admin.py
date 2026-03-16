from django.contrib import admin

from .models import Organization, Scope, Target


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
    list_display_links = ["value"]
    list_filter = [
        "target_type",
        "insert_date",
    ]
    list_per_page = 50
    list_select_related = ["project"]
    ordering = ["-insert_date"]
    date_hierarchy = "insert_date"
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
            {"fields": ("request_headers", "scan_config"), "classes": ("collapse",)},
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
    list_display_links = ["name"]
    list_filter = [
        "insert_date",
    ]
    list_select_related = ["project"]
    ordering = ["-insert_date"]
    date_hierarchy = "insert_date"
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


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    """Admin interface for Scope model."""

    list_display = [
        "name",
        "organization",
        "scope_type",
        "start_date",
        "end_date",
        "insert_date",
    ]
    list_display_links = ["name"]
    list_filter = [
        "scope_type",
        "organization",
        "insert_date",
    ]
    list_select_related = ["organization"]
    ordering = ["-insert_date"]
    date_hierarchy = "insert_date"
    search_fields = [
        "name",
        "description",
    ]
    readonly_fields = [
        "insert_date",
    ]
    filter_horizontal = [
        "targets",
        "workers",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("organization", "name", "scope_type", "description", "start_date", "end_date", "insert_date")},
        ),
        (
            "Targets & Workers",
            {"fields": ("targets", "workers")},
        ),
        (
            "Scan Parameters",
            {
                "fields": (
                    "threads",
                    "rate_limit",
                    "timeout",
                    "retries",
                    "delay",
                    "proxy",
                    "user_agent",
                    "follow_redirect",
                    "depth",
                    "request_headers",
                    "default_profiles",
                    "extra_config",
                ),
                "classes": ("collapse",),
            },
        ),
    )
