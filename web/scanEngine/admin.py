from django.contrib import admin

from scanEngine.models import (
    Configuration,
    EngineType,
    InterestingLookupModel,
    Notification,
    SecatorScan,
    SecatorTask,
    SecatorWorkflow,
    VulnerabilityReportSetting,
    Wordlist,
)


# Register your models here.


@admin.register(EngineType)
class EngineTypeAdmin(admin.ModelAdmin):
    """Admin interface for EngineType model with legacy support."""

    list_display = [
        "engine_name",
        "scan_type",
        "default_engine",
    ]
    list_filter = [
        "scan_type",
        "default_engine",
    ]
    search_fields = [
        "engine_name",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("engine_name", "scan_type", "default_engine")}),
        (
            "Configuration",
            {
                "fields": ("yaml_configuration",),
                "classes": ("wide",),
            },
        ),
    )


admin.site.register(Wordlist)
admin.site.register(Configuration)
admin.site.register(InterestingLookupModel)
admin.site.register(Notification)
admin.site.register(VulnerabilityReportSetting)


# Secator Integration Admin Classes


@admin.register(SecatorWorkflow)
class SecatorWorkflowAdmin(admin.ModelAdmin):
    """Admin interface for SecatorWorkflow model."""

    list_display = [
        "name",
        "display_name_formatted",
        "alias",
        "workflow_type",
        "scan_type",
        "is_active",
        "created_at",
        "updated_at",
    ]
    list_filter = [
        "workflow_type",
        "scan_type",
        "is_active",
        "created_at",
    ]
    search_fields = [
        "name",
        "alias",
        "display_name",
        "description",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "alias", "display_name", "description", "workflow_type", "scan_type", "is_active")}),
        (
            "Configuration",
            {
                "fields": ("yaml_configuration",),
                "classes": ("wide",),
            },
        ),
        (
            "Timestamps",
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def display_name_formatted(self, obj):
        """Display the formatted display name."""
        return obj.get_display_name()
    display_name_formatted.short_description = "Display Name"

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Override form field for alias to use TextInput instead of Select."""
        if db_field.name == "alias":
            from django import forms

            kwargs["widget"] = forms.TextInput(attrs={"placeholder": "e.g., subdomain_recon, cidr_recon"})
            kwargs["help_text"] = "Enter the workflow alias from Secator (optional)"
        return super().formfield_for_dbfield(db_field, request, **kwargs)


@admin.register(SecatorTask)
class SecatorTaskAdmin(admin.ModelAdmin):
    """Admin interface for SecatorTask model."""

    list_display = [
        "name",
        "task_type",
        "is_builtin",
        "created_at",
        "updated_at",
    ]
    list_filter = [
        "task_type",
        "is_builtin",
        "created_at",
    ]
    search_fields = [
        "name",
        "task_type",
        "description",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "task_type", "description", "is_builtin")}),
        (
            "Configuration",
            {
                "fields": ("yaml_configuration",),
                "classes": ("wide",),
            },
        ),
        (
            "Timestamps",
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(SecatorScan)
class SecatorScanAdmin(admin.ModelAdmin):
    """Admin interface for SecatorScan model."""

    list_display = [
        "name",
        "alias",
        "scan_type",
        "scan_config_type",
        "is_default",
        "is_active",
        "created_at",
    ]
    list_filter = [
        "scan_type",
        "scan_config_type",
        "is_default",
        "is_active",
        "created_at",
    ]
    search_fields = [
        "name",
        "description",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "alias", "display_name", "description", "scan_type", "is_default")}),
        ("Configuration", {"fields": ("scan_config_type", "yaml_configuration", "is_active")}),
        (
            "Timestamps",
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Override form field for alias to use TextInput instead of Select."""
        if db_field.name == "alias":
            from django import forms

            kwargs["widget"] = forms.TextInput(attrs={"placeholder": "e.g., domain, host, network, subdomain, url"})
            kwargs["help_text"] = "Enter the scan alias from Secator (optional)"
        return super().formfield_for_dbfield(db_field, request, **kwargs)
