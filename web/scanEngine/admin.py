from django import forms
from django.contrib import admin

from reNgine.admin_common import (
    FIELDSET_CONFIGURATION_YAML,
    SimpleLookupModelAdmin,
    TimestampedModelAdminMixin,
    build_fieldsets_with_timestamps,
)
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
        FIELDSET_CONFIGURATION_YAML,
    )


@admin.register(Wordlist)
class WordlistAdmin(SimpleLookupModelAdmin):
    """Admin interface for Wordlist model; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"
    list_filter = ["count"]


@admin.register(Configuration)
class ConfigurationAdmin(admin.ModelAdmin):
    """Admin interface for Configuration model."""

    list_display = [
        "name",
        "short_name",
    ]
    list_filter = []
    search_fields = [
        "name",
        "short_name",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "short_name")},
        ),
        (
            "Content",
            {
                "fields": ("content",),
                "classes": ("wide",),
            },
        ),
    )


@admin.register(InterestingLookupModel)
class InterestingLookupModelAdmin(SimpleLookupModelAdmin):
    """Admin interface for InterestingLookupModel; list_display and fieldsets from model _meta."""

    fieldset_title = "Basic Information"
    list_filter = [
        "custom_type",
        "title_lookup",
        "url_lookup",
        "condition_200_http_lookup",
    ]


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """Admin interface for Notification model."""

    list_display = [
        "id",
        "send_to_slack",
        "send_to_discord",
        "send_to_telegram",
        "send_scan_status_notif",
        "send_vuln_notif",
    ]
    list_filter = [
        "send_to_slack",
        "send_to_lark",
        "send_to_discord",
        "send_to_telegram",
        "send_scan_status_notif",
        "send_interesting_notif",
        "send_vuln_notif",
        "send_subdomain_changes_notif",
    ]
    search_fields = []
    fieldsets = (
        (
            "Channels",
            {
                "fields": (
                    "send_to_slack",
                    "slack_hook_url",
                    "send_to_lark",
                    "lark_hook_url",
                    "send_to_discord",
                    "discord_hook_url",
                    "send_to_telegram",
                    "telegram_bot_token",
                    "telegram_bot_chat_id",
                )
            },
        ),
        (
            "Notification Types",
            {
                "fields": (
                    "send_scan_status_notif",
                    "send_interesting_notif",
                    "send_vuln_notif",
                    "send_subdomain_changes_notif",
                )
            },
        ),
        (
            "Options",
            {
                "fields": (
                    "send_scan_output_file",
                    "send_scan_tracebacks",
                )
            },
        ),
    )


@admin.register(VulnerabilityReportSetting)
class VulnerabilityReportSettingAdmin(admin.ModelAdmin):
    """Admin interface for VulnerabilityReportSetting model."""

    list_display = [
        "id",
        "company_name",
        "show_rengine_banner",
        "show_executive_summary",
        "show_footer",
    ]
    list_filter = [
        "show_rengine_banner",
        "show_executive_summary",
        "show_footer",
    ]
    search_fields = [
        "company_name",
        "company_email",
        "footer_text",
    ]
    fieldsets = (
        (
            "Company",
            {
                "fields": (
                    "company_name",
                    "company_address",
                    "company_email",
                    "company_website",
                )
            },
        ),
        (
            "Branding",
            {
                "fields": (
                    "primary_color",
                    "secondary_color",
                    "show_rengine_banner",
                )
            },
        ),
        (
            "Report Content",
            {
                "fields": (
                    "show_executive_summary",
                    "executive_summary_description",
                    "show_footer",
                    "footer_text",
                )
            },
        ),
    )


# Secator Integration Admin Classes


@admin.register(SecatorWorkflow)
class SecatorWorkflowAdmin(TimestampedModelAdminMixin, admin.ModelAdmin):
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
    fieldsets = build_fieldsets_with_timestamps(
        (
            "Basic Information",
            {
                "fields": (
                    "name",
                    "alias",
                    "display_name",
                    "description",
                    "workflow_type",
                    "scan_type",
                    "is_active",
                )
            },
        ),
        FIELDSET_CONFIGURATION_YAML,
        model=SecatorWorkflow,
    )

    def display_name_formatted(self, obj):
        """Display the formatted display name."""
        return obj.get_display_name()

    display_name_formatted.short_description = "Display Name"

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Override form field for alias to use TextInput instead of Select."""
        if db_field.name == "alias":
            kwargs["widget"] = forms.TextInput(attrs={"placeholder": "e.g., subdomain_recon, cidr_recon"})
            kwargs["help_text"] = "Enter the workflow alias from Secator (optional)"
        return super().formfield_for_dbfield(db_field, request, **kwargs)


@admin.register(SecatorTask)
class SecatorTaskAdmin(TimestampedModelAdminMixin, admin.ModelAdmin):
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
    fieldsets = build_fieldsets_with_timestamps(
        ("Basic Information", {"fields": ("name", "task_type", "description", "is_builtin")}),
        FIELDSET_CONFIGURATION_YAML,
        model=SecatorTask,
    )


@admin.register(SecatorScan)
class SecatorScanAdmin(TimestampedModelAdminMixin, admin.ModelAdmin):
    """Admin interface for SecatorScan model."""

    list_display = [
        "name",
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
    fieldsets = build_fieldsets_with_timestamps(
        ("Basic Information", {"fields": ("name", "description", "scan_type", "is_default")}),
        (
            "Configuration",
            {
                "fields": ("scan_config_type", "yaml_configuration", "is_active"),
                "classes": ("wide",),
            },
        ),
        model=SecatorScan,
    )
