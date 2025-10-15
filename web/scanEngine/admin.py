from django.contrib import admin

from scanEngine.models import (
    Configuration,
    EngineType,
    InstalledExternalTool,
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
admin.site.register(InstalledExternalTool)


# Secator Integration Admin Classes


@admin.register(SecatorWorkflow)
class SecatorWorkflowAdmin(admin.ModelAdmin):
    """Admin interface for SecatorWorkflow model."""

    list_display = [
        "name",
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
        "description",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "description", "workflow_type", "scan_type", "is_active")}),
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
        "scan_type",
        "execution_mode",
        "scan_config_type",
        "is_default",
        "get_tasks_count_display",
        "created_at",
    ]
    list_filter = [
        "scan_type",
        "execution_mode",
        "scan_config_type",
        "is_default",
        "created_at",
    ]
    search_fields = [
        "name",
        "description",
    ]
    readonly_fields = [
        "created_at",
        "updated_at",
        "get_tasks_count_display",
    ]
    filter_horizontal = [
        "tasks",
    ]
    fieldsets = (
        ("Basic Information", {"fields": ("name", "description", "scan_type", "is_default")}),
        ("Execution Configuration", {"fields": ("execution_mode", "scan_config_type", "workflow", "tasks")}),
        (
            "Statistics",
            {
                "fields": ("get_tasks_count_display",),
                "classes": ("collapse",),
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

    def get_tasks_count_display(self, obj):
        """Display the number of tasks in this scan configuration."""
        return obj.get_tasks_count()

    get_tasks_count_display.short_description = "Tasks Count"
