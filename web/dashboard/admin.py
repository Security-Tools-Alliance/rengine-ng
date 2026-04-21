from django.contrib import admin

from dashboard.models import (
    NetlasAPIKey,
    OllamaSettings,
    OpenAiAPIKey,
    Project,
    SearchHistory,
    UserAPIKey,
    UserPreference,
)


@admin.register(SearchHistory)
class SearchHistoryAdmin(admin.ModelAdmin):
    """Admin interface for SearchHistory model."""

    list_display = [
        "id",
        "query",
    ]
    list_display_links = ["query"]
    list_filter = []
    ordering = ["-id"]
    search_fields = [
        "query",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("query",)},
        ),
    )


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    """Admin interface for Project model."""

    list_display = [
        "id",
        "name",
        "slug",
        "insert_date",
    ]
    list_display_links = ["name"]
    list_filter = [
        "insert_date",
    ]
    ordering = ["-insert_date"]
    date_hierarchy = "insert_date"
    search_fields = [
        "name",
        "slug",
        "description",
    ]
    filter_horizontal = [
        "users",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "slug", "description", "insert_date")},
        ),
        (
            "Users",
            {"fields": ("users",)},
        ),
    )


@admin.register(OllamaSettings)
class OllamaSettingsAdmin(admin.ModelAdmin):
    """Admin interface for OllamaSettings model."""

    list_display = [
        "id",
        "selected_model",
        "use_ollama",
    ]
    list_filter = [
        "use_ollama",
    ]
    search_fields = [
        "selected_model",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("selected_model", "use_ollama")},
        ),
    )


@admin.register(OpenAiAPIKey)
class OpenAiAPIKeyAdmin(admin.ModelAdmin):
    """Admin interface for OpenAiAPIKey model."""

    list_display = [
        "id",
    ]
    list_filter = []
    ordering = ["-id"]
    search_fields = []
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("key",)},
        ),
    )


@admin.register(NetlasAPIKey)
class NetlasAPIKeyAdmin(admin.ModelAdmin):
    """Admin interface for NetlasAPIKey model."""

    list_display = [
        "id",
    ]
    list_filter = []
    ordering = ["-id"]
    search_fields = []
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("key",)},
        ),
    )


@admin.register(UserAPIKey)
class UserAPIKeyAdmin(admin.ModelAdmin):
    """Admin interface for UserAPIKey model."""

    list_display = ["id", "name", "user", "created_at", "last_used", "is_active", "is_system"]
    list_filter = ["is_active", "is_system", "created_at"]
    search_fields = ["name", "user__username"]
    readonly_fields = ["created_at"]


@admin.register(UserPreference)
class UserPreferenceAdmin(admin.ModelAdmin):
    """Admin interface for UserPreference model."""

    list_display = ["id", "user"]
    list_display_links = ["user"]
    list_filter = ["user"]
    ordering = ["user__username"]
    search_fields = ["user__username"]
