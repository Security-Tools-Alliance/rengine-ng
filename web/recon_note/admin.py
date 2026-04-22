from django.contrib import admin

from recon_note.models import TodoNote


@admin.register(TodoNote)
class TodoNoteAdmin(admin.ModelAdmin):
    """Admin interface for TodoNote model."""

    list_display = [
        "id",
        "title",
        "project",
        "scan_history",
        "subdomain",
        "is_done",
        "is_important",
    ]
    list_filter = [
        "is_done",
        "is_important",
    ]
    search_fields = [
        "title",
        "description",
    ]
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("title", "description", "project")},
        ),
        (
            "Associations",
            {"fields": ("scan_history", "subdomain")},
        ),
        (
            "Status",
            {"fields": ("is_done", "is_important")},
        ),
    )
