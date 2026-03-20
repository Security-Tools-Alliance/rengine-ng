from django.apps import AppConfig


class DashboardConfig(AppConfig):
    name = "dashboard"

    def ready(self):
        # Import signals module to register handlers (module-level receivers ensure idempotent registration)
        from dashboard import signals  # noqa: F401
