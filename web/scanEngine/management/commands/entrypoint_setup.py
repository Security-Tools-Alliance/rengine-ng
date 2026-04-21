"""
Run all Django setup steps in a single process (migrations, OAuth, cron, Secator load, collectstatic).

Used by docker/web/entrypoint.sh to avoid multiple Python/Django startups.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Run migrations, setup OAuth, ensure scheduled scans cron, load Secator components, collect static files (single process)."

    def _print_section(self, title: str) -> None:
        """Print a section header matching entrypoint.sh print_msg style."""
        sep = "============================================================"
        self.stdout.write("")
        self.stdout.write(sep)
        self.stdout.write(title)
        self.stdout.write(sep)
        self.stdout.write("")

    def handle(self, *args, **options) -> None:
        self._print_section("Generate Django migrations files")
        call_command("makemigrations")

        self._print_section("Migrate database")
        call_command("migrate")

        self._print_section("Setup OAuth providers from environment")
        call_command("setup_oauth")

        self._print_section("Ensure scheduled scans (if any schedule exists)")
        try:
            call_command("ensure_scheduled_scans_cron")
        except CommandError:
            self.stdout.write(
                self.style.WARNING("ensure_scheduled_scans_cron failed or skipped (e.g. no cron in container).")
            )

        self._print_section("Loading Secator components (from Secator library)")
        try:
            call_command("load_secator_all")
        except CommandError:
            self.stdout.write(self.style.WARNING("load_secator_all failed or skipped."))

        self._print_section("Collect static files")
        call_command("collectstatic", "--noinput")

        self.stdout.write(self.style.SUCCESS("Entrypoint setup completed."))
