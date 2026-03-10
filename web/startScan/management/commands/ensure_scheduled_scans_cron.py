"""
CLI hook for run_scheduled_scans cron job installation.

This command is the sole CLI/entrypoint hook for cron setup. It delegates to
startScan.cron_utils.ensure_run_scheduled_scans_cron() (the single place where
crontab logic lives). Used by docker/web/entrypoint.sh at startup and by
operators for manual fixes. For the full picture of who calls cron_utils, see
the module docstring in startScan/cron_utils.py.
"""

from django.core.management.base import BaseCommand

from startScan.cron_utils import ensure_run_scheduled_scans_cron


class Command(BaseCommand):
    help = "Ensure run_scheduled_scans cron job is installed in the web container (no-op if not in container)."

    def handle(self, *args, **options):
        if ensure_run_scheduled_scans_cron():
            self.stdout.write(self.style.SUCCESS("Cron job present or installed."))
        else:
            self.stdout.write(
                "Crontab not available (e.g. outside web container). "
                "In the web container without cron package, scheduled scans run via the entrypoint loop."
            )
