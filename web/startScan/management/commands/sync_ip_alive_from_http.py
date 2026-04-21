"""
Backfill IpAddress.alive=True from HTTP evidence (subdomain / endpoint).

Uses IpRepository.sync_alive_from_http_evidence for each distinct IP linked to the
scan (M2M or IP-backed endpoints). Does not set alive=False.

Usage:
  python manage.py sync_ip_alive_from_http
  python manage.py sync_ip_alive_from_http --scan-history <id>
"""

from django.core.management.base import BaseCommand

from reNgine.services.repositories.ip_repository import IpRepository
from reNgine.services.scan_finding_metrics import ip_address_ids_in_scan
from startScan.models import ScanHistory


class Command(BaseCommand):
    help = (
        "Set IpAddress.alive from HTTP evidence for IPs linked to scan(s). "
        "Without --scan-history, all ScanHistory rows are processed."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--scan-history",
            type=int,
            default=None,
            dest="scan_history_id",
            metavar="ID",
            help="Limit to this ScanHistory primary key (omit to process every scan).",
        )

    def handle(self, *args, **options):
        scan_history_id = options["scan_history_id"]
        if scan_history_id is not None:
            self._run_for_scans([scan_history_id])
            return

        scan_ids = list(ScanHistory.objects.order_by("id").values_list("id", flat=True))
        if not scan_ids:
            self.stdout.write(self.style.WARNING("No ScanHistory rows in the database."))
            return
        self._run_for_scans(scan_ids)

    def _run_for_scans(self, scan_ids: list[int]) -> None:
        single = len(scan_ids) == 1
        repo = IpRepository()
        scans_with_ips = 0
        total_ip_checks = 0
        updated = 0

        for sid in scan_ids:
            ids = sorted(ip_address_ids_in_scan(sid))
            if not ids:
                continue
            scans_with_ips += 1
            total_ip_checks += len(ids)
            for ip_id in ids:
                if repo.sync_alive_from_http_evidence(ip_id, sid):
                    updated += 1

        if single and total_ip_checks == 0:
            self.stdout.write(self.style.WARNING("No IP addresses linked to this scan."))
            return

        if not single and scans_with_ips == 0:
            self.stdout.write(self.style.WARNING("No IP addresses linked to any scan."))
            return

        if single:
            self.stdout.write(
                self.style.SUCCESS("Processed %s IP(s); set alive=True for %s row(s)." % (total_ip_checks, updated))
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "Processed %s scan(s) with linked IPs (%s IP row checks); "
                    "set alive=True for %s row(s)." % (scans_with_ips, total_ip_checks, updated)
                )
            )
