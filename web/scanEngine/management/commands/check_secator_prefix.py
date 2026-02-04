"""
Django management command to validate SECATOR_REPORTS_PREFIX and RENGINE_RESULTS.
Helps detect worker/web configuration mismatch in production.
"""

import sys

from django.core.management.base import BaseCommand

from reNgine.secator.diagnostic import get_secator_prefix_diagnostic


class Command(BaseCommand):
    help = (
        "Validate Secator path configuration (SECATOR_REPORTS_PREFIX vs RENGINE_RESULTS). "
        "Exits with code 1 if stored paths still contain the prefix or if RENGINE_RESULTS is not usable."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--sample-size",
            type=int,
            default=20,
            help="Max number of sample paths to show when prefix mismatch is detected (default: 20)",
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Only exit with code 1 on failure; minimal output",
        )

    def handle(self, *args, **options):
        sample_size = options["sample_size"]
        quiet = options["quiet"]
        diag = get_secator_prefix_diagnostic(sample_size=sample_size)

        if quiet:
            if not diag["ok"]:
                self.stderr.write(
                    "check_secator_prefix: configuration or data issues detected"
                )
            sys.exit(0 if diag["ok"] else 1)

        self.stdout.write("Secator path configuration diagnostic")
        self.stdout.write("=" * 50)
        self.stdout.write(f"  SECATOR_REPORTS_PREFIX = {diag['prefix_configured']!r}")
        self.stdout.write(f"  RENGINE_RESULTS       = {diag['rengine_results']!r}")
        self.stdout.write(
            f"  RENGINE_RESULTS exists: {diag['rengine_results_exists']}"
        )
        self.stdout.write(
            f"  RENGINE_RESULTS readable: {diag['rengine_results_readable']}"
        )
        self.stdout.write(
            f"  Stored paths with content: {diag['count_total_with_path']}"
        )
        self.stdout.write(
            f"  Paths still containing prefix (mis-sync/legacy): {diag['count_paths_still_with_prefix']}"
        )
        self.stdout.write("")

        if diag["paths_still_with_prefix"]:
            self.stdout.write(
                self.style.WARNING("Sample paths that still start with prefix:")
            )
            for p in diag["paths_still_with_prefix"]:
                self.stdout.write(self.style.WARNING(f"  - {p}"))
            self.stdout.write("")
            self.stdout.write(
                self.style.WARNING(
                    "Worker and web SECATOR_REPORTS_PREFIX should match; "
                    "or these are legacy paths from before stripping. "
                    "ServeScanFile will log warnings when serving such paths."
                )
            )
            self.stdout.write("")

        if not diag["rengine_results_readable"]:
            self.stdout.write(
                self.style.ERROR(
                    "RENGINE_RESULTS directory is missing or not readable. "
                    "File serving (screenshots, stored responses) will fail."
                )
            )
            self.stdout.write("")

        if diag["ok"]:
            self.stdout.write(self.style.SUCCESS("OK: Configuration and stored paths look consistent."))
        else:
            self.stderr.write(
                self.style.ERROR("One or more issues detected. Review output above.")
            )

        sys.exit(0 if diag["ok"] else 1)
