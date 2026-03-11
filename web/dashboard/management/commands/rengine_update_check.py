"""
Django management command to check for reNgine-ng updates (GitHub latest release vs current version).
Output can be JSON for scripting or human-readable.
"""

import json
import sys

from django.core.management.base import BaseCommand

from reNgine.utilities.update_check import get_update_info


class Command(BaseCommand):
    help = "Check if a reNgine-ng update is available (current vs GitHub latest release)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--json",
            action="store_true",
            help="Output result as JSON (for scripting)",
        )

    def handle(self, *args, **options):
        info = get_update_info()
        as_json = options.get("json", False)

        if not info.get("status"):
            if as_json:
                self.stdout.write(json.dumps(info, indent=2))
            else:
                self.stdout.write(self.style.ERROR("Update check failed: %s" % info.get("message", "Unknown error")))
            sys.exit(1)

        if as_json:
            out = {
                "status": info["status"],
                "current_version": info["current_version"],
                "latest_version": info["latest_version"],
                "update_available": info["update_available"],
            }
            if info.get("changelog") is not None:
                out["changelog"] = info["changelog"]
            self.stdout.write(json.dumps(out, indent=2))
            return

        self.stdout.write("Current version: %s" % info["current_version"])
        self.stdout.write("Latest version: %s" % info["latest_version"])
        if info["update_available"]:
            self.stdout.write(self.style.SUCCESS("An update is available."))
        else:
            self.stdout.write(self.style.SUCCESS("You are on the latest version."))
