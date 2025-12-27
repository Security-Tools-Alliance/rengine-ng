"""
Django management command to generate system API key for Secator workers.
"""

from django.core.management.base import BaseCommand, CommandError

from reNgine.utilities.api_key_generator import generate_secator_api_key, has_secator_api_key


class Command(BaseCommand):
    help = "Generate or retrieve system API key for Secator workers"

    def add_arguments(self, parser):
        parser.add_argument(
            "--recreate",
            action="store_true",
            help="Delete existing system API key and create a new one",
        )
        parser.add_argument(
            "--show-key",
            action="store_true",
            help="Show the generated API key (only works when creating a new key)",
        )

    def handle(self, *args, **options):
        recreate = options.get("recreate", False)
        show_key = options.get("show_key", False)

        try:
            # Check if key already exists
            if has_secator_api_key() and not recreate:
                self.stdout.write(
                    self.style.WARNING("System API key already exists. Use --recreate to generate a new one.")
                )
                self.stdout.write("")
                self.stdout.write("Note: The actual key value cannot be retrieved from the database.")
                self.stdout.write(
                    "If you need to see the key, you must use --recreate to generate a new one with --show-key."
                )
                return

            # Generate the key
            if recreate:
                self.stdout.write(self.style.WARNING("Recreating system API key..."))

            key, created = generate_secator_api_key(recreate=recreate)

            if created:
                self.stdout.write(self.style.SUCCESS("✓ System API key generated successfully!"))
                self.stdout.write("")

                if show_key and key:
                    self.stdout.write(self.style.SUCCESS("━" * 80))
                    self.stdout.write(self.style.SUCCESS("API Key (save this securely):"))
                    self.stdout.write(self.style.SUCCESS(key))
                    self.stdout.write(self.style.SUCCESS("━" * 80))
                    self.stdout.write("")
                    self.stdout.write("Add this to your .env file:")
                    self.stdout.write(f"RENGINE_API_KEY={key}")
                    self.stdout.write("")
                    self.stdout.write(self.style.WARNING("⚠️  This is the only time you will see this key!"))
                    self.stdout.write(
                        self.style.WARNING("⚠️  Store it securely - it cannot be retrieved again from the database.")
                    )
                else:
                    self.stdout.write(self.style.WARNING("⚠️  API key was generated but not displayed."))
                    self.stdout.write(self.style.WARNING("Use --show-key flag to see the key when generating."))
            else:
                self.stdout.write(self.style.WARNING("System API key already exists (returned existing)."))

            self.stdout.write("")
            self.stdout.write("System API key details:")
            self.stdout.write("  - User: secator-worker")
            self.stdout.write("  - Name: Secator Worker System Key")
            self.stdout.write("  - Type: System (cannot be deleted via UI)")
            self.stdout.write("")
            self.stdout.write("This key is used by Secator workers to authenticate with the reNgine API.")

        except Exception as e:
            raise CommandError(f"Failed to generate system API key: {str(e)}")
