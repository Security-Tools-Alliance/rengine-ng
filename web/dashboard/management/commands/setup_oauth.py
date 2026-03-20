"""
Management command to setup OAuth providers from environment variables
"""

import os

from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Setup OAuth providers from environment variables (single-site only)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--purge-missing",
            action="store_true",
            default=False,
            help="Remove OAuth providers whose env credentials are empty. "
            "Without this flag, providers configured via admin UI are preserved.",
        )
        parser.add_argument(
            "--site-id",
            type=int,
            help=(
                "ID of the django.contrib.sites Site to attach SocialApps to. "
                "If omitted and multiple sites exist, the command will abort and "
                "ask for an explicit --site-id."
            ),
        )

    def handle(self, *args, **options):
        site_id = options.get("site_id")

        if site_id is not None:
            try:
                site = Site.objects.get(pk=site_id)
            except Site.DoesNotExist as e:
                raise CommandError(f"Site with id={site_id} does not exist.") from e
        else:
            site_count = Site.objects.count()
            if site_count == 0:
                raise CommandError("No Site instances are configured. Please create a Site first.")
            if site_count > 1:
                raise CommandError(
                    "Multiple Site instances are configured. Please specify which one to configure using --site-id."
                )
            site = Site.objects.get_current()

        self.stdout.write(f"Setting up OAuth for site: {site.domain}")

        providers = {
            "google": {
                "name": "Google",
                "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip(),
                "secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
            },
            "github": {
                "name": "GitHub",
                "client_id": os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip(),
                "secret": os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip(),
            },
            "microsoft": {
                "name": "Microsoft",
                "client_id": os.getenv("MICROSOFT_OAUTH_CLIENT_ID", "").strip(),
                "secret": os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET", "").strip(),
            },
            "gitlab": {
                "name": "GitLab",
                "client_id": os.getenv("GITLAB_OAUTH_CLIENT_ID", "").strip(),
                "secret": os.getenv("GITLAB_OAUTH_CLIENT_SECRET", "").strip(),
            },
        }

        for provider_id, config in providers.items():
            if config["client_id"] and config["secret"]:
                # Lookup by provider only (sites is M2M and unreliable as a
                # lookup key in update_or_create). Site association is managed
                # separately via app.sites.add().
                app, created = SocialApp.objects.update_or_create(
                    provider=provider_id,
                    defaults={
                        "name": config["name"],
                        "client_id": config["client_id"],
                        "secret": config["secret"],
                    },
                )
                app.sites.add(site)

                action = "Created" if created else "Updated"
                self.stdout.write(self.style.SUCCESS(f"{action} {config['name']} OAuth provider"))
            elif options["purge_missing"]:
                # Only remove when --purge-missing is explicitly passed
                deleted_count, _ = SocialApp.objects.filter(provider=provider_id, sites=site).delete()
                if deleted_count:
                    self.stdout.write(self.style.WARNING(f"Removed {config['name']} (no credentials, --purge-missing)"))

        self.stdout.write(self.style.SUCCESS("OAuth setup complete!"))
