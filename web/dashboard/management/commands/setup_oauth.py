"""
Management command to setup OAuth providers from environment variables
"""
import os
from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp


class Command(BaseCommand):
    help = 'Setup OAuth providers from environment variables'

    def handle(self, *args, **options):
        site = Site.objects.get_current()
        self.stdout.write(f'Setting up OAuth for site: {site.domain}')
        
        providers = {
            'google': {
                'name': 'Google',
                'client_id': os.getenv('GOOGLE_OAUTH_CLIENT_ID', ''),
                'secret': os.getenv('GOOGLE_OAUTH_CLIENT_SECRET', ''),
            },
            'github': {
                'name': 'GitHub',
                'client_id': os.getenv('GITHUB_OAUTH_CLIENT_ID', ''),
                'secret': os.getenv('GITHUB_OAUTH_CLIENT_SECRET', ''),
            },
            'microsoft': {
                'name': 'Microsoft',
                'client_id': os.getenv('MICROSOFT_OAUTH_CLIENT_ID', ''),
                'secret': os.getenv('MICROSOFT_OAUTH_CLIENT_SECRET', ''),
            },
            'gitlab': {
                'name': 'GitLab',
                'client_id': os.getenv('GITLAB_OAUTH_CLIENT_ID', ''),
                'secret': os.getenv('GITLAB_OAUTH_CLIENT_SECRET', ''),
            },
        }
        
        for provider_id, config in providers.items():
            if config['client_id'] and config['secret']:
                app, created = SocialApp.objects.update_or_create(
                    provider=provider_id,
                    defaults={
                        'name': config['name'],
                        'client_id': config['client_id'],
                        'secret': config['secret'],
                    }
                )
                app.sites.add(site)
                
                action = 'Created' if created else 'Updated'
                self.stdout.write(
                    self.style.SUCCESS(f'{action} {config["name"]} OAuth provider')
                )
            else:
                # Remove if exists but no credentials
                deleted_count, _ = SocialApp.objects.filter(provider=provider_id).delete()
                if deleted_count:
                    self.stdout.write(
                        self.style.WARNING(f'Removed {config["name"]} (no credentials)')
                    )
        
        self.stdout.write(self.style.SUCCESS('OAuth setup complete!'))
