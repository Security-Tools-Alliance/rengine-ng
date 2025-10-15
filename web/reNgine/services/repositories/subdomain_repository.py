"""
Subdomain Repository - Data access for subdomain operations.
Handles Subdomain database operations.
"""

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_domain
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_task_logger(__name__)


class SubdomainRepository:
    """Repository for subdomain-related database operations."""

    def save_from_secator(self, item, scan_history_id, domain_id):
        """
        Save subdomain from Secator result.

        Args:
            item: Secator subdomain item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            Subdomain: Saved subdomain object or None
        """
        try:
            subdomain_name = item.get("host") or item.get("target") or item.get("name")

            if not subdomain_name:
                logger.warning("Subdomain item missing name field")
                return None

            if not is_valid_domain(subdomain_name):
                logger.warning(f"Invalid subdomain: {subdomain_name}")
                return None

            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            subdomain, created = Subdomain.objects.get_or_create(
                name=subdomain_name,
                scan_history=scan_history,
                defaults={
                    "target_domain": domain,
                    "is_imported_subdomain": False,
                },
            )

            if created:
                logger.info(f"Created subdomain: {subdomain_name}")
            else:
                logger.debug(f"Subdomain already exists: {subdomain_name}")

            return subdomain

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving subdomain: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving subdomain: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving subdomain from Secator: {e}")
            return None

    def get_or_create(self, name, scan_history_id, domain_id, **kwargs):
        """
        Get or create a subdomain.

        Args:
            name: Subdomain name
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            **kwargs: Additional fields

        Returns:
            tuple: (Subdomain, created boolean) or (None, False)
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            defaults = {
                "target_domain": domain,
                "is_imported_subdomain": False,
            }
            defaults.update(kwargs)

            subdomain, created = Subdomain.objects.get_or_create(
                name=name, scan_history=scan_history, defaults=defaults
            )

            return subdomain, created

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return None, False
        except Exception as e:
            logger.error(f"Error in get_or_create subdomain: {e}")
            return None, False

    def bulk_create(self, subdomains, scan_history_id, domain_id):
        """
        Bulk create subdomains.

        Args:
            subdomains: List of subdomain names
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created Subdomain objects
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            subdomain_objects = []
            for name in subdomains:
                if is_valid_domain(name):
                    subdomain_objects.append(
                        Subdomain(
                            name=name, scan_history=scan_history, target_domain=domain, is_imported_subdomain=False
                        )
                    )

            if subdomain_objects:
                created = Subdomain.objects.bulk_create(subdomain_objects, ignore_conflicts=True)
                logger.info(f"Bulk created {len(created)} subdomains")
                return created

            return []

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create subdomains: {e}")
            return []

    def update_http_url(self, subdomain_id, http_url):
        """
        Update HTTP URL for a subdomain.

        Args:
            subdomain_id: ID of the subdomain
            http_url: HTTP URL to set

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            subdomain = Subdomain.objects.get(id=subdomain_id)
            subdomain.http_url = http_url
            subdomain.save(update_fields=["http_url"])
            return True
        except ObjectDoesNotExist:
            logger.error(f"Subdomain with ID {subdomain_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating subdomain HTTP URL: {e}")
            return False
