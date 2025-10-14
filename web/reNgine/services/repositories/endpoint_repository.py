"""
Endpoint Repository - Data access for endpoint operations.
Handles EndPoint database operations.
"""

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_url
from startScan.models import EndPoint, ScanHistory
from targetApp.models import Domain


logger = get_task_logger(__name__)


class EndpointRepository:
    """Repository for endpoint-related database operations."""

    def save_from_secator(self, item, scan_history_id, domain_id):
        """
        Save endpoint from Secator result.

        Args:
            item: Secator URL item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            EndPoint: Saved endpoint object or None
        """
        try:
            http_url = item.get("url") or item.get("target")

            if not http_url:
                logger.warning("Endpoint item missing URL field")
                return None

            if not is_valid_url(http_url):
                logger.warning(f"Invalid URL: {http_url}")
                return None

            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            http_status = item.get("status_code") or item.get("status") or 0

            endpoint, created = EndPoint.objects.get_or_create(
                http_url=http_url,
                scan_history=scan_history,
                defaults={
                    "target_domain": domain,
                    "http_status": http_status,
                    "content_length": item.get("content_length", 0),
                    "page_title": item.get("title", ""),
                    "content_type": item.get("content_type", ""),
                },
            )

            if created:
                logger.info(f"Created endpoint: {http_url}")
            else:
                logger.debug(f"Endpoint already exists: {http_url}")

            return endpoint

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving endpoint: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving endpoint: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving endpoint from Secator: {e}")
            return None

    def get_or_create(self, http_url, scan_history_id, domain_id, **kwargs):
        """
        Get or create an endpoint.

        Args:
            http_url: Endpoint URL
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            **kwargs: Additional fields

        Returns:
            tuple: (EndPoint, created boolean) or (None, False)
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            defaults = {
                "target_domain": domain,
                "http_status": 0,
            }
            defaults.update(kwargs)

            endpoint, created = EndPoint.objects.get_or_create(
                http_url=http_url, scan_history=scan_history, defaults=defaults
            )

            return endpoint, created

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return None, False
        except Exception as e:
            logger.error(f"Error in get_or_create endpoint: {e}")
            return None, False

    def bulk_create(self, endpoints, scan_history_id, domain_id):
        """
        Bulk create endpoints.

        Args:
            endpoints: List of endpoint dictionaries
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created EndPoint objects
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)

            endpoint_objects = []
            for endpoint_data in endpoints:
                http_url = endpoint_data.get("http_url")
                if http_url and is_valid_url(http_url):
                    endpoint_objects.append(
                        EndPoint(
                            http_url=http_url,
                            scan_history=scan_history,
                            target_domain=domain,
                            http_status=endpoint_data.get("http_status", 0),
                            content_length=endpoint_data.get("content_length", 0),
                            page_title=endpoint_data.get("page_title", ""),
                        )
                    )

            if endpoint_objects:
                created = EndPoint.objects.bulk_create(endpoint_objects, ignore_conflicts=True)
                logger.info(f"Bulk created {len(created)} endpoints")
                return created

            return []

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create endpoints: {e}")
            return []

    def update_http_status(self, endpoint_id, http_status):
        """
        Update HTTP status for an endpoint.

        Args:
            endpoint_id: ID of the endpoint
            http_status: HTTP status code

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            endpoint = EndPoint.objects.get(id=endpoint_id)
            endpoint.http_status = http_status
            endpoint.save(update_fields=["http_status"])
            return True
        except ObjectDoesNotExist:
            logger.error(f"EndPoint with ID {endpoint_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating endpoint HTTP status: {e}")
            return False
