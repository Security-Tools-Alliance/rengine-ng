"""
Endpoint Repository - Data access for endpoint operations.
Handles EndPoint database operations with enriched Secator integration.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.utils import timezone

from reNgine.core.validators import is_valid_domain, is_valid_url
from startScan.models import EndPoint, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


logger = get_task_logger(__name__)


class EndpointRepository:
    """Repository for endpoint-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[EndPoint]:
        """
        Save endpoint from Secator result with enriched data.

        Args:
            item: Secator URL item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            EndPoint: Saved endpoint object or None
        """
        try:
            return self._process_secator_endpoint_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving endpoint: {e}", exc_info=True)
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving endpoint: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Error saving endpoint from Secator: {e}", exc_info=True)
            logger.error(f"Endpoint item data: {item}")
            return None

    def _process_secator_endpoint_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[EndPoint]:
        # Extract URL from Secator Url type (always uses 'url' field)
        http_url = item.get("url")

        if not http_url:
            logger.warning(f"Endpoint item missing URL field. Available fields: {list(item.keys())}")
            return None

        if not is_valid_url(http_url):
            logger.warning(f"Invalid URL: {http_url}")
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        # Prepare enriched defaults with all Secator URL fields
        defaults = {
            "target_domain": domain,
            "http_status": item.get("status_code") or item.get("status") or 0,
            "content_length": item.get("content_length", 0),
            "page_title": item.get("title", ""),
            "content_type": item.get("content_type", ""),
            "webserver": item.get("webserver", ""),
            "discovered_date": timezone.now(),
        }

        if response_time := item.get("time"):
            if isinstance(response_time, str) and response_time.endswith("ms"):
                try:
                    response_time = float(response_time[:-2]) / 1000.0
                except ValueError:
                    response_time = None
            elif isinstance(response_time, (int, float)):
                # Assume it's already in seconds if numeric
                response_time = float(response_time)
            else:
                response_time = None

            if response_time is not None:
                defaults["response_time"] = response_time

        # Add method, words, lines, and headers fields
        defaults["method"] = item.get("method", "")
        defaults["words"] = item.get("words", 0)
        defaults["lines"] = item.get("lines", 0)

        # Combine response_headers and request_headers into headers JSONField
        headers_dict = {}
        if "response_headers" in item:
            headers_dict["response"] = item["response_headers"]
        if "request_headers" in item:
            headers_dict["request"] = item["request_headers"]
        if headers_dict:
            defaults["headers"] = headers_dict

        # Add screenshot path if available
        if "screenshot_path" in item:
            defaults["screenshot_path"] = item["screenshot_path"]
        # Note: stored_response_path is not stored as EndPoint model doesn't have this field

        endpoint, created = EndPoint.objects.get_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults=defaults,
        )

        # Associate with subdomain if hostname can be extracted
        self._associate_with_subdomain(endpoint, http_url, scan_history_id)

        # Mark as default if this is the first endpoint for the subdomain
        self._mark_as_default_if_first(endpoint)

        # Associate with technologies if available
        self._associate_technologies(endpoint, item)

        if created:
            logger.info(f"Created endpoint: {http_url}")
        else:
            logger.debug(f"Endpoint already exists: {http_url}")

        return endpoint

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
            } | kwargs
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
            return self._create_endpoints_in_bulk(scan_history_id, domain_id, endpoints)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create endpoints: {e}")
            return []

    def _create_endpoints_in_bulk(
        self, scan_history_id: int, domain_id: int, endpoints: List[Dict[str, Any]]
    ) -> List[EndPoint]:
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

    def _associate_with_subdomain(self, endpoint: EndPoint, http_url: str, scan_history_id: int) -> None:
        """
        Associate endpoint with subdomain based on URL hostname.

        Args:
            endpoint: Endpoint object
            http_url: Endpoint URL
            scan_history_id: Scan history ID
        """
        try:
            hostname = urlparse(http_url).hostname
            if hostname and is_valid_domain(hostname):
                if subdomain := Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first():
                    endpoint.subdomain = subdomain
                    endpoint.save(update_fields=["subdomain"])
                    logger.debug(f"Associated endpoint {http_url} with subdomain {hostname}")
                else:
                    logger.debug(f"Subdomain {hostname} not found in scan {scan_history_id}")

        except Exception as e:
            logger.error(f"Error associating endpoint with subdomain: {e}")

    def _mark_as_default_if_first(self, endpoint: EndPoint) -> None:
        """
        Mark endpoint as default if it's the first endpoint for the subdomain.
        Only one default endpoint per subdomain is allowed.
        Uses database locking to prevent race conditions in concurrent scenarios.

        Args:
            endpoint: Endpoint object
        """
        try:
            if not endpoint.subdomain:
                logger.debug(f"Endpoint {endpoint.http_url} has no subdomain, skipping default marking")
                return

            # Use transaction with select_for_update to prevent race conditions
            # This ensures only one thread can mark an endpoint as default at a time
            with transaction.atomic():
                # Lock endpoints for this subdomain by fetching them with select_for_update
                # This prevents concurrent threads from checking/modifying at the same time
                list(EndPoint.objects.filter(subdomain=endpoint.subdomain).exclude(id=endpoint.id).select_for_update())

                if (
                    EndPoint.objects.filter(subdomain=endpoint.subdomain, is_default=True)
                    .exclude(id=endpoint.id)
                    .exists()
                ):
                    logger.debug(
                        f"Default endpoint already exists for subdomain {endpoint.subdomain.name}, "
                        f"not marking {endpoint.http_url} as default"
                    )

                else:
                    # Check if this is the first endpoint for this subdomain
                    # Exclude current endpoint from count to check if it's truly the first
                    endpoint_count = (
                        EndPoint.objects.filter(subdomain=endpoint.subdomain).exclude(id=endpoint.id).count()
                    )

                    if endpoint_count == 0:  # This is the first endpoint
                        # Refresh endpoint from DB to ensure we have latest data
                        endpoint.refresh_from_db()
                        endpoint.is_default = True
                        endpoint.save(update_fields=["is_default"])
                        logger.info(
                            f"Marked endpoint {endpoint.http_url} as default for subdomain {endpoint.subdomain.name}"
                        )
                    else:
                        logger.debug(
                            f"Endpoint {endpoint.http_url} is not the first for subdomain {endpoint.subdomain.name} "
                            f"(count: {endpoint_count})"
                        )
        except Exception as e:
            logger.error(f"Error marking endpoint as default: {e}", exc_info=True)
            # Don't raise the exception - just log it to avoid breaking the save process

    def _associate_technologies(self, endpoint: EndPoint, item: Dict[str, Any]) -> None:
        """
        Associate technologies with endpoint.

        Args:
            endpoint: Endpoint object
            item: Secator item
        """
        try:
            # Check if there are technologies in the 'tech' field
            technologies = item.get("tech", [])

            if not technologies or not isinstance(technologies, list):
                return

            for tech_name in technologies:
                if tech_name and isinstance(tech_name, str):
                    tech_obj, _ = Technology.objects.get_or_create(name=tech_name.strip())
                    endpoint.techs.add(tech_obj)
                    logger.debug(f"Associated technology {tech_name} with endpoint {endpoint.http_url}")

        except Exception as e:
            logger.error(f"Error associating technologies with endpoint: {e}")

    def extract_technologies_from_list(self, tech_list: List[str]) -> List[Technology]:
        """
        Extract and create technologies from a list of technology names.

        Args:
            tech_list: List of technology names

        Returns:
            list: List of Technology objects
        """
        try:
            technologies = []
            for tech_name in tech_list:
                if tech_name and tech_name.strip():
                    tech_obj, _ = Technology.objects.get_or_create(name=tech_name.strip())
                    technologies.append(tech_obj)

            return technologies

        except Exception as e:
            logger.error(f"Error extracting technologies from list: {e}")
            return []
