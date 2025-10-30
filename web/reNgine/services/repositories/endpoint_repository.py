"""
Endpoint Repository - Data access for endpoint operations.
Handles EndPoint database operations with enriched Secator integration.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

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
            http_url = item.get("url") or item.get("target")

            if not http_url:
                logger.warning("Endpoint item missing URL field")
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
                "discovered_date": datetime.now(),
            }

            # Convert response time from milliseconds to seconds if provided
            response_time = item.get("time")
            if response_time:
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

            # Add additional fields if available
            if "method" in item:
                # Store HTTP method in extra_data since it's not a direct field
                extra_data = {"method": item["method"]}
                if "words" in item:
                    extra_data["words"] = item["words"]
                if "lines" in item:
                    extra_data["lines"] = item["lines"]
                if "headers" in item:
                    extra_data["headers"] = item["headers"]
                defaults["extra_data"] = extra_data

            # Add screenshot and stored response paths if available
            if "screenshot_path" in item:
                defaults["screenshot_path"] = item["screenshot_path"]
            if "stored_response_path" in item:
                # Store in extra_data since it's not a direct field
                if "extra_data" not in defaults:
                    defaults["extra_data"] = {}
                defaults["extra_data"]["stored_response_path"] = item["stored_response_path"]

            endpoint, created = EndPoint.objects.get_or_create(
                http_url=http_url,
                scan_history=scan_history,
                defaults=defaults,
            )

            # Associate with subdomain if hostname can be extracted
            self._associate_with_subdomain(endpoint, http_url, scan_history_id)

            # Associate with technologies if available
            self._associate_technologies(endpoint, item)

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
                subdomain = Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first()

                if subdomain:
                    endpoint.subdomain = subdomain
                    endpoint.save(update_fields=["subdomain"])
                    logger.debug(f"Associated endpoint {http_url} with subdomain {hostname}")
                else:
                    logger.debug(f"Subdomain {hostname} not found in scan {scan_history_id}")

        except Exception as e:
            logger.error(f"Error associating endpoint with subdomain: {e}")

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
