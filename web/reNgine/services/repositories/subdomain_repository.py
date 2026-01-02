"""
Subdomain Repository - Data access for subdomain operations.
Handles Subdomain database operations with enriched Secator integration.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_domain, is_valid_ip
from startScan.models import IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


logger = get_task_logger(__name__)


class SubdomainRepository:
    """Repository for subdomain-related database operations."""

    def save_from_secator(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int, rengine_context: Dict[str, Any] = None
    ) -> Optional[Subdomain]:
        """
        Save subdomain from Secator result with enriched data.

        Args:
            item: Secator subdomain item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional reNgine context with imported_subdomains, etc.

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

            # Check if this subdomain is in the imported list
            is_imported = self._is_imported_subdomain(subdomain_name, rengine_context or {})

            # Prepare enriched defaults
            defaults = {
                "target_domain": domain,
                "is_imported_subdomain": is_imported,
                "discovered_date": datetime.now(),
                "verified": item.get("verified", False),
                "sources": item.get("sources", []),
            }

            # Add extra data if available
            extra_data = item.get("extra_data", {})
            if extra_data:
                # Map common extra data fields to subdomain fields
                if "http_url" in extra_data:
                    defaults["http_url"] = extra_data["http_url"]
                if "http_status" in extra_data:
                    defaults["http_status"] = extra_data["http_status"]
                if "content_type" in extra_data:
                    defaults["content_type"] = extra_data["content_type"]
                if "content_length" in extra_data:
                    defaults["content_length"] = extra_data["content_length"]
                if "page_title" in extra_data:
                    defaults["page_title"] = extra_data["page_title"]
                if "webserver" in extra_data:
                    defaults["webserver"] = extra_data["webserver"]
                if "response_time" in extra_data:
                    defaults["response_time"] = extra_data["response_time"]

            subdomain, created = Subdomain.objects.get_or_create(
                name=subdomain_name,
                scan_history=scan_history,
                defaults=defaults,
            )

            # If subdomain already exists but we need to update the imported flag
            if not created and is_imported and not subdomain.is_imported_subdomain:
                subdomain.is_imported_subdomain = True
                subdomain.save(update_fields=["is_imported_subdomain"])
                logger.info(f"Updated subdomain {subdomain_name} as imported")

            # Associate with IP addresses if available
            self._associate_ip_addresses(subdomain, item, scan_history_id)

            # Associate with technologies if available
            self._associate_technologies(subdomain, item)

            if created:
                logger.info(f"Created subdomain: {subdomain_name} (imported: {is_imported})")
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

    def _is_imported_subdomain(self, subdomain_name, rengine_context):
        """
        Check if a subdomain is in the imported list.

        Args:
            subdomain_name: Name of the subdomain
            rengine_context: reNgine context with imported_subdomains list

        Returns:
            bool: True if subdomain is imported
        """
        imported_subdomains = rengine_context.get("imported_subdomains", [])
        if not imported_subdomains:
            return False

        # Clean and normalize the subdomain name
        subdomain_clean = subdomain_name.strip().lower()
        imported_clean = [s.strip().lower() for s in imported_subdomains if s and s.strip()]

        return subdomain_clean in imported_clean

    def _associate_ip_addresses(self, subdomain: Subdomain, item: Dict[str, Any], scan_history_id: int) -> None:
        """
        Associate IP addresses with subdomain.

        Args:
            subdomain: Subdomain object
            item: Secator item
            scan_history_id: Scan history ID
        """
        try:
            # Check if there are IP addresses in extra_data
            extra_data = item.get("extra_data", {})
            ip_addresses = extra_data.get("ip_addresses", [])

            if not ip_addresses and isinstance(ip_addresses, list):
                return

            for ip_address in ip_addresses:
                if is_valid_ip(ip_address):
                    ip_obj, _ = IpAddress.objects.get_or_create(
                        address=ip_address,
                        defaults={
                            "is_cdn": False,
                            "is_private": self._is_private_ip(ip_address),
                            "version": self._get_ip_version(ip_address),
                        },
                    )
                    subdomain.ip_addresses.add(ip_obj)
                    logger.debug(f"Associated IP {ip_address} with subdomain {subdomain.name}")

        except Exception as e:
            logger.error(f"Error associating IP addresses with subdomain: {e}")

    def _associate_technologies(self, subdomain: Subdomain, item: Dict[str, Any]) -> None:
        """
        Associate technologies with subdomain.

        Args:
            subdomain: Subdomain object
            item: Secator item
        """
        try:
            # Check if there are technologies in extra_data
            extra_data = item.get("extra_data", {})
            technologies = extra_data.get("technologies", [])

            if not technologies and isinstance(technologies, list):
                return

            for tech_name in technologies:
                if tech_name and isinstance(tech_name, str):
                    tech_obj, _ = Technology.objects.get_or_create(name=tech_name.strip())
                    subdomain.technologies.add(tech_obj)
                    logger.debug(f"Associated technology {tech_name} with subdomain {subdomain.name}")

        except Exception as e:
            logger.error(f"Error associating technologies with subdomain: {e}")

    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is private.

        Args:
            ip_address: IP address to check

        Returns:
            bool: True if private IP
        """
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private
        except (ValueError, ipaddress.AddressValueError):
            return False

    def _get_ip_version(self, ip_address: str) -> int:
        """
        Get IP version (4 or 6).

        Args:
            ip_address: IP address

        Returns:
            int: IP version (4 or 6)
        """
        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.version
        except (ValueError, ipaddress.AddressValueError):
            return 4  # Default to IPv4
