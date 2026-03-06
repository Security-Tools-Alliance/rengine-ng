"""
Subdomain Repository - Data access for subdomain operations.
Handles Subdomain database operations with enriched Secator integration.
"""

import contextlib
from typing import Any, Dict, Optional

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.utils import timezone

from reNgine.core.validators import is_valid_domain, is_valid_ip
from reNgine.utilities.domain import get_domain_by_id, resolve_domain_for_scan
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import Domain, IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Target


PREFIX_SUBDOMAIN_REPO = "[SUBDOMAIN_REPO]"
logger = get_module_logger(__name__)


class SubdomainRepository:
    """Repository for subdomain-related database operations."""

    def save_from_secator(
        self, item: Dict[str, Any], scan_history_id: int, target_id: int, rengine_context: Dict[str, Any] = None
    ) -> Optional[Subdomain]:
        """
        Save subdomain from Secator result with enriched data.

        Args:
            item: Secator subdomain item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional reNgine context with imported_subdomains, etc.

        Returns:
            Subdomain: Saved subdomain object or None
        """
        try:
            return self._process_secator_subdomain_item(item, scan_history_id, target_id, rengine_context)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Object not found when saving subdomain: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Integrity error saving subdomain: %s" % (e,),
                level="error",
            )
            return None
        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Error saving subdomain from Secator: %s" % (e,),
                level="error",
            )
            return None

    def _process_secator_subdomain_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Dict[str, Any] = None,
    ) -> Optional[Subdomain]:
        subdomain_name = item.get("host") or item.get("target") or item.get("name")

        if not subdomain_name:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Subdomain item missing name field",
                level="warning",
            )
            return None

        if not is_acceptable_subdomain_name(subdomain_name):
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Invalid subdomain: %s" % (subdomain_name,),
                level="warning",
            )
            return None

        subdomain = self.get_or_create_from_host(scan_history_id, target_id, subdomain_name)
        if not subdomain:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "SAVE",
                "Could not get or create subdomain for target_id=%s, subdomain=%s" % (target_id, subdomain_name),
                level="warning",
            )
            return None

        is_imported = self._is_imported_subdomain(subdomain_name, rengine_context or {})

        update_fields = []
        if item.get("verified", False) != subdomain.verified:
            subdomain.verified = item.get("verified", False)
            update_fields.append("verified")
        sources = item.get("sources", [])
        if sources != (subdomain.sources or []):
            subdomain.sources = sources
            update_fields.append("sources")
        if is_imported and not subdomain.is_imported_subdomain:
            subdomain.is_imported_subdomain = True
            update_fields.append("is_imported_subdomain")

        extra_data = item.get("extra_data", {}) or {}
        if extra_data:
            defaults: Dict[str, Any] = {}
            self._map_extra_data_to_subdomain_fields(extra_data, defaults)
            for key, value in defaults.items():
                if getattr(subdomain, key, None) != value:
                    setattr(subdomain, key, value)
                    update_fields.append(key)

        if update_fields:
            subdomain.save(update_fields=list(dict.fromkeys(update_fields)))

        self._associate_ip_addresses(subdomain, item, scan_history_id)
        self._associate_technologies(subdomain, item)

        logger.log_line(
            PREFIX_SUBDOMAIN_REPO,
            "SAVE",
            "Saved subdomain: %s (imported: %s)" % (subdomain.name, is_imported),
            level="info",
        )

        rengine_context = rengine_context or {}
        if subscan_id := rengine_context.get("subscan_id"):
            from startScan.models import SubScan

            with contextlib.suppress(SubScan.DoesNotExist):
                subscan = SubScan.objects.get(id=subscan_id)
                subscan.subdomain_subscan_ids.add(subdomain)
        return subdomain

    def _resolve_domain_for_subdomain(
        self, scan_history_id: int, target_id: int, subdomain_name: str
    ) -> Optional[Domain]:
        """Resolve Domain for this scan and subdomain using TLD extraction."""
        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        return resolve_domain_for_scan(scan_history_id, subdomain_name, target_value, create=True)

    def get_or_create_from_host(self, scan_history_id: int, target_id: int, hostname: str) -> Optional[Subdomain]:
        """
        Get or create a Subdomain for the given scan and host (hostname or IP).

        Single entry point for "obtain subdomain for this host" used by Endpoint, Ip, Port,
        Record, Certificate, and Vulnerability repositories. Uses is_acceptable_subdomain_name
        (accepts FQDNs, .lan/.local, and IPs).

        Returns:
            Subdomain or None if hostname is empty, invalid, or domain resolution fails.
        """
        if not hostname or not isinstance(hostname, str):
            return None
        normalized = hostname.strip().lower()
        if not normalized:
            return None
        if not is_acceptable_subdomain_name(normalized):
            return None
        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = resolve_domain_for_scan(scan_history_id, normalized, target_value, create=True)
        if not domain:
            return None
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
        except ObjectDoesNotExist:
            return None
        defaults = {
            "domain": domain,
            "is_imported_subdomain": False,
            "discovered_date": timezone.now(),
        }
        subdomain, _ = Subdomain.objects.get_or_create(
            name=normalized,
            scan_history=scan_history,
            defaults=defaults,
        )
        return subdomain

    def _map_extra_data_to_subdomain_fields(self, extra_data: Dict[str, Any], defaults: Dict[str, Any]) -> None:
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
        if "cname" in extra_data:
            defaults["cname"] = extra_data["cname"]
        if "is_cdn" in extra_data:
            defaults["is_cdn"] = extra_data["is_cdn"]
        if "cdn_name" in extra_data:
            defaults["cdn_name"] = extra_data["cdn_name"]
        if "http_header_path" in extra_data:
            defaults["http_header_path"] = extra_data["http_header_path"]

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
            domain = get_domain_by_id(domain_id)
            if domain is None:
                return None, False

            defaults = {
                "domain": domain,
                "is_imported_subdomain": False,
            } | kwargs
            subdomain, created = Subdomain.objects.get_or_create(
                name=name, scan_history=scan_history, defaults=defaults
            )

            return subdomain, created

        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "GET_OR_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return None, False
        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create subdomain: %s" % (e,),
                level="error",
            )
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
            domain = get_domain_by_id(domain_id)
            if domain is None:
                return []

            if subdomain_objects := [
                Subdomain(
                    name=name,
                    scan_history=scan_history,
                    domain=domain,
                    is_imported_subdomain=False,
                )
                for name in subdomains
                if is_valid_domain(name)
            ]:
                created = Subdomain.objects.bulk_create(subdomain_objects, ignore_conflicts=True)
                logger.log_line(
                    PREFIX_SUBDOMAIN_REPO,
                    "BULK_CREATE",
                    "Bulk created %s subdomains" % (len(created),),
                    level="info",
                )
                return created

            return []

        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "BULK_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return []
        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "BULK_CREATE",
                "Error in bulk create subdomains: %s" % (e,),
                level="error",
            )
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
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "UPDATE",
                "Subdomain with ID %s not found" % (subdomain_id,),
                level="error",
            )
            return False
        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "UPDATE",
                "Error updating subdomain HTTP URL: %s" % (e,),
                level="error",
            )
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
        Associate IP addresses with subdomain and ensure an endpoint exists for each IP.
        Endpoint creation is idempotent (get_or_create); we avoid duplicate calls for
        the same (ip, scan_history_id, domain_id) within this run via a local cache.
        """
        try:
            extra_data = item.get("extra_data", {})
            ip_addresses = extra_data.get("ip_addresses", [])

            if not ip_addresses and isinstance(ip_addresses, list):
                return

            from reNgine.services.repositories.endpoint_repository import EndpointRepository

            endpoint_repo = EndpointRepository()
            created_endpoints_cache: set[tuple[str, int, int]] = set()
            sid = subdomain.scan_history_id
            did = subdomain.domain_id

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
                    logger.log_line(
                        PREFIX_SUBDOMAIN_REPO,
                        "ASSOCIATE",
                        "Associated IP %s with subdomain %s" % (ip_address, subdomain.name),
                        level="debug",
                    )
                    cache_key = (ip_address, sid, did)
                    if cache_key not in created_endpoints_cache:
                        endpoint_repo.create_endpoint_for_ip(ip_address, sid, did)
                        created_endpoints_cache.add(cache_key)

        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "ASSOCIATE",
                "Error associating IP addresses with subdomain: %s" % (e,),
                level="error",
            )

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
                    logger.log_line(
                        PREFIX_SUBDOMAIN_REPO,
                        "ASSOCIATE",
                        "Associated technology %s with subdomain %s" % (tech_name, subdomain.name),
                        level="debug",
                    )

        except Exception as e:
            logger.log_line(
                PREFIX_SUBDOMAIN_REPO,
                "ASSOCIATE",
                "Error associating technologies with subdomain: %s" % (e,),
                level="error",
            )

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
