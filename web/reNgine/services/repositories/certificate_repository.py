"""
Certificate Repository - Data access for certificate operations.
Handles Certificate database operations from Secator Certificate output type.
"""

import contextlib
from datetime import datetime
from datetime import timezone as dt_timezone
from typing import Any, Dict, Optional

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.domain import get_or_create_domain_for_target
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.time import ensure_timezone_aware, parse_datetime_iso
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import Certificate, IpAddress, ScanHistory, Subdomain


PREFIX_CERT_REPO = "[CERT_REPO]"
logger = get_module_logger(__name__)


class CertificateRepository:
    """Repository for certificate-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Certificate]:
        """
        Save certificate from Secator certificate result.

        Args:
            item: Secator certificate item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (unused)

        Returns:
            Certificate: Saved certificate object or None
        """
        try:
            return self._process_secator_certificate_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Object not found when saving certificate: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Integrity error saving certificate: %s" % (e,),
                level="error",
            )
            return None
        except Exception as e:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Error saving certificate from Secator: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return None

    def _process_secator_certificate_item(
        self, item: Dict[str, Any], scan_history_id: int, target_id: int
    ) -> Optional[Certificate]:
        host = item.get("host")
        fingerprint_sha256 = item.get("fingerprint_sha256", "")

        host = host or ""
        ip_str = item.get("ip", "")
        host_or_ip = host or ip_str
        if not host_or_ip:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Certificate item missing host and ip fields",
                level="warning",
            )
            return None

        domain = get_or_create_domain_for_target(scan_history_id, host_or_ip) if host_or_ip else None
        if not domain:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Could not resolve domain for target_id=%s, host=%s" % (target_id, host_or_ip),
                level="warning",
            )
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)

        # Parse datetime fields
        not_before = self._parse_datetime(item.get("not_before"))
        not_after = self._parse_datetime(item.get("not_after"))

        subdomain = None
        if host_or_ip and is_acceptable_subdomain_name(host_or_ip):
            subdomain = SubdomainRepository().get_or_create_from_host(scan_history_id, target_id, host_or_ip)
        if not subdomain and host:
            with contextlib.suppress(Exception):
                subdomain = Subdomain.objects.filter(name=host.strip().lower(), domain=domain).first()
        # Get or create IP address if ip is provided
        ip_address = None
        if ip_str:
            with contextlib.suppress(Exception):
                # IpAddress doesn't have a domain field, search by address only
                ip_address = IpAddress.objects.filter(address=ip_str).first()
        # Prepare defaults
        defaults = {
            "scan_history": scan_history,
            "subdomain": subdomain,
            "ip_address": ip_address,
            "domain": domain,
            "fingerprint_sha256": fingerprint_sha256,
            "ip": ip_str,
            "raw_value": item.get("raw_value", ""),
            "subject_cn": item.get("subject_cn", ""),
            "subject_an": item.get("subject_an", []),
            "not_before": not_before,
            "not_after": not_after,
            "issuer_dn": item.get("issuer_dn", ""),
            "issuer_cn": item.get("issuer_cn", ""),
            "issuer": item.get("issuer", ""),
            "self_signed": item.get("self_signed", False),
            "trusted": item.get("trusted", False),
            "status": item.get("status", ""),
            "keysize": item.get("keysize"),
            "serial_number": item.get("serial_number", ""),
            "ciphers": item.get("ciphers", []),
        }

        # Get or create certificate (use host_or_ip when host is empty so IP-only certs work)
        certificate, created = Certificate.objects.get_or_create(
            host=host_or_ip, fingerprint_sha256=fingerprint_sha256, scan_history=scan_history, defaults=defaults
        )

        if not created:
            # Update existing certificate
            for key, value in defaults.items():
                setattr(certificate, key, value)
            certificate.save()

        if created:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Created certificate: %s - %s" % (host_or_ip, certificate.subject_cn or "N/A"),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_CERT_REPO,
                "SAVE",
                "Updated certificate: %s - %s" % (host, certificate.subject_cn or "N/A"),
                level="debug",
            )

        return certificate

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        """
        Parse datetime value from Secator.

        Args:
            value: Datetime value (can be datetime, string, timestamp, or None)

        Returns:
            datetime or None
        """
        if value is None:
            return None

        if isinstance(value, datetime):
            # Ensure datetime is timezone-aware
            return ensure_timezone_aware(value)

        if isinstance(value, str):
            # Try ISO format first using utility function
            parsed = parse_datetime_iso(value)
            if parsed is not None:
                return parsed

            # Try common formats - strptime returns naive datetime
            with contextlib.suppress(Exception):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y"]:
                    try:
                        parsed = datetime.strptime(value, fmt)
                        # Make naive datetime aware using UTC
                        return ensure_timezone_aware(parsed)
                    except ValueError:
                        continue

        if isinstance(value, (int, float)):
            with contextlib.suppress(Exception):
                # Handle both seconds and milliseconds timestamps
                # If value is very large (> year 2100 in seconds), assume milliseconds
                if value > 4102444800:  # Year 2100 in seconds
                    value = value / 1000
                return datetime.fromtimestamp(value, tz=dt_timezone.utc)

        return None
