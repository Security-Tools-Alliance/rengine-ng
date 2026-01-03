"""
Certificate Repository - Data access for certificate operations.
Handles Certificate database operations from Secator Certificate output type.
"""

import contextlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from startScan.models import Certificate, IpAddress, ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_task_logger(__name__)


class CertificateRepository:
    """Repository for certificate-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[Certificate]:
        """
        Save certificate from Secator certificate result.

        Args:
            item: Secator certificate item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            Certificate: Saved certificate object or None
        """
        try:
            return self._process_secator_certificate_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving certificate: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving certificate: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving certificate from Secator: {e}")
            return None

    def _process_secator_certificate_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[Certificate]:
        host = item.get("host")
        fingerprint_sha256 = item.get("fingerprint_sha256", "")

        if not host:
            logger.warning("Certificate item missing host field")
            return None

        # Validate scan_history and domain exist
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        # Parse datetime fields
        not_before = self._parse_datetime(item.get("not_before"))
        not_after = self._parse_datetime(item.get("not_after"))

        # Get or create subdomain if host is provided
        subdomain = None
        if host:
            with contextlib.suppress(Exception):
                subdomain = Subdomain.objects.filter(name=host, target_domain=domain).first()
        # Get or create IP address if ip is provided
        ip_address = None
        ip_str = item.get("ip", "")
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

        # Get or create certificate
        certificate, created = Certificate.objects.get_or_create(
            host=host, fingerprint_sha256=fingerprint_sha256, scan_history=scan_history, defaults=defaults
        )

        if not created:
            # Update existing certificate
            for key, value in defaults.items():
                setattr(certificate, key, value)
            certificate.save()

        if created:
            logger.info(f"Created certificate: {host} - {certificate.subject_cn or 'N/A'}")
        else:
            logger.debug(f"Updated certificate: {host} - {certificate.subject_cn or 'N/A'}")

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
            # If datetime is naive, make it aware using UTC (Django best practice with USE_TZ=True)
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value

        if isinstance(value, str):
            try:
                # Try ISO format - fromisoformat returns aware datetime if timezone info is present
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                # If parsed datetime is naive, make it aware using UTC
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except Exception:
                with contextlib.suppress(Exception):
                    # Try common formats - strptime returns naive datetime
                    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y"]:
                        try:
                            parsed = datetime.strptime(value, fmt)
                            # Make naive datetime aware using UTC (Django best practice)
                            return parsed.replace(tzinfo=timezone.utc)
                        except ValueError:
                            continue
        if isinstance(value, (int, float)):
            with contextlib.suppress(Exception):
                # Handle both seconds and milliseconds timestamps
                # If value is very large (> year 2100 in seconds), assume milliseconds
                if value > 4102444800:  # Year 2100 in seconds
                    value = value / 1000
                return datetime.fromtimestamp(value, tz=timezone.utc)
        return None
