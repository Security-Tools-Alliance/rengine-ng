"""
Domain Repository - Data access for domain information operations.
Handles DomainInfo database operations from Secator Domain output type.
"""

import contextlib
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.core.validators import is_valid_ip
from reNgine.utilities.domain import (
    get_domain_for_scan_by_name,
    get_or_create_domain_for_target,
    normalize_domain_name,
)
from reNgine.utilities.logger import format_exception_for_log, get_module_logger
from reNgine.utilities.time import ensure_timezone_aware, parse_datetime_iso
from startScan.models import (
    Domain,
    DomainInfo,
    DomainRegistration,
    NameServer,
    Registrar,
    WhoisStatus,
)
from targetApp.services.scope_params import get_finding_scope_filter_domain_for_target


PREFIX_DOMAIN_REPO = "[DOMAIN_REPO]"
logger = get_module_logger(__name__)


def _is_ip_address_label(normalized: str) -> bool:
    """True if normalized string is only a valid IPv4/IPv6 address (not a domain name)."""
    return bool(normalized) and is_valid_ip(normalized)


def _domain_scope_filter(rengine_context: Optional[Dict[str, Any]], target_id: int) -> Optional[Callable[[str], bool]]:
    """Resolve domain filter from context or from target_id."""
    if rengine_context:
        filters = rengine_context.get("finding_scope_filters") or {}
        fn = filters.get("domain_filter")
        if fn is not None and callable(fn):
            return fn
    return get_finding_scope_filter_domain_for_target(target_id)


class DomainRepository:
    """Repository for domain information-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DomainInfo]:
        """
        Save domain information from Secator Domain result.

        Args:
            item: Secator Domain item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (unused)

        Returns:
            DomainInfo: Saved domain info object or None
        """
        try:
            return self._process_secator_domain_item(item, scan_history_id, target_id, rengine_context=rengine_context)
        except FindingOutOfScopeError as e:
            reason = format_exception_for_log(e)
            domain_name = self._domain_string_from_item(item) or "?"
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Skipped (out of scope): domain=%s | %s scan_id=%s" % (domain_name, reason, scan_history_id),
                level="info",
            )
            return None
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Object not found when saving domain info: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Integrity error saving domain info: %s" % (e,),
                level="error",
            )
            return None
        except Exception as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Error saving domain info from Secator: %s" % (e,),
                level="error",
            )
            return None

    def save_raw_whois_from_secator_tag(
        self,
        scan_history_id: int,
        target_id: int,
        domain_name: str,
        raw_whois_text: str,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DomainInfo]:
        """
        Store raw WHOIS text from Secator jswhois tag in DomainInfo.extra_data["raw_whois"].

        Creates Domain and DomainInfo if needed. Does not populate structured WHOIS fields.
        """
        normalized = normalize_domain_name(domain_name) if domain_name else None
        if not normalized:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "raw_whois: empty domain name after normalization",
                level="warning",
            )
            return None
        if _is_ip_address_label(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "raw_whois: skipped, IP addresses are not stored as domains (%s)" % (normalized,),
                level="info",
            )
            return None
        scope_filter = _domain_scope_filter(rengine_context, target_id)
        if scope_filter is not None and not scope_filter(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "raw_whois: domain out of scope (restrict_findings_to_target)",
                level="debug",
            )
            raise FindingOutOfScopeError("Domain out of scope (restrict_findings_to_target)")
        domain = get_or_create_domain_for_target(scan_history_id, normalized)
        if not domain:
            return None
        domain_info, created = self._get_or_create_domain_info(domain)
        self._ensure_extra_data_initialized(domain_info)
        domain_info.extra_data["raw_whois"] = raw_whois_text
        domain_info.save()
        domain.domain_info = domain_info
        domain.save()
        return domain_info

    def save_asn_from_secator_tag(
        self,
        scan_history_id: int,
        target_id: int,
        domain_name: str,
        asn_value: str,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DomainInfo]:
        """
        Store ASN info from Secator getasn tag in DomainInfo.extra_data["asn"].

        Creates Domain and DomainInfo if needed. Used when getasn input is a host/domain.
        """
        normalized = normalize_domain_name(domain_name) if domain_name else None
        if not normalized:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "save_asn: empty domain name after normalization",
                level="warning",
            )
            return None
        if _is_ip_address_label(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "save_asn: skipped, IP addresses are not stored as domains (%s)" % (normalized,),
                level="info",
            )
            return None
        scope_filter = _domain_scope_filter(rengine_context, target_id)
        if scope_filter is not None and not scope_filter(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "save_asn: domain out of scope (restrict_findings_to_target)",
                level="debug",
            )
            raise FindingOutOfScopeError("Domain out of scope (restrict_findings_to_target)")
        domain = get_or_create_domain_for_target(scan_history_id, normalized)
        if not domain:
            return None
        domain_info, _ = self._get_or_create_domain_info(domain)
        self._ensure_extra_data_initialized(domain_info)
        domain_info.extra_data["asn"] = asn_value
        domain_info.save()
        domain.domain_info = domain_info
        domain.save()
        return domain_info

    def _process_secator_domain_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[DomainInfo]:
        domain_name, whois = self._validate_and_extract_domain_data(item)
        if not domain_name or not whois:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Domain item rejected: missing domain_name or whois data (domain_name=%s, has_whois=%s)"
                % (domain_name, whois is not None),
                level="warning",
            )
            return None

        normalized = normalize_domain_name(domain_name) if domain_name else None
        if not normalized:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Domain item rejected: failed to normalize domain_name",
                level="warning",
            )
            return None

        if _is_ip_address_label(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Domain item rejected: host is an IP address, not a domain name (%s)" % (normalized,),
                level="info",
            )
            return None

        scope_filter = _domain_scope_filter(rengine_context, target_id)
        if scope_filter is not None and not scope_filter(normalized):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Domain item out of scope (restrict_findings_to_target)",
                level="debug",
            )
            raise FindingOutOfScopeError("Domain out of scope (restrict_findings_to_target)")

        domain = get_domain_for_scan_by_name(scan_history_id, normalized)
        if not domain:
            domain = get_or_create_domain_for_target(scan_history_id, normalized)
        if not domain:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Domain item rejected: no existing domain matches (scan_history_id=%s, target_id=%s, domain_name=%s)"
                % (scan_history_id, target_id, normalized),
                level="warning",
            )
            return None

        domain_info, created = self._get_or_create_domain_info(domain)
        extra_data_internal = self._build_extra_data_internal_from_whois(whois)

        self._update_domain_info_dates(domain_info, item, whois, extra_data_internal)
        self._associate_registrar_and_registrant(domain_info, item, whois, extra_data_internal)
        self._associate_admin_and_tech_contacts(domain_info, extra_data_internal, domain)
        self._store_whois_payload(domain_info, whois, item)

        self._save_and_finalize_domain_info(domain_info, extra_data_internal, domain, normalized, created)

        return domain_info

    def _domain_string_from_item(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract domain name string from item; supports Secator Domain object or plain string."""
        raw = item.get("domain")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if isinstance(raw, dict):
            name = raw.get("domain") or raw.get("punycode")
            if isinstance(name, str) and name.strip():
                return name.strip()
            n = raw.get("name") or ""
            e = raw.get("extension") or ""
            if n or e:
                return ("%s.%s" % (n, e)).strip(".") or None
        return None

    def _validate_and_extract_domain_data(self, item: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Validate and extract domain name and WHOIS data from item."""
        domain_name = self._domain_string_from_item(item)
        if not domain_name:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "VALIDATE",
                "Domain item missing or invalid domain field",
                level="warning",
            )
            return None, None

        whois = (item.get("extra_data", {}) or {}).get("whois")
        if isinstance(whois, dict):
            return domain_name, whois

        if whois := self._build_whois_from_flat_item(item):
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "VALIDATE",
                "Using synthetic whois from flat whois-go style item for domain %s" % (domain_name,),
                level="debug",
            )
            return domain_name, whois

        logger.log_line(
            PREFIX_DOMAIN_REPO,
            "VALIDATE",
            "Domain item missing extra_data.whois and flat whois-go style fields for domain %s" % (domain_name,),
            level="warning",
        )
        return None, None

    def _get_or_create_domain_info(self, domain: Domain) -> Tuple[DomainInfo, bool]:
        """Get or create DomainInfo for domain."""
        if domain.domain_info:
            return domain.domain_info, False
        return DomainInfo(), True

    def _update_domain_info_dates(
        self, domain_info: DomainInfo, item: Dict[str, Any], whois: Dict[str, Any], extra_data_internal: Dict[str, Any]
    ) -> None:
        """Update domain info date fields."""
        whois_domain = whois.get("domain", {}) if isinstance(whois, dict) else {}
        creation_date_value = item.get("creation_date") or (
            whois_domain.get("creation_date") if isinstance(whois_domain, dict) else None
        )
        expiration_date_value = item.get("expiration_date") or (
            whois_domain.get("expiration_date") if isinstance(whois_domain, dict) else None
        )

        if creation_date := self._parse_datetime(creation_date_value):
            domain_info.created = creation_date
        if expiration_date := self._parse_datetime(expiration_date_value):
            domain_info.expires = expiration_date
        if last_update := self._parse_datetime(extra_data_internal.get("last_update")):
            domain_info.updated = last_update

    def _associate_registrar_and_registrant(
        self, domain_info: DomainInfo, item: Dict[str, Any], whois: Dict[str, Any], extra_data_internal: Dict[str, Any]
    ) -> None:
        """Associate registrar and registrant with domain info."""
        whois_domain = whois.get("domain", {}) if isinstance(whois, dict) else {}
        registrar_name = (
            item.get("registrar", "")
            or (whois_domain.get("registrar", "") if isinstance(whois_domain, dict) else "")
            or extra_data_internal.get("registrar_name", "")
        )

        if registrar_name and (registrar := self._get_or_create_registrar(registrar_name, extra_data_internal)):
            domain_info.registrar = registrar

        registrant_name = item.get("registrant", "") or extra_data_internal.get("registrant_name", "")
        if registrant_name and (registrant := self._get_or_create_registrant(registrant_name, extra_data_internal)):
            domain_info.registrant = registrant

    def _associate_admin_and_tech_contacts(
        self, domain_info: DomainInfo, extra_data_internal: Dict[str, Any], domain: Domain
    ) -> None:
        """Associate admin and tech contacts with domain info."""
        admin_c = extra_data_internal.get("admin_c", "")
        tech_c = extra_data_internal.get("tech_c", "")

        if admin_c and (admin := self._get_or_create_admin_tech(admin_c, extra_data_internal, "admin", domain)):
            domain_info.admin = admin

        if tech_c and (tech := self._get_or_create_admin_tech(tech_c, extra_data_internal, "tech", domain)):
            domain_info.tech = tech

    def _ensure_extra_data_initialized(self, domain_info: DomainInfo) -> None:
        """Ensure domain_info.extra_data is initialized as an empty dict if None."""
        if domain_info.extra_data is None:
            domain_info.extra_data = {}

    def _store_whois_payload(self, domain_info: DomainInfo, whois: Dict[str, Any], item: Dict[str, Any]) -> None:
        """Store full WHOIS payload in domain info extra_data."""
        self._ensure_extra_data_initialized(domain_info)
        domain_info.extra_data["whois"] = whois
        if "alive" in item:
            domain_info.extra_data["alive"] = item.get("alive")

    def _save_and_finalize_domain_info(
        self,
        domain_info: DomainInfo,
        extra_data_internal: Dict[str, Any],
        domain: Domain,
        domain_name: str,
        created: bool,
    ) -> None:
        """Save domain info and associate with domain."""
        domain_info.save()
        self._process_extra_data(domain_info, extra_data_internal)
        domain_info.save()

        domain.domain_info = domain_info
        domain.save()

        if created:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Created domain info for domain %s" % (domain_name,),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "SAVE",
                "Updated domain info for domain %s" % (domain_name,),
                level="debug",
            )

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
            return ensure_timezone_aware(value)

        if isinstance(value, str):
            # Try ISO format first
            parsed = parse_datetime_iso(value)
            if parsed is not None:
                return parsed

            # Try common formats
            with contextlib.suppress(Exception):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y"]:
                    try:
                        parsed = datetime.strptime(value, fmt)
                        return ensure_timezone_aware(parsed)
                    except ValueError:
                        continue

        if isinstance(value, (int, float)):
            with contextlib.suppress(Exception):
                # Handle both seconds and milliseconds timestamps
                if value > 4102444800:  # Year 2100 in seconds
                    value = value / 1000
                from datetime import timezone as dt_timezone

                return datetime.fromtimestamp(value, tz=dt_timezone.utc)

        return None

    def _get_or_create_registrar(self, registrar_name: str, extra_data: Dict[str, Any]) -> Optional[Registrar]:
        """
        Get or create registrar from name and extra_data.

        Args:
            registrar_name: Registrar name
            extra_data: Extra data containing registrar_info

        Returns:
            Registrar object or None
        """
        try:
            registrar_info = extra_data.get("registrar_info", {})
            defaults = self._build_registrar_defaults(registrar_info, registrar_name)
            registrar, created = Registrar.objects.get_or_create(name=registrar_name, defaults=defaults)

            if not created:
                address = self._parse_registrar_address(registrar_info.get("address", ""))
                self._update_registrar(registrar, registrar_info, address)

            return registrar

        except Exception as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "REGISTRAR",
                "Error getting or creating registrar: %s" % (e,),
                level="error",
            )
            return None

    def _parse_registrar_address(self, address: Any) -> str:
        """Parse address for Registrar (join list to string)."""
        if isinstance(address, list):
            return ", ".join(str(item) for item in address if item)
        if isinstance(address, str):
            return address
        return str(address) if address else ""

    def _build_registrar_defaults(self, registrar_info: Dict[str, Any], registrar_name: str) -> Dict[str, Any]:
        """Build defaults dictionary for Registrar creation."""
        address = self._parse_registrar_address(registrar_info.get("address", ""))
        return {
            "name": registrar_name,
            "phone": registrar_info.get("phone", ""),
            "email": registrar_info.get("e-mail", ""),
            "url": registrar_info.get("website", ""),
            "address": address,
            "country": registrar_info.get("country", ""),
            "fax": registrar_info.get("fax-no", ""),
        }

    def _update_registrar(self, registrar: Registrar, registrar_info: Dict[str, Any], address: str) -> bool:
        """Update existing Registrar with new information if available."""
        updated = False
        field_mappings = {
            "phone": registrar_info.get("phone", ""),
            "email": registrar_info.get("e-mail", ""),
            "url": registrar_info.get("website", ""),
            "address": address,
            "country": registrar_info.get("country", ""),
            "fax": registrar_info.get("fax-no", ""),
        }

        return self._update_object_fields_if_empty(field_mappings, registrar, updated)

    def _extract_nic_hdl_id(self, nic_hdl: Dict[str, Any]) -> Optional[str]:
        """Extract id_str (nic-hdl) from nic_hdl dictionary."""
        return nic_hdl.get("nic-hdl") or nic_hdl.get("id_str") or nic_hdl.get("id") or nic_hdl.get("nic_hdl")

    def _parse_address(self, address: Any) -> Dict[str, str]:
        """Parse address from list or string format into dictionary."""
        result = {}
        if isinstance(address, list) and len(address) > 0:
            result["address"] = address[0]
            if len(address) > 1:
                result["city"] = address[1]
            if len(address) > 2:
                if third := str(address[2]).strip():
                    if any(char.isdigit() for char in third):
                        result["zip_code"] = third
                    else:
                        result["state"] = third
        elif isinstance(address, str):
            result["address"] = address
        return result

    def _build_domain_registration_defaults(
        self, nic_hdl: Dict[str, Any], name: str, organization: str, nic_hdl_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Build defaults dictionary for DomainRegistration creation."""
        defaults = {
            "name": name,
            "organization": organization,
            "contact": nic_hdl.get("contact", ""),
            "type": nic_hdl.get("type", ""),
            "email": nic_hdl.get("e-mail", ""),
            "phone": nic_hdl.get("phone", ""),
            "country": nic_hdl.get("country", ""),
            "id_str": nic_hdl_id or nic_hdl.get("nic-hdl", ""),
            "fax": nic_hdl.get("fax-no") or nic_hdl.get("fax", ""),
        }
        defaults |= self._parse_address(nic_hdl.get("address", []))
        return defaults

    def _update_domain_registration(
        self, registration: DomainRegistration, nic_hdl: Dict[str, Any], name: str, nic_hdl_id: Optional[str] = None
    ) -> bool:
        """Update existing DomainRegistration with new information if available."""
        updated = False
        if name and not registration.name:
            registration.name = name
            updated = True
        if name and not registration.organization:
            registration.organization = name
            updated = True
        if nic_hdl_id and (not registration.id_str or registration.id_str != nic_hdl_id):
            registration.id_str = nic_hdl_id
            updated = True
        field_mappings = {
            "contact": nic_hdl.get("contact", ""),
            "type": nic_hdl.get("type", ""),
            "email": nic_hdl.get("e-mail", ""),
            "phone": nic_hdl.get("phone", ""),
            "country": nic_hdl.get("country", ""),
            "fax": nic_hdl.get("fax-no") or nic_hdl.get("fax", ""),
        }

        return self._update_object_fields_if_empty(field_mappings, registration, updated)

    def _update_object_fields_if_empty(self, field_mappings: Dict[str, Any], obj: Any, updated: bool) -> bool:
        """
        Update object fields with values from field_mappings only if fields are empty.

        Args:
            field_mappings: Dictionary mapping field names to values
            obj: Object to update (Registrar or DomainRegistration)
            updated: Boolean indicating if any updates have been made

        Returns:
            Boolean indicating if any updates were made
        """
        for field, value in field_mappings.items():
            if value and not getattr(obj, field):
                setattr(obj, field, value)
                updated = True
        if updated:
            obj.save()
        return updated

    def _get_or_create_registrant(
        self, registrant_name: str, extra_data: Dict[str, Any]
    ) -> Optional[DomainRegistration]:
        """
        Get or create registrant from name and extra_data.

        Args:
            registrant_name: Registrant name
            extra_data: Extra data containing nic_hdl

        Returns:
            DomainRegistration object or None
        """
        try:
            nic_hdl = extra_data.get("nic_hdl", {})
            nic_hdl_id = self._extract_nic_hdl_id(nic_hdl)
            defaults = self._build_domain_registration_defaults(nic_hdl, registrant_name, registrant_name, nic_hdl_id)

            if nic_hdl_id:
                registrant, created = DomainRegistration.objects.get_or_create(id_str=nic_hdl_id, defaults=defaults)
            else:
                registrant, created = DomainRegistration.objects.get_or_create(name=registrant_name, defaults=defaults)

            if not created:
                self._update_domain_registration(registrant, nic_hdl, registrant_name, nic_hdl_id)

            return registrant

        except Exception as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "REGISTRANT",
                "Error getting or creating registrant: %s" % (e,),
                level="error",
            )
            return None

    def _find_nic_hdl_in_extra_data(self, extra_data: Dict[str, Any], nic_hdl_id: str) -> Optional[Dict[str, Any]]:
        """
        Find nic_hdl in extra_data from fragments.nic_hdl.

        Args:
            extra_data: Extra data dictionary
            nic_hdl_id: NIC handle ID to search for

        Returns:
            nic_hdl dictionary or None
        """
        extra_nic_hdl = extra_data.get("nic_hdl", {})
        if isinstance(extra_nic_hdl, dict) and extra_nic_hdl.get("nic-hdl") == nic_hdl_id:
            return extra_nic_hdl
        if isinstance(extra_nic_hdl, list):
            for nh in extra_nic_hdl:
                if isinstance(nh, dict) and nh.get("nic-hdl") == nic_hdl_id:
                    return nh

        if isinstance(extra_nic_hdl, dict) and extra_nic_hdl.get("nic-hdl"):
            return extra_nic_hdl

        return None

    def _find_existing_contact(
        self, domain: Domain, contact_type: str, nic_hdl_id: str
    ) -> Optional[DomainRegistration]:
        """
        Find existing contact from domain's DomainInfo or by id_str.

        Args:
            domain: Domain object
            contact_type: Type of contact ("admin" or "tech")
            nic_hdl_id: NIC handle ID

        Returns:
            DomainRegistration object or None
        """
        if domain_info := getattr(domain, "domain_info", None):
            if contact_type == "admin" and domain_info.admin and domain_info.admin.id_str == nic_hdl_id:
                return domain_info.admin
            if contact_type == "tech" and domain_info.tech and domain_info.tech.id_str == nic_hdl_id:
                return domain_info.tech

        if nic_hdl_id:
            return DomainRegistration.objects.filter(id_str=nic_hdl_id).first()

        return None

    def _create_contact(
        self, nic_hdl: Dict[str, Any], contact_name: str, nic_hdl_id: str, defaults: Dict[str, Any], contact_type: str
    ) -> Optional[DomainRegistration]:
        """
        Create a new contact, handling integrity errors.

        Args:
            nic_hdl: nic_hdl dictionary
            contact_name: Contact name
            nic_hdl_id: NIC handle ID
            defaults: Default values for creation
            contact_type: Type of contact ("admin" or "tech")

        Returns:
            DomainRegistration object or None
        """
        try:
            if nic_hdl_id:
                create_defaults = {k: v for k, v in defaults.items() if k != "id_str"}
                return DomainRegistration.objects.create(id_str=nic_hdl_id, **create_defaults)
            return DomainRegistration.objects.create(name=contact_name, **defaults)
        except IntegrityError as ie:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "CONTACT",
                "Integrity error creating %s contact, trying to get existing: %s" % (contact_type, ie),
                level="warning",
            )
            if nic_hdl_id and (contact_obj := DomainRegistration.objects.filter(id_str=nic_hdl_id).first()):
                return contact_obj
            return DomainRegistration.objects.filter(name=contact_name).first()

    def _get_or_create_admin_tech(
        self, nic_hdl_id: str, extra_data: Dict[str, Any], contact_type: str, domain: Domain
    ) -> Optional[DomainRegistration]:
        """
        Get or create admin or tech contact from nic-hdl ID and extra_data.
        Restricts search to contacts linked to the current domain's DomainInfo.

        Args:
            nic_hdl_id: NIC handle ID (e.g., "ES6827-FRNIC")
            extra_data: Extra data containing nic_hdl from fragments
            contact_type: Type of contact ("admin" or "tech")
            domain: Domain object to restrict the search to

        Returns:
            DomainRegistration object or None
        """
        try:
            nic_hdl = self._find_nic_hdl_in_extra_data(extra_data, nic_hdl_id)

            if not nic_hdl:
                logger.log_line(
                    PREFIX_DOMAIN_REPO,
                    "CONTACT",
                    "No nic-hdl found for %s contact ID: %s, creating minimal contact" % (contact_type, nic_hdl_id),
                    level="warning",
                )
                nic_hdl = {"nic-hdl": nic_hdl_id, "contact": nic_hdl_id}

            contact_name = nic_hdl.get("contact", "") or nic_hdl.get("nic-hdl", nic_hdl_id)
            defaults = self._build_domain_registration_defaults(nic_hdl, contact_name, contact_name, nic_hdl_id)

            contact_obj = self._find_existing_contact(domain, contact_type, nic_hdl_id)

            if contact_obj:
                self._update_domain_registration(contact_obj, nic_hdl, contact_name, nic_hdl_id)
            else:
                contact_obj = self._create_contact(nic_hdl, contact_name, nic_hdl_id, defaults, contact_type)

            return contact_obj

        except Exception as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "CONTACT",
                "Error getting or creating %s contact: %s" % (contact_type, e),
                level="error",
                exc_info=True,
            )
            return None

    def _process_extra_data(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """
        Process extra_data and populate DomainInfo fields.

        Args:
            domain_info: DomainInfo object to update
            extra_data: Extra data dictionary from Secator
        """
        try:
            self._process_basic_fields(domain_info, extra_data)
            self._process_status_fields(domain_info, extra_data)
            self._process_name_servers(domain_info, extra_data)
            self._process_dnssec(domain_info, extra_data)
            self._store_remaining_data(domain_info, extra_data)
        except Exception as e:
            logger.log_line(
                PREFIX_DOMAIN_REPO,
                "EXTRA_DATA",
                "Error processing extra_data: %s" % (e,),
                level="error",
            )

    def _process_basic_fields(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """Process basic fields like last_update and whois_server."""
        if not domain_info.updated:
            if last_update := self._parse_datetime(extra_data.get("last_update")):
                domain_info.updated = last_update

        if whois_server := extra_data.get("whois_server", ""):
            domain_info.whois_server = whois_server

    def _add_status_to_domain_info(self, domain_info: DomainInfo, status_value: str) -> None:
        """Add a status value to domain_info status many-to-many field."""
        if status_value:
            status_obj, _ = WhoisStatus.objects.get_or_create(name=status_value)
            domain_info.status.add(status_obj)

    def _process_status_value(self, domain_info: DomainInfo, status_value: Any) -> None:
        """Process a single status value (string or list)."""
        if isinstance(status_value, list):
            for value in status_value:
                self._add_status_to_domain_info(domain_info, value)
        else:
            self._add_status_to_domain_info(domain_info, status_value)

    def _process_status_fields(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """Process status and eppstatus fields from extra_data."""
        if status := extra_data.get("status", ""):
            self._add_status_to_domain_info(domain_info, status)

        if eppstatus := extra_data.get("eppstatus", ""):
            self._process_status_value(domain_info, eppstatus)

        nic_hdl = extra_data.get("nic_hdl", {})
        if isinstance(nic_hdl, dict) and (nic_eppstatus := nic_hdl.get("eppstatus", "")):
            self._process_status_value(domain_info, nic_eppstatus)

    def _add_name_server(self, domain_info: DomainInfo, ns_name: str) -> None:
        """Add a name server to domain_info."""
        if ns_name:
            ns_obj, _ = NameServer.objects.get_or_create(name=ns_name)
            domain_info.name_servers.add(ns_obj)

    def _process_name_servers(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """Process name servers from extra_data."""
        nserver_data = extra_data.get("nserver", {})
        if isinstance(nserver_data, dict):
            nserver_list = nserver_data.get("nserver", [])
            if isinstance(nserver_list, list):
                for ns_name in nserver_list:
                    self._add_name_server(domain_info, ns_name)
        elif isinstance(nserver_data, list):
            for ns_name in nserver_data:
                self._add_name_server(domain_info, ns_name)

    def _process_dnssec(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """Process DNSSEC information."""
        if "key1-tag" in extra_data:
            domain_info.dnssec = True

    def _store_remaining_data(self, domain_info: DomainInfo, extra_data: Dict[str, Any]) -> None:
        """Store remaining extra_data in JSONField."""
        stored_data = {
            "chain": extra_data.get("chain", []),
            "raw": extra_data.get("raw", ""),
            "emails": extra_data.get("emails", []),
            "key1-tag": extra_data.get("key1-tag", {}),
        }

        self._ensure_extra_data_initialized(domain_info)
        domain_info.extra_data.update(stored_data)

    def _resolve_registrant_contact(
        self,
        registrant_info: Dict[str, Any],
        admin_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a contact dict preferring registrant_info over admin_info for each key.

        Precedence for each key: registrant_info[key] if present, else admin_info[key].
        Used so synthetic WHOIS does not overwrite distinct registrant data with admin.
        _build_whois_from_flat_item then uses this for: id, name, organization, email,
        phone, country, street; handle/registrant name/organization also fall back to
        item["registrant"], item["registrant_organization"], admin_info where documented.
        """
        resolved: Dict[str, Any] = {}
        if not isinstance(registrant_info, dict):
            registrant_info = {}
        if not isinstance(admin_info, dict):
            admin_info = {}
        for key in set(registrant_info.keys()) | set(admin_info.keys()):
            if registrant_info.get(key):
                resolved[key] = registrant_info.get(key)
            elif admin_info.get(key):
                resolved[key] = admin_info.get(key)
        return resolved

    def _build_whois_from_flat_item(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Build a normalized whois-like dict from a flat whois-go style domain item.

        Used when extra_data.whois is missing (e.g. Secator whois task output).
        """
        if not isinstance(item, dict) or not item.get("domain"):
            return None

        extra = item.get("extra_data") or {}
        admin_info = item.get("administrative_info") or {}
        tech_info = item.get("technical_info") or {}
        registrant_info = item.get("registrant_info") or {}
        raw_registrar = item.get("registrar_info") or {}

        resolved_registrant = self._resolve_registrant_contact(registrant_info, admin_info)

        details = dict(raw_registrar) if isinstance(raw_registrar, dict) else {}
        if "email" in details and "e-mail" not in details:
            details["e-mail"] = details.get("email", "")
        if "referral_url" in details and "website" not in details:
            details["website"] = details.get("referral_url", "")
        if "fax" in details and "fax-no" not in details:
            details["fax-no"] = details.get("fax", "")

        status = item.get("status")
        if isinstance(status, str):
            statuses = [status]
        elif isinstance(status, list):
            statuses = [s for s in status if isinstance(s, str)]
        else:
            statuses = []

        registrant_name = resolved_registrant.get("name") or item.get("registrant") or admin_info.get("name") or ""
        registrant_organization = (
            resolved_registrant.get("organization")
            or item.get("registrant_organization")
            or admin_info.get("organization")
            or ""
        )

        return {
            "domain": {
                "creation_date": item.get("creation_date"),
                "expiration_date": item.get("expiration_date"),
                "updated_date": item.get("updated_date"),
                "statuses": statuses,
                "name_servers": extra.get("name_servers") if isinstance(extra.get("name_servers"), list) else [],
            },
            "registrar": {
                "name": item.get("registrar") or "",
                "details": details,
                "url": (raw_registrar.get("referral_url") or "") if isinstance(raw_registrar, dict) else "",
            },
            "contacts": {
                "admin": {"handle": admin_info.get("id") or ""},
                "tech": {"handle": tech_info.get("id") or ""},
                "registrant": {
                    "name": registrant_name,
                    "organization": registrant_organization,
                    "handle": resolved_registrant.get("id") or admin_info.get("id") or "",
                    "email": resolved_registrant.get("email") or "",
                    "phone": resolved_registrant.get("phone") or "",
                    "country": resolved_registrant.get("country") or "",
                    "street": resolved_registrant.get("street") or "",
                },
            },
            "registry_ids": {
                "registry_admin_id": admin_info.get("id") or "",
                "registry_tech_id": tech_info.get("id") or "",
            },
        }

    def _build_extra_data_internal_from_whois(self, whois: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build an internal extra_data dict from Secator's normalized WHOIS payload.

        The internal dict is shaped to match what the existing repository helpers
        expect (registrar_info, nserver, status/eppstatus, nic_hdl, admin_c/tech_c, ...).
        """
        extra_data: Dict[str, Any] = {}

        if not isinstance(whois, dict):
            return extra_data

        self._extract_whois_servers(whois, extra_data)
        self._extract_chain_and_emails(whois, extra_data)
        self._extract_raw_data(whois, extra_data)
        self._extract_domain_info(whois, extra_data)
        self._extract_fragments_info(whois, extra_data)
        self._extract_registrar_info(whois, extra_data)
        self._extract_contacts_info(whois, extra_data)
        self._extract_registry_ids(whois, extra_data)

        return extra_data

    def _extract_whois_servers(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract WHOIS server information."""
        servers = whois.get("servers", {})
        if isinstance(servers, dict):
            used_servers = servers.get("used", [])
            if isinstance(used_servers, list):
                used_clean = [s.strip() for s in used_servers if isinstance(s, str) and s.strip()]
            else:
                used_clean = []

            if used_clean:
                extra_data["whois_server"] = ", ".join(used_clean)[:150]
            else:
                whois_server = servers.get("primary", "")
                if isinstance(whois_server, str) and whois_server:
                    extra_data["whois_server"] = whois_server[:150]

    def _extract_chain_and_emails(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract chain and emails from WHOIS."""
        chain = whois.get("chain", [])
        if isinstance(chain, list):
            extra_data["chain"] = chain

        emails = whois.get("emails", [])
        if isinstance(emails, list):
            extra_data["emails"] = emails

    def _extract_raw_data(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract raw WHOIS data."""
        raw = whois.get("raw", {})
        if isinstance(raw, dict):
            raw_by_server = raw.get("by_server", {})
            if isinstance(raw_by_server, dict):
                extra_data["raw"] = raw_by_server

    def _extract_domain_info(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract domain information including dates, statuses, name servers, and DNSSEC."""
        whois_domain = whois.get("domain", {})
        if not isinstance(whois_domain, dict):
            return

        updated_date = whois_domain.get("updated_date", "")
        if isinstance(updated_date, str) and updated_date:
            extra_data["last_update"] = updated_date

        statuses = whois_domain.get("statuses", [])
        if isinstance(statuses, list) and (
            statuses_clean := [s.strip() for s in statuses if isinstance(s, str) and s.strip()]
        ):
            extra_data["status"] = statuses_clean[0]
            if len(statuses_clean) > 1:
                extra_data["eppstatus"] = statuses_clean[1:]

        name_servers = whois_domain.get("name_servers", [])
        if isinstance(name_servers, list):
            extra_data.setdefault("nserver", {"nserver": name_servers})

        self._extract_dnssec_info(whois_domain, extra_data)

    def _extract_dnssec_info(self, whois_domain: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract DNSSEC information from domain data."""
        dnssec = whois_domain.get("dnssec", {})
        if not isinstance(dnssec, dict):
            return

        dnssec_state = dnssec.get("dnssec", "")
        dnssec_keys = dnssec.get("dnssec_keys", [])
        has_keys = isinstance(dnssec_keys, list) and len(dnssec_keys) > 0
        if dnssec_state == "signed" or has_keys:
            if has_keys and isinstance(dnssec_keys[0], dict):
                first_key = dnssec_keys[0]
                extra_data["key1-tag"] = {
                    "key1-tag": first_key.get("key_tag", ""),
                    "key1-algo": first_key.get("algorithm", ""),
                    "key1-dgst-t": first_key.get("digest_type", ""),
                    "key1-dgst": first_key.get("digest", ""),
                }
            else:
                extra_data["key1-tag"] = {}

    def _extract_fragments_info(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract fragments information from WHOIS."""
        fragments = whois.get("fragments", {})
        if not isinstance(fragments, dict):
            return

        domain_info = fragments.get("domain_info", {})
        if isinstance(domain_info, dict):
            extra_data["domain_info"] = domain_info

        nserver = fragments.get("nserver", {})
        if isinstance(nserver, dict) and "nserver" in nserver:
            extra_data["nserver"] = nserver

        nic_hdl = fragments.get("nic_hdl", {})
        if (isinstance(nic_hdl, dict) and nic_hdl) or (isinstance(nic_hdl, list) and nic_hdl):
            extra_data["nic_hdl"] = nic_hdl

    def _extract_registrar_info(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract registrar information with fallback logic."""
        registrar = whois.get("registrar", {})
        if not isinstance(registrar, dict):
            return

        registrar_details = registrar.get("details", {})
        if isinstance(registrar_details, dict):
            registrar_info = dict(registrar_details)
        else:
            registrar_info = {}

        if "fax-no" not in registrar_info:
            fax = registrar_info.get("fax", "")
            if isinstance(fax, str) and fax:
                registrar_info["fax-no"] = fax

        if "website" not in registrar_info:
            url = registrar.get("url", "")
            if isinstance(url, str) and url:
                registrar_info["website"] = url

        registrar_name = registrar.get("name", "")
        if isinstance(registrar_name, str) and registrar_name:
            registrar_info.setdefault("name", registrar_name)
            extra_data["registrar_name"] = registrar_name

        extra_data["registrar_info"] = registrar_info

    def _extract_contacts_info(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract contacts information including admin, tech, and registrant."""
        contacts = whois.get("contacts", {})
        if not isinstance(contacts, dict):
            return

        admin = contacts.get("admin", {})
        if isinstance(admin, dict) and (admin_handle := admin.get("handle", "")) and isinstance(admin_handle, str):
            extra_data["admin_c"] = admin_handle

        tech = contacts.get("tech", {})
        if isinstance(tech, dict) and (tech_handle := tech.get("handle", "")) and isinstance(tech_handle, str):
            extra_data["tech_c"] = tech_handle

        if "nic_hdl" not in extra_data:
            self._extract_registrant_nic_hdl(contacts, extra_data)

    def _extract_registrant_nic_hdl(self, contacts: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract registrant NIC handle information."""
        registrant = contacts.get("registrant", {})
        if not isinstance(registrant, dict):
            return

        contact_name = registrant.get("name", "") or registrant.get("organization", "")
        email = registrant.get("email", "")
        phone = registrant.get("phone", "")
        country = registrant.get("country", "")
        handle = registrant.get("handle", "")
        street = registrant.get("street", [])
        address = street if isinstance(street, list) else []
        extra_data["nic_hdl"] = {
            "contact": contact_name or "",
            "e-mail": email if isinstance(email, str) else "",
            "phone": phone if isinstance(phone, str) else "",
            "country": country if isinstance(country, str) else "",
            "address": address,
            "nic-hdl": handle if isinstance(handle, str) else "",
        }
        if contact_name:
            extra_data["registrant_name"] = contact_name

    def _extract_registry_ids(self, whois: Dict[str, Any], extra_data: Dict[str, Any]) -> None:
        """Extract registry IDs as fallback for admin_c and tech_c."""
        if "admin_c" in extra_data and "tech_c" in extra_data:
            return

        registry_ids = whois.get("registry_ids", {})
        if not isinstance(registry_ids, dict):
            return

        if "admin_c" not in extra_data:
            admin_id = registry_ids.get("registry_admin_id", "")
            if isinstance(admin_id, str) and admin_id:
                extra_data["admin_c"] = admin_id
        if "tech_c" not in extra_data:
            tech_id = registry_ids.get("registry_tech_id", "")
            if isinstance(tech_id, str) and tech_id:
                extra_data["tech_c"] = tech_id
