"""
Domain Repository - Data access for domain information operations.
Handles DomainInfo database operations from Secator Domain output type.
"""

import contextlib
from datetime import datetime
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.utilities.time import ensure_timezone_aware, parse_datetime_iso
from startScan.models import ScanHistory
from targetApp.models import (
    Domain,
    DomainInfo,
    DomainRegistration,
    NameServer,
    Registrar,
    WhoisStatus,
)


logger = get_task_logger(__name__)


class DomainRepository:
    """Repository for domain information-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[DomainInfo]:
        """
        Save domain information from Secator Domain result.

        Args:
            item: Secator Domain item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            DomainInfo: Saved domain info object or None
        """
        try:
            return self._process_secator_domain_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving domain info: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving domain info: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving domain info from Secator: {e}")
            return None

    def _process_secator_domain_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[DomainInfo]:
        domain_name = item.get("domain")

        if not domain_name:
            logger.warning("Domain item missing domain field")
            return None

        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        # Verify domain name matches
        if domain.name != domain_name:
            logger.warning(f"Domain name mismatch: expected {domain.name}, got {domain_name}")
            return None

        # Get or create domain info
        if domain.domain_info:
            domain_info = domain.domain_info
            created = False
        else:
            domain_info = DomainInfo()
            created = True

        # Parse dates
        creation_date = self._parse_datetime(item.get("creation_date"))
        expiration_date = self._parse_datetime(item.get("expiration_date"))
        extra_data = item.get("extra_data", {})
        last_update = self._parse_datetime(extra_data.get("last_update"))

        # Update basic fields
        if creation_date:
            domain_info.created = creation_date
        if expiration_date:
            domain_info.expires = expiration_date
        if last_update:
            domain_info.updated = last_update

        if registrar_name := item.get("registrar", ""):
            if registrar := self._get_or_create_registrar(registrar_name, extra_data):
                domain_info.registrar = registrar

        if registrant_name := item.get("registrant", ""):
            if registrant := self._get_or_create_registrant(registrant_name, extra_data):
                domain_info.registrant = registrant

        # Process admin and tech contacts
        if extra_data:
            admin_c = extra_data.get("admin_c", "")
            tech_c = extra_data.get("tech_c", "")

            if admin_c:
                if admin := self._get_or_create_admin_tech(admin_c, extra_data, "admin", domain):
                    domain_info.admin = admin

            if tech_c:
                if tech := self._get_or_create_admin_tech(tech_c, extra_data, "tech", domain):
                    domain_info.tech = tech

        # Save domain info first (needed for many-to-many relationships)
        domain_info.save()

        # Process extra_data (after save to allow many-to-many relationships)
        if extra_data:
            self._process_extra_data(domain_info, extra_data)

        # Associate domain with domain_info (always update to ensure link is correct)
        domain.domain_info = domain_info
        domain.save()

        if created:
            logger.info(f"Created domain info for domain {domain_name}")
        else:
            logger.debug(f"Updated domain info for domain {domain_name}")

        return domain_info

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
            logger.error(f"Error getting or creating registrar: {e}")
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

    def _find_nic_hdl_in_jswhois(self, jswhois_full: Dict[str, Any], nic_hdl_id: str) -> Optional[Dict[str, Any]]:
        """Find matching nic-hdl in jswhois_full structure."""
        if not jswhois_full or "chain" not in jswhois_full:
            return None

        last_chain = jswhois_full["chain"][-1]
        last_elem = jswhois_full.get(last_chain, {})

        found_nic_hdl = last_elem.get("nic-hdl")
        if not found_nic_hdl:
            return None

        if isinstance(found_nic_hdl, dict):
            if found_nic_hdl.get("nic-hdl") == nic_hdl_id:
                return found_nic_hdl
        elif isinstance(found_nic_hdl, list):
            for nh in found_nic_hdl:
                if isinstance(nh, dict) and nh.get("nic-hdl") == nic_hdl_id:
                    return nh

        if nic_hdl_id in last_elem:
            potential_nic_hdl = last_elem[nic_hdl_id]
            if isinstance(potential_nic_hdl, dict) and potential_nic_hdl.get("nic-hdl") == nic_hdl_id:
                return potential_nic_hdl

        return None

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
            logger.error(f"Error getting or creating registrant: {e}")
            return None

    def _find_nic_hdl_in_extra_data(self, extra_data: Dict[str, Any], nic_hdl_id: str) -> Optional[Dict[str, Any]]:
        """
        Find nic_hdl in extra_data using multiple fallback strategies.

        Args:
            extra_data: Extra data dictionary
            nic_hdl_id: NIC handle ID to search for

        Returns:
            nic_hdl dictionary or None
        """
        jswhois_full = extra_data.get("jswhois_full", {})
        if nic_hdl := self._find_nic_hdl_in_jswhois(jswhois_full, nic_hdl_id):
            return nic_hdl

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
        if domain_info := getattr(domain, "domain_info", None) if hasattr(domain, "domain_info") else None:
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
            logger.warning(f"Integrity error creating {contact_type} contact, trying to get existing: {ie}")
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
            extra_data: Extra data containing jswhois_full or domain_info
            contact_type: Type of contact ("admin" or "tech")
            domain: Domain object to restrict the search to

        Returns:
            DomainRegistration object or None
        """
        try:
            nic_hdl = self._find_nic_hdl_in_extra_data(extra_data, nic_hdl_id)

            if not nic_hdl:
                logger.warning(
                    f"No nic-hdl found for {contact_type} contact ID: {nic_hdl_id}, creating minimal contact"
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
            logger.error(f"Error getting or creating {contact_type} contact: {e}", exc_info=True)
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
            logger.error(f"Error processing extra_data: {e}")

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

        if domain_info.extra_data is None:
            domain_info.extra_data = {}
        domain_info.extra_data.update(stored_data)
