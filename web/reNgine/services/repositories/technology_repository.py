"""
Technology Repository - Data access for technology operations.
Handles Technology database operations with ManyToMany associations from Secator Tag.
"""

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.db import DatabaseError, IntegrityError

from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.core.validators import is_valid_ip, is_valid_url
from reNgine.secator.path_utils import strip_secator_reports_prefix
from reNgine.secator.source_extraction import extract_secator_tool_source
from reNgine.secator.subdomain_technology_link import upsert_subdomain_technology_link
from reNgine.services.repositories.ip_repository import IpRepository, normalize_ip_address_string
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.logger import format_exception_for_log, get_module_logger
from reNgine.utilities.scan_lookups import get_or_create_endpoint_in_scan_for_ingestion
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import EndPoint, ScanHistory, Subdomain, Technology


PREFIX_TECH_REPO = "[TECH_REPO]"
logger = get_module_logger(__name__)

_MAX_IS_LEGACY_SCAN_CACHE = 512


def _secator_prefers_endpoint_tech_links(*, is_legacy_scan: bool) -> bool:
    return not is_legacy_scan


def _endpoint_ids_for_subdomain_scan(
    *,
    scan_history_id: int,
    subdomain_id: int,
    precomputed_endpoint_ids: Optional[list[int]],
) -> list[int]:
    if precomputed_endpoint_ids is not None:
        return precomputed_endpoint_ids
    return list(
        EndPoint.objects.filter(scan_history_id=scan_history_id, subdomain_id=subdomain_id)
        .only("id")
        .values_list("id", flat=True)
    )


def _bulk_link_technology_to_endpoints_through(
    tech_obj: Technology,
    endpoint_ids: list[int],
    existing_endpoint_tech_links: Optional[set[tuple[int, int]]],
) -> None:
    through = EndPoint.techs.through
    if existing_endpoint_tech_links is not None:
        desired_pairs = {(endpoint_id, tech_obj.id) for endpoint_id in endpoint_ids}
        missing_pairs = desired_pairs.difference(existing_endpoint_tech_links)
        if not missing_pairs:
            return
        through.objects.bulk_create(
            [
                through(endpoint_id=endpoint_id, technology_id=technology_id)
                for endpoint_id, technology_id in missing_pairs
            ],
            ignore_conflicts=True,
        )
        existing_endpoint_tech_links.update(missing_pairs)
        return
    through.objects.bulk_create(
        [through(endpoint_id=endpoint_id, technology_id=tech_obj.id) for endpoint_id in endpoint_ids],
        ignore_conflicts=True,
    )


def _log_technology_linked_to_subdomain_endpoints(
    tech_obj: Technology,
    subdomain: Subdomain,
    scan_history_id: int,
) -> None:
    logger.log_line(
        PREFIX_TECH_REPO,
        "ASSOCIATE_TECH_TO_ENDPOINT",
        "Technology %s linked to subdomain endpoints (Secator; subdomain M2M skipped): subdomain=%s scan_id=%s"
        % (tech_obj.name, subdomain.name, scan_history_id),
        level="debug",
    )


def _upsert_subdomain_m2m_technology_with_log(
    subdomain: Subdomain,
    tech_obj: Technology,
    source: Optional[str],
    scan_history_id: int,
    fallback_reason: str,
) -> None:
    upsert_subdomain_technology_link(subdomain, tech_obj, source)
    logger.log_line(
        PREFIX_TECH_REPO,
        "ASSOCIATE_TECH_TO_SUBDOMAIN",
        ("Technology %s linked to subdomain via legacy M2M (%s): subdomain=%s scan_id=%s")
        % (tech_obj.name, fallback_reason, subdomain.name, scan_history_id),
        level="debug",
    )


def _link_technology_to_subdomain_via_endpoints_or_m2m(
    subdomain: Subdomain,
    tech_obj: Technology,
    scan_history_id: int,
    source: Optional[str],
    *,
    is_legacy_scan: bool,
    precomputed_endpoint_ids: Optional[list[int]] = None,
    existing_endpoint_tech_links: Optional[set[tuple[int, int]]] = None,
) -> None:
    """
    For Secator scans, attach technologies to all endpoints of the subdomain when any exist,
    avoiding redundant SubdomainTechnology rows. Otherwise upsert the M2M through row
    (legacy scans, or no endpoints yet).

    Usage:
    - Default (both optional args omitted): load endpoint ids for this subdomain/scan, then
      ``bulk_create`` through rows with ``ignore_conflicts=True``.
    - ``precomputed_endpoint_ids``: skip the endpoint query when a caller already has the id list
      (e.g. batch ingestion over one scan).
    - ``existing_endpoint_tech_links``: mutable set of ``(endpoint_id, technology_id)`` pairs
      already inserted in the current batch; when set, only missing pairs are created and the set
      is updated, avoiding redundant inserts while still using ``ignore_conflicts`` for safety.
    """
    if _secator_prefers_endpoint_tech_links(is_legacy_scan=is_legacy_scan):
        endpoint_ids = _endpoint_ids_for_subdomain_scan(
            scan_history_id=scan_history_id,
            subdomain_id=subdomain.id,
            precomputed_endpoint_ids=precomputed_endpoint_ids,
        )
        if endpoint_ids:
            _bulk_link_technology_to_endpoints_through(tech_obj, endpoint_ids, existing_endpoint_tech_links)
            _log_technology_linked_to_subdomain_endpoints(tech_obj, subdomain, scan_history_id)
            return
        fallback_reason = "no endpoints fallback"
    else:
        fallback_reason = "legacy scan fallback"
    _upsert_subdomain_m2m_technology_with_log(subdomain, tech_obj, source, scan_history_id, fallback_reason)


class TechnologyRepository:
    """Repository for technology-related database operations."""

    def __init__(self) -> None:
        self._is_legacy_scan_by_id: OrderedDict[int, bool] = OrderedDict()

    def _cache_is_legacy_scan(self, scan_history_id: int, value: bool) -> None:
        self._is_legacy_scan_by_id[scan_history_id] = value
        self._is_legacy_scan_by_id.move_to_end(scan_history_id)
        while len(self._is_legacy_scan_by_id) > _MAX_IS_LEGACY_SCAN_CACHE:
            self._is_legacy_scan_by_id.popitem(last=False)

    def _prime_is_legacy_scan_cache(self, scan_history_ids: List[int]) -> None:
        """
        Bulk-prime ``is_legacy_scan`` cache for unknown scan ids in one query.

        Useful for ingestion loops that repeatedly resolve scan mode.
        """
        unknown_ids = [sid for sid in scan_history_ids if sid not in self._is_legacy_scan_by_id]
        if not unknown_ids:
            return
        scans_by_id = ScanHistory.objects.only("id", "is_legacy_scan").in_bulk(unknown_ids)
        for sid in unknown_ids:
            scan = scans_by_id.get(sid)
            if scan is None:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "SCAN_LOOKUP",
                    "ScanHistory not found while resolving is_legacy_scan: scan_id=%s" % (sid,),
                    level="warning",
                )
                self._cache_is_legacy_scan(sid, False)
                continue
            self._cache_is_legacy_scan(sid, bool(getattr(scan, "is_legacy_scan", False)))

    def _get_is_legacy_scan(self, scan_history_id: int) -> bool:
        self._prime_is_legacy_scan_cache([scan_history_id])
        self._is_legacy_scan_by_id.move_to_end(scan_history_id)
        return self._is_legacy_scan_by_id[scan_history_id]

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Technology]:
        """
        Save technology from Secator tag result.

        Args:
            item: Secator tag item (represents technology)
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (unused)

        Returns:
            Technology: Saved technology object or None
        """
        try:
            return self._process_secator_technology_item(item, scan_history_id, target_id)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Object not found when saving technology: %s" % (e,),
                level="error",
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Integrity error saving technology: %s" % (e,),
                level="error",
            )
            return None
        except DatabaseError as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Database error saving technology from Secator: %s" % (e,),
                level="error",
            )
            return None

    def _process_secator_technology_item(
        self, item: Dict[str, Any], scan_history_id: int, target_id: int
    ) -> Optional[Technology]:
        tech_name = (item.get("name") or "").strip()
        # Secator Tag type uses 'match' field for the target where technology was found
        match_target = item.get("match")

        if not tech_name:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Technology item missing name field. Available fields: %s" % (list(item.keys()),),
                level="warning",
            )
            return None

        if not match_target:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Technology item missing match field. Available fields: %s" % (list(item.keys()),),
                level="warning",
            )
            return None

        # Normalize path for storage (prefix strip); file access and project check
        # are in api.scan_file (ServeScanFile, get_project_for_scan_file_path).
        raw_stored_path = item.get("stored_response_path") or ""
        path_max_length = Technology._meta.get_field("stored_response_path").max_length
        stored_response_path = (
            strip_secator_reports_prefix(raw_stored_path, max_length=path_max_length) if raw_stored_path else ""
        )
        tech_obj, created = Technology.objects.get_or_create(
            scan_history_id=scan_history_id,
            name=tech_name,
            defaults={
                "value": item.get("value", ""),
                "category": item.get("category", ""),
                "stored_response_path": stored_response_path,
            },
        )

        if created:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Created technology: %s" % (tech_name,),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_TECH_REPO,
                "SAVE",
                "Technology already exists: %s" % (tech_name,),
                level="debug",
            )

        tool_source = extract_secator_tool_source(item, include_provider=False, max_length=200)
        is_legacy_scan = self._get_is_legacy_scan(scan_history_id)
        self._associate_technology(
            tech_obj,
            match_target,
            scan_history_id,
            tool_source,
            is_legacy_scan=is_legacy_scan,
        )

        return tech_obj

    def get_or_create(self, name: str, scan_history_id: int, **kwargs) -> Tuple[Optional[Technology], bool]:
        """
        Get or create a technology.

        Args:
            name: Technology name
            **kwargs: Additional fields (not used for Technology model)

        Returns:
            tuple: (Technology, created boolean) or (None, False)
        """
        try:
            if not name or not name.strip():
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "GET_OR_CREATE",
                    "Technology name is empty",
                    level="warning",
                )
                return None, False

            tech_obj, created = Technology.objects.get_or_create(
                scan_history_id=scan_history_id,
                name=name.strip(),
            )

            return tech_obj, created

        except (IntegrityError, DatabaseError) as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create technology: %s" % (e,),
                level="error",
            )
            return None, False

    def bulk_create(self, technologies: List[str], scan_history_id: int) -> List[Technology]:
        """
        Bulk create technologies efficiently.

        Normalizes and de-duplicates the input list, fetches existing technologies
        in a single query, creates only missing ones via Django's bulk_create,
        then returns all requested Technology objects (existing + newly created).

        Args:
            technologies: List of technology names

        Returns:
            list: List of Technology objects (existing + newly created)
        """
        normalized_names = {t.strip() for t in (technologies or []) if t and t.strip()}
        if not normalized_names:
            logger.log_line(
                PREFIX_TECH_REPO,
                "BULK_CREATE",
                "No valid technology names provided for bulk_create",
                level="info",
            )
            return []

        try:
            existing_technologies = list(
                Technology.objects.filter(scan_history_id=scan_history_id, name__in=normalized_names)
            )
            if missing_names := normalized_names - {tech.name for tech in existing_technologies}:
                new_instances = [Technology(scan_history_id=scan_history_id, name=name) for name in missing_names]
                Technology.objects.bulk_create(new_instances)
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "BULK_CREATE",
                    "Bulk created %s new technologies out of %s requested"
                    % (len(new_instances), len(normalized_names)),
                    level="info",
                )

            return list(Technology.objects.filter(scan_history_id=scan_history_id, name__in=normalized_names))

        except DatabaseError as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "BULK_CREATE",
                "Error in bulk create technologies: %s" % (e,),
                level="error",
            )
            return []

    def associate_with_subdomain(
        self, tech_name: str, subdomain_name: str, scan_history_id: int, source: Optional[str] = None
    ) -> bool:
        """
        Associate technology with a specific subdomain.

        Args:
            tech_name: Technology name
            subdomain_name: Subdomain name
            scan_history_id: Scan history ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tech_obj, _ = Technology.objects.get_or_create(scan_history_id=scan_history_id, name=tech_name)

            is_legacy_scan = self._get_is_legacy_scan(scan_history_id)
            if subdomain := Subdomain.objects.filter(name=subdomain_name, scan_history_id=scan_history_id).first():
                _link_technology_to_subdomain_via_endpoints_or_m2m(
                    subdomain,
                    tech_obj,
                    scan_history_id,
                    source,
                    is_legacy_scan=is_legacy_scan,
                )
                return True
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_SUBDOMAIN",
                    "Subdomain not found in scan: subdomain=%s scan_id=%s" % (subdomain_name, scan_history_id),
                    level="warning",
                )
                return False

        except (IntegrityError, DatabaseError) as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_SUBDOMAIN",
                "Error linking technology to subdomain: %s | subdomain=%s scan_id=%s"
                % (reason, subdomain_name, scan_history_id),
                level="error",
            )
            return False

    def associate_with_endpoint(self, tech_name: str, endpoint_url: str, scan_history_id: int) -> bool:
        """
        Associate technology with a specific endpoint.

        Expects at most one EndPoint per (http_url, scan_history_id); logs and returns False
        if multiple endpoints exist (data integrity issue).

        Args:
            tech_name: Technology name (will be stripped for consistency)
            endpoint_url: Endpoint URL
            scan_history_id: Scan history ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            normalized_name = (tech_name or "").strip()
            if not normalized_name:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_ENDPOINT",
                    "Technology name empty, cannot link to endpoint",
                    level="warning",
                )
                return False

            tech_obj, _ = Technology.objects.get_or_create(scan_history_id=scan_history_id, name=normalized_name)

            endpoint = get_or_create_endpoint_in_scan_for_ingestion(endpoint_url, scan_history_id)
            if not endpoint:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_ENDPOINT",
                    "Endpoint not found/created in scan: url=%s scan_id=%s"
                    % (endpoint_url[:80] if endpoint_url else "", scan_history_id),
                    level="warning",
                )
                return False
            endpoint.techs.add(tech_obj)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_ENDPOINT",
                "Technology %s linked to endpoint %s" % (normalized_name, endpoint_url[:80] if endpoint_url else ""),
                level="debug",
            )
            return True

        except MultipleObjectsReturned:
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_ENDPOINT",
                "Multiple endpoints for same URL, cannot link technology: url=%s scan_id=%s"
                % (endpoint_url[:80] if endpoint_url else "", scan_history_id),
                level="error",
            )
            return False
        except (IntegrityError, DatabaseError) as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_ENDPOINT",
                "Error linking technology to endpoint: %s | endpoint=%s scan_id=%s"
                % (reason, endpoint_url[:80] if endpoint_url else "", scan_history_id),
                level="error",
            )
            return False

    def get_technologies_for_subdomain(self, subdomain_name: str, scan_history_id: int) -> List[Technology]:
        """
        Get all technologies associated with a subdomain.

        Args:
            subdomain_name: Subdomain name
            scan_history_id: Scan history ID

        Returns:
            list: List of Technology objects
        """
        try:
            if subdomain := Subdomain.objects.filter(name=subdomain_name, scan_history_id=scan_history_id).first():
                return list(subdomain.technologies.all())
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_FOR_SUBDOMAIN",
                "Subdomain %s not found in scan %s" % (subdomain_name, scan_history_id),
                level="warning",
            )
            return []

        except Exception as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_FOR_SUBDOMAIN",
                "Error getting technologies for subdomain: %s" % (e,),
                level="error",
            )
            return []

    def get_technologies_for_endpoint(self, endpoint_url: str, scan_history_id: int) -> List[Technology]:
        """
        Get all technologies associated with an endpoint.

        Args:
            endpoint_url: Endpoint URL
            scan_history_id: Scan history ID

        Returns:
            list: List of Technology objects
        """
        try:
            if endpoint := EndPoint.objects.filter(http_url=endpoint_url, scan_history_id=scan_history_id).first():
                return list(endpoint.techs.all())
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_FOR_ENDPOINT",
                "Endpoint %s not found in scan %s" % (endpoint_url, scan_history_id),
                level="warning",
            )
            return []

        except Exception as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_FOR_ENDPOINT",
                "Error getting technologies for endpoint: %s" % (e,),
                level="error",
            )
            return []

    def _associate_technology(
        self,
        tech_obj: Technology,
        match_target: str,
        scan_history_id: int,
        source: Optional[str] = None,
        *,
        is_legacy_scan: bool,
    ) -> None:
        """
        Associate technology with subdomain or endpoint based on match target.

        For URL targets, expects at most one EndPoint per (http_url, scan_history_id);
        logs and falls back to subdomain association if multiple endpoints exist.

        Args:
            tech_obj: Technology object
            match_target: Match target (URL or hostname)
            scan_history_id: Scan history ID
        """
        try:
            # Check if match_target is a URL
            if match_target.startswith(("http://", "https://")):
                if is_valid_url(match_target):
                    endpoint = get_or_create_endpoint_in_scan_for_ingestion(match_target, scan_history_id)
                    if endpoint:
                        endpoint.techs.add(tech_obj)
                        logger.log_line(
                            PREFIX_TECH_REPO,
                            "ASSOCIATE_TECH_TO_ENDPOINT",
                            "Technology %s linked to endpoint %s"
                            % (tech_obj.name, match_target[:80] if match_target else ""),
                            level="debug",
                        )
                        return
                    logger.log_line(
                        PREFIX_TECH_REPO,
                        "ASSOCIATE_TECH_TO_TARGET",
                        "Endpoint not found/created for match_target, trying subdomain: %s"
                        % (match_target[:80] if match_target else "",),
                        level="debug",
                    )
                    if hostname := urlparse(match_target).hostname:
                        self._associate_with_subdomain_by_hostname(
                            tech_obj,
                            hostname,
                            scan_history_id,
                            source,
                            is_legacy_scan=is_legacy_scan,
                        )
            elif is_acceptable_subdomain_name(match_target):
                self._associate_with_subdomain_by_hostname(
                    tech_obj,
                    match_target,
                    scan_history_id,
                    source,
                    is_legacy_scan=is_legacy_scan,
                )
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_TARGET",
                    "Invalid match target, cannot link technology: %s" % (match_target[:80] if match_target else "",),
                    level="warning",
                )

        except DatabaseError as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_TARGET",
                "Error linking technology to subdomain/endpoint: %s | match_target=%s scan_id=%s"
                % (reason, match_target[:80] if match_target else "", scan_history_id),
                level="error",
            )

    def _associate_with_subdomain_by_hostname(
        self,
        tech_obj: Technology,
        hostname: str,
        scan_history_id: int,
        source: Optional[str] = None,
        *,
        is_legacy_scan: bool,
    ) -> None:
        """Associate technology with subdomain (DNS) or endpoints tied to an IP host."""
        try:
            hn = (hostname or "").strip().lower()
            if is_valid_ip(hn):
                normalized = normalize_ip_address_string(hn)
                if not normalized:
                    return
                ip_obj = IpRepository().first_ip_in_scan(normalized, scan_history_id)
                if not ip_obj:
                    return
                for ep in EndPoint.objects.filter(scan_history_id=scan_history_id, ip_address_id=ip_obj.id):
                    ep.techs.add(tech_obj)
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_ENDPOINT",
                    "Technology %s linked to IP %s endpoints in scan %s" % (tech_obj.name, normalized, scan_history_id),
                    level="debug",
                )
                return

            subdomain = None
            try:
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                target_id = getattr(scan_history, "target_id", None)
                if target_id and is_acceptable_subdomain_name(hostname):
                    subdomain = SubdomainRepository().get_or_create_from_host(scan_history_id, target_id, hostname)
            except ObjectDoesNotExist:
                pass
            if not subdomain:
                subdomain = Subdomain.objects.filter(
                    name=hostname.strip().lower(), scan_history_id=scan_history_id
                ).first()
            if subdomain:
                _link_technology_to_subdomain_via_endpoints_or_m2m(
                    subdomain,
                    tech_obj,
                    scan_history_id,
                    source,
                    is_legacy_scan=is_legacy_scan,
                )
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_TECH_TO_SUBDOMAIN",
                    "Subdomain not found in scan: hostname=%s scan_id=%s" % (hostname, scan_history_id),
                    level="debug",
                )

        except FindingOutOfScopeError as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_SUBDOMAIN",
                "Skipped (out of scope): hostname=%s | %s scan_id=%s" % (hostname, reason, scan_history_id),
                level="info",
            )
        except Exception as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_TECH_TO_SUBDOMAIN",
                "Error linking technology to subdomain by hostname: %s | hostname=%s scan_id=%s"
                % (reason, hostname, scan_history_id),
                level="error",
            )

    def extract_technologies_from_list(self, tech_list: List[str], scan_history_id: int) -> List[Technology]:
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
                    tech_obj, _ = Technology.objects.get_or_create(
                        scan_history_id=scan_history_id,
                        name=tech_name.strip(),
                    )
                    technologies.append(tech_obj)

            return technologies

        except (IntegrityError, DatabaseError) as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "EXTRACT_FROM_LIST",
                "Error extracting technologies from list: %s" % (e,),
                level="error",
            )
            return []
