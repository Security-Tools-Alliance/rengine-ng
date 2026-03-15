"""
Technology Repository - Data access for technology operations.
Handles Technology database operations with ManyToMany associations from Secator Tag.
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.db import DatabaseError, IntegrityError

from reNgine.core.validators import is_valid_url
from reNgine.secator.path_utils import strip_secator_reports_prefix
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.logger import format_exception_for_log, get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import EndPoint, ScanHistory, Subdomain, Technology


PREFIX_TECH_REPO = "[TECH_REPO]"
logger = get_module_logger(__name__)


class TechnologyRepository:
    """Repository for technology-related database operations."""

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

        # Associate with subdomain or endpoint based on match target
        self._associate_technology(tech_obj, match_target, scan_history_id)

        return tech_obj

    def get_or_create(self, name: str, **kwargs) -> Tuple[Optional[Technology], bool]:
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

            tech_obj, created = Technology.objects.get_or_create(name=name.strip())

            return tech_obj, created

        except (IntegrityError, DatabaseError) as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create technology: %s" % (e,),
                level="error",
            )
            return None, False

    def bulk_create(self, technologies: List[str]) -> List[Technology]:
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
            existing_technologies = list(Technology.objects.filter(name__in=normalized_names))
            existing_names = {tech.name for tech in existing_technologies}
            missing_names = normalized_names - existing_names

            if missing_names:
                new_instances = [Technology(name=name) for name in missing_names]
                Technology.objects.bulk_create(new_instances)
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "BULK_CREATE",
                    "Bulk created %s new technologies out of %s requested"
                    % (len(new_instances), len(normalized_names)),
                    level="info",
                )

            return list(Technology.objects.filter(name__in=normalized_names))

        except DatabaseError as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "BULK_CREATE",
                "Error in bulk create technologies: %s" % (e,),
                level="error",
            )
            return []

    def associate_with_subdomain(self, tech_name: str, subdomain_name: str, scan_history_id: int) -> bool:
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
            tech_obj, _ = Technology.objects.get_or_create(name=tech_name)

            if subdomain := Subdomain.objects.filter(name=subdomain_name, scan_history_id=scan_history_id).first():
                subdomain.technologies.add(tech_obj)
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_SUBDOMAIN",
                    "Associated technology %s with subdomain %s" % (tech_name, subdomain_name),
                    level="debug",
                )
                return True
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_SUBDOMAIN",
                    "Subdomain %s not found in scan %s" % (subdomain_name, scan_history_id),
                    level="warning",
                )
                return False

        except (IntegrityError, DatabaseError) as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_SUBDOMAIN",
                "Error associating technology with subdomain: %s | subdomain=%s scan_id=%s"
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
                    "ASSOCIATE_ENDPOINT",
                    "Technology name is empty in associate_with_endpoint",
                    level="warning",
                )
                return False

            tech_obj, _ = Technology.objects.get_or_create(name=normalized_name)

            endpoint = EndPoint.objects.get(http_url=endpoint_url, scan_history_id=scan_history_id)
            endpoint.techs.add(tech_obj)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_ENDPOINT",
                "Associated technology %s with endpoint %s" % (normalized_name, endpoint_url),
                level="debug",
            )
            return True

        except EndPoint.DoesNotExist:
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_ENDPOINT",
                "Endpoint %s not found in scan %s" % (endpoint_url, scan_history_id),
                level="warning",
            )
            return False
        except MultipleObjectsReturned:
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_ENDPOINT",
                "Multiple endpoints found for (http_url=%s, scan_history_id=%s); cannot associate technology unambiguously"
                % (repr(endpoint_url), scan_history_id),
                level="error",
            )
            return False
        except (IntegrityError, DatabaseError) as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_ENDPOINT",
                "Error associating technology with endpoint: %s | endpoint=%s scan_id=%s"
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

    def _associate_technology(self, tech_obj: Technology, match_target: str, scan_history_id: int) -> None:
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
                    try:
                        endpoint = EndPoint.objects.get(http_url=match_target, scan_history_id=scan_history_id)
                        endpoint.techs.add(tech_obj)
                        logger.log_line(
                            PREFIX_TECH_REPO,
                            "ASSOCIATE",
                            "Associated technology %s with endpoint %s" % (tech_obj.name, match_target),
                            level="debug",
                        )
                        return
                    except EndPoint.DoesNotExist:
                        logger.log_line(
                            PREFIX_TECH_REPO,
                            "ASSOCIATE",
                            "Endpoint %s not found, trying subdomain association" % (match_target,),
                            level="debug",
                        )
                    except MultipleObjectsReturned:
                        logger.log_line(
                            PREFIX_TECH_REPO,
                            "ASSOCIATE",
                            "Multiple endpoints for (http_url=%s, scan_history_id=%s); skipping endpoint association"
                            % (repr(match_target), scan_history_id),
                            level="error",
                        )
                        return

                    if hostname := urlparse(match_target).hostname:
                        self._associate_with_subdomain_by_hostname(tech_obj, hostname, scan_history_id)
            elif is_acceptable_subdomain_name(match_target):
                self._associate_with_subdomain_by_hostname(tech_obj, match_target, scan_history_id)
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE",
                    "Invalid match target for technology association: %s" % (match_target,),
                    level="warning",
                )

        except DatabaseError as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE",
                "Error associating technology: %s | match_target=%s scan_id=%s"
                % (reason, match_target[:80] if match_target else "", scan_history_id),
                level="error",
            )

    def _associate_with_subdomain_by_hostname(self, tech_obj: Technology, hostname: str, scan_history_id: int) -> None:
        """Associate technology with subdomain by hostname (or IP). Uses get_or_create_from_host when needed."""
        try:
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
                subdomain.technologies.add(tech_obj)
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_SUBDOMAIN_HOSTNAME",
                    "Associated technology %s with subdomain %s" % (tech_obj.name, hostname),
                    level="debug",
                )
            else:
                logger.log_line(
                    PREFIX_TECH_REPO,
                    "ASSOCIATE_SUBDOMAIN_HOSTNAME",
                    "Subdomain %s not found in scan %s" % (hostname, scan_history_id),
                    level="debug",
                )

        except Exception as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_TECH_REPO,
                "ASSOCIATE_SUBDOMAIN_HOSTNAME",
                "Error associating technology with subdomain by hostname: %s | hostname=%s scan_id=%s"
                % (reason, hostname, scan_history_id),
                level="error",
            )

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

        except (IntegrityError, DatabaseError) as e:
            logger.log_line(
                PREFIX_TECH_REPO,
                "EXTRACT_FROM_LIST",
                "Error extracting technologies from list: %s" % (e,),
                level="error",
            )
            return []
