"""
Technology Repository - Data access for technology operations.
Handles Technology database operations with ManyToMany associations from Secator Tag.
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

from reNgine.core.validators import is_valid_domain, is_valid_url
from startScan.models import EndPoint, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


logger = get_task_logger(__name__)


class TechnologyRepository:
    """Repository for technology-related database operations."""

    def save_from_secator(self, item: Dict[str, Any], scan_history_id: int, domain_id: int) -> Optional[Technology]:
        """
        Save technology from Secator tag result.

        Args:
            item: Secator tag item (represents technology)
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            Technology: Saved technology object or None
        """
        try:
            return self._process_secator_technology_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving technology: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving technology: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving technology from Secator: {e}")
            return None

    def _process_secator_technology_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[Technology]:
        tech_name = item.get("name")
        # Secator Tag type uses 'match' field for the target where technology was found
        match_target = item.get("match")

        if not tech_name:
            logger.warning(f"Technology item missing name field. Available fields: {list(item.keys())}")
            return None

        if not match_target:
            logger.warning(f"Technology item missing match field. Available fields: {list(item.keys())}")
            return None

        # Validate scan_history and domain exist
        ScanHistory.objects.get(id=scan_history_id)
        Domain.objects.get(id=domain_id)

        # Get or create technology
        tech_obj, created = Technology.objects.get_or_create(
            name=tech_name,
            defaults={
                "value": item.get("value", ""),
                "category": item.get("category", ""),
                "stored_response_path": item.get("stored_response_path", ""),
            },
        )

        if created:
            logger.info(f"Created technology: {tech_name}")
        else:
            logger.debug(f"Technology already exists: {tech_name}")

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
                logger.warning("Technology name is empty")
                return None, False

            tech_obj, created = Technology.objects.get_or_create(name=name.strip())

            return tech_obj, created

        except Exception as e:
            logger.error(f"Error in get_or_create technology: {e}")
            return None, False

    def bulk_create(self, technologies: List[str]) -> List[Technology]:
        """
        Bulk create technologies.

        Args:
            technologies: List of technology names

        Returns:
            list: List of created Technology objects
        """
        try:
            created_technologies = []
            for tech_name in technologies:
                if tech_name and tech_name.strip():
                    # Use get_or_create to avoid duplicates
                    tech, created = Technology.objects.get_or_create(name=tech_name.strip())
                    if created:
                        created_technologies.append(tech)

            logger.info(f"Created {len(created_technologies)} new technologies")
            return created_technologies

        except Exception as e:
            logger.error(f"Error in bulk create technologies: {e}")
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
                logger.debug(f"Associated technology {tech_name} with subdomain {subdomain_name}")
                return True
            else:
                logger.warning(f"Subdomain {subdomain_name} not found in scan {scan_history_id}")
                return False

        except Exception as e:
            logger.error(f"Error associating technology with subdomain: {e}")
            return False

    def associate_with_endpoint(self, tech_name: str, endpoint_url: str, scan_history_id: int) -> bool:
        """
        Associate technology with a specific endpoint.

        Args:
            tech_name: Technology name
            endpoint_url: Endpoint URL
            scan_history_id: Scan history ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tech_obj, _ = Technology.objects.get_or_create(name=tech_name)

            if endpoint := EndPoint.objects.filter(http_url=endpoint_url, scan_history_id=scan_history_id).first():
                endpoint.techs.add(tech_obj)
                logger.debug(f"Associated technology {tech_name} with endpoint {endpoint_url}")
                return True
            else:
                logger.warning(f"Endpoint {endpoint_url} not found in scan {scan_history_id}")
                return False

        except Exception as e:
            logger.error(f"Error associating technology with endpoint: {e}")
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
            logger.warning(f"Subdomain {subdomain_name} not found in scan {scan_history_id}")
            return []

        except Exception as e:
            logger.error(f"Error getting technologies for subdomain: {e}")
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
            logger.warning(f"Endpoint {endpoint_url} not found in scan {scan_history_id}")
            return []

        except Exception as e:
            logger.error(f"Error getting technologies for endpoint: {e}")
            return []

    def _associate_technology(self, tech_obj: Technology, match_target: str, scan_history_id: int) -> None:
        """
        Associate technology with subdomain or endpoint based on match target.

        Args:
            tech_obj: Technology object
            match_target: Match target (URL or hostname)
            scan_history_id: Scan history ID
        """
        try:
            # Check if match_target is a URL
            if match_target.startswith(("http://", "https://")):
                if is_valid_url(match_target):
                    if endpoint := EndPoint.objects.filter(
                        http_url=match_target, scan_history_id=scan_history_id
                    ).first():
                        endpoint.techs.add(tech_obj)
                        logger.debug(f"Associated technology {tech_obj.name} with endpoint {match_target}")
                        return
                    else:
                        logger.debug(f"Endpoint {match_target} not found, trying subdomain association")

                        if hostname := urlparse(match_target).hostname:
                            self._associate_with_subdomain_by_hostname(tech_obj, hostname, scan_history_id)
            elif is_valid_domain(match_target):
                self._associate_with_subdomain_by_hostname(tech_obj, match_target, scan_history_id)
            else:
                logger.warning(f"Invalid match target for technology association: {match_target}")

        except Exception as e:
            logger.error(f"Error associating technology: {e}")

    def _associate_with_subdomain_by_hostname(self, tech_obj: Technology, hostname: str, scan_history_id: int) -> None:
        """
        Associate technology with subdomain by hostname.

        Args:
            tech_obj: Technology object
            hostname: Hostname
            scan_history_id: Scan history ID
        """
        try:
            if subdomain := Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first():
                subdomain.technologies.add(tech_obj)
                logger.debug(f"Associated technology {tech_obj.name} with subdomain {hostname}")
            else:
                logger.debug(f"Subdomain {hostname} not found in scan {scan_history_id}")

        except Exception as e:
            logger.error(f"Error associating technology with subdomain by hostname: {e}")

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
