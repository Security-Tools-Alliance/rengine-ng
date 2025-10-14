"""
Database hooks for saving Secator results to reNgine database.
Uses repository pattern to avoid circular dependencies.
"""

from celery.utils.log import get_task_logger

from reNgine.secator.hooks.base import SecatorHooks
from reNgine.services.repositories.endpoint_repository import EndpointRepository
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.services.repositories.vulnerability_repository import VulnerabilityRepository


logger = get_task_logger(__name__)


class DatabaseHooks(SecatorHooks):
    """Hooks for saving Secator results to database."""

    def __init__(self, scan_history_id, domain_id):
        """
        Initialize database hooks.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.subdomain_repo = SubdomainRepository()
        self.endpoint_repo = EndpointRepository()
        self.vulnerability_repo = VulnerabilityRepository()

    def on_item(self, item):
        """
        Save item to database based on type.

        Args:
            item: Secator result item

        Returns:
            item: Original item
        """
        try:
            item_type = item.get("_type")

            if item_type == "subdomain":
                self.subdomain_repo.save_from_secator(item, self.scan_history_id, self.domain_id)
            elif item_type == "url":
                self.endpoint_repo.save_from_secator(item, self.scan_history_id, self.domain_id)
            elif item_type == "vulnerability":
                self.vulnerability_repo.save_from_secator(item, self.scan_history_id, self.domain_id)
            else:
                logger.debug(f"Unhandled item type: {item_type}")

        except Exception as e:
            logger.error(f"Error saving item to database: {e}")

        return item

    def on_duplicate(self, item):
        """
        Handle duplicate item.

        Args:
            item: Duplicate item

        Returns:
            item: Original item
        """
        logger.debug(f"Duplicate item detected: {item.get('_type')} - {item.get('target')}")
        return item

    def on_error(self, item):
        """
        Handle error item.

        Args:
            item: Error item

        Returns:
            item: Original item
        """
        logger.error(f"Error item received: {item}")
        return item
