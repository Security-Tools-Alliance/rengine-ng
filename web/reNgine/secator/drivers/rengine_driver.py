"""
Main reNgine driver for Secator.
Combines all hooks needed for reNgine integration.
"""

from celery.utils.log import get_task_logger

from reNgine.secator.hooks.database_hooks import DatabaseHooks
from reNgine.secator.hooks.progress_hooks import ProgressHooks


logger = get_task_logger(__name__)


class ReNgineDriver:
    """
    Main driver that orchestrates all hooks for reNgine.
    Following Secator's driver pattern.
    """

    def __init__(self, scan_history_id, domain_id, notification_config=None):
        """
        Initialize reNgine driver.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            notification_config: Optional notification configuration
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.notification_config = notification_config or {}

        self.db_hooks = DatabaseHooks(scan_history_id, domain_id)
        self.progress_hooks = ProgressHooks(scan_history_id)

    def get_hooks_config(self):
        """
        Returns hooks configuration for Secator runners.
        Format: {RunnerClass: {hook_name: [hook_functions]}}

        Returns:
            dict: Hooks configuration
        """
        try:
            from secator.runners import Scan, Task, Workflow
        except ImportError as e:
            logger.error("Failed to import Secator runners")
            raise ImportError("Failed to import Secator runners. Ensure secator is installed and available.") from e

        return {
            Workflow: {
                "on_init": [self._create_workflow_init_hook()],
                "on_start": [self._create_workflow_start_hook()],
                "on_iter": [self._create_workflow_iter_hook()],
                "on_end": [self._create_workflow_end_hook()],
            },
            Task: {
                "on_init": [self._create_task_init_hook()],
                "on_item": [self._create_task_item_hook()],
                "on_duplicate": [self._create_task_duplicate_hook()],
                "on_iter": [self._create_task_iter_hook()],
                "on_end": [self._create_task_end_hook()],
                "on_error": [self._create_task_error_hook()],
            },
            Scan: {
                "on_init": [self._create_scan_init_hook()],
                "on_start": [self._create_scan_start_hook()],
                "on_iter": [self._create_scan_iter_hook()],
                "on_end": [self._create_scan_end_hook()],
            },
        }

    def _create_workflow_init_hook(self):
        """Create workflow init hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_init()
        return hook

    def _create_workflow_start_hook(self):
        """Create workflow start hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_start()
        return hook

    def _create_workflow_iter_hook(self):
        """Create workflow iteration hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_iter()
        return hook

    def _create_workflow_end_hook(self):
        """Create workflow end hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_end()
        return hook

    def _create_task_init_hook(self):
        """Create task init hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_init()
        return hook

    def _create_task_item_hook(self):
        """Create task item hook."""
        def hook(_secator_runner, item):
            return self.db_hooks.on_item(item)
        return hook

    def _create_task_duplicate_hook(self):
        """Create task duplicate hook."""
        def hook(_secator_runner, item):
            return self.db_hooks.on_duplicate(item)
        return hook

    def _create_task_iter_hook(self):
        """Create task iteration hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_iter()
        return hook

    def _create_task_end_hook(self):
        """Create task end hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_end()
        return hook

    def _create_task_error_hook(self):
        """Create task error hook."""
        def hook(_secator_runner, item):
            return self.db_hooks.on_error(item)
        return hook

    def _create_scan_init_hook(self):
        """Create scan init hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_init()
        return hook

    def _create_scan_start_hook(self):
        """Create scan start hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_start()
        return hook

    def _create_scan_iter_hook(self):
        """Create scan iteration hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_iter()
        return hook

    def _create_scan_end_hook(self):
        """Create scan end hook."""
        def hook(_secator_runner):
            self.progress_hooks.on_end()
        return hook
