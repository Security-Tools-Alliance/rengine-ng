"""
Pure API driver for Secator workers.
No Django dependencies - only HTTP API calls.
"""

import logging
import os

from reNgine.secator.hooks.base import SecatorHooks
from reNgine.secator.hooks.database_hooks import DatabaseHooks
from reNgine.secator.hooks.progress_hooks import ProgressHooks


logger = logging.getLogger(__name__)


class APISecatorHooks(SecatorHooks):
    """Secator hooks implementation using API calls."""

    def __init__(self, scan_history_id, domain_id, rengine_context=None):
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.rengine_context = rengine_context or {}

        # Initialize API hooks
        self.db_hooks = DatabaseHooks(scan_history_id, domain_id, rengine_context=self.rengine_context)
        self.progress_hooks = ProgressHooks(scan_history_id, domain_id)

        logger.info(f"🔧 APISecatorHooks initialized for scan {scan_history_id}, domain {domain_id}")

    def on_init(self, runner=None):
        """Execute when runner init is completed."""
        logger.info(f"🎯 on_init called for scan {self.scan_history_id}")
        return self.progress_hooks.on_init(runner)

    def on_start(self, runner=None):
        """Execute when runner starts."""
        logger.info(f"🎯 on_start called for scan {self.scan_history_id}")
        return self.progress_hooks.on_start(runner)

    def on_iter(self, runner=None):
        """Execute on each iteration."""
        logger.info(f"🎯 on_iter called for scan {self.scan_history_id}")
        return self.progress_hooks.on_iter(runner)

    def on_end(self, runner=None):
        """Execute when runner finishes."""
        logger.info(f"🎯 on_end called for scan {self.scan_history_id}")
        return self.progress_hooks.on_end(runner)

    def on_item(self, runner, item):
        """Execute when item is emitted."""
        logger.info(f"🎯 on_item called for scan {self.scan_history_id}")
        return self.db_hooks.on_item(item)

    def on_duplicate(self, runner, item):
        """Execute when duplicate detected."""
        logger.info(f"🎯 on_duplicate called for scan {self.scan_history_id}")
        return self.db_hooks.on_duplicate(item)

    def on_error(self, runner, item):
        """Execute on error."""
        logger.info(f"🎯 on_error called for scan {self.scan_history_id}")
        return self.db_hooks.on_error(item)


class SerializableAPIHook:
    """Base class for serializable API hooks."""

    def __init__(self, scan_history_id, domain_id, hook_type, hook_method, rengine_context=None):
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.hook_type = hook_type
        self.hook_method = hook_method
        self.rengine_context = rengine_context or {}

        # Add function-like attributes for Secator compatibility
        self.__name__ = f"{hook_type}_{hook_method}_hook"
        self.__qualname__ = f"SerializableAPIHook.{self.__name__}"
        self.__module__ = __name__

    def __call__(self, *args, **kwargs):
        """Execute the hook by recreating the necessary objects."""
        logger.info(
            f"🎯 Hook called: {self.hook_type}.{self.hook_method} with args={len(args)}, kwargs={list(kwargs.keys())}"
        )
        try:
            # Recreate the necessary hook objects
            if self.hook_type == "progress":
                hook_obj = ProgressHooks(self.scan_history_id)
            elif self.hook_type == "database":
                hook_obj = DatabaseHooks(self.scan_history_id, self.domain_id, rengine_context=self.rengine_context)
            else:
                logger.error(f"Unknown hook type: {self.hook_type}")
                return

            # Call the appropriate method
            method = getattr(hook_obj, self.hook_method)
            logger.info(f"🎯 Executing {self.hook_type}.{self.hook_method}")
            result = method(*args, **kwargs)
            logger.info(f"🎯 Hook {self.hook_type}.{self.hook_method} completed successfully")
            return result
        except Exception as e:
            logger.error(f"❌ Error executing {self.hook_type} hook {self.hook_method}: {e}")
            import traceback

            logger.error(f"❌ Traceback: {traceback.format_exc()}")


class SerializableAPIWorkflowHook:
    """Serializable workflow hook for API mode."""

    def __init__(self, scan_history_id, domain_id, hook_type, hook_method, rengine_context=None):
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.hook_type = hook_type
        self.hook_method = hook_method
        self.rengine_context = rengine_context or {}

        # Add function-like attributes for Secator compatibility
        self.__name__ = f"workflow_{hook_type}_{hook_method}_hook"
        self.__qualname__ = f"SerializableAPIWorkflowHook.{self.__name__}"
        self.__module__ = __name__

    def __call__(self, secator_runner):
        """Execute the workflow hook."""
        try:
            if self.hook_type == "file_sync":
                # File sync hooks are not supported in pure API mode
                logger.debug("File sync hooks not supported in pure API mode")
            else:
                logger.error(f"Unknown workflow hook type: {self.hook_type}")
        except Exception as e:
            logger.error(f"Error executing workflow hook {self.hook_method}: {e}")


class SerializableAPITaskHook:
    """Serializable task hook for API mode."""

    def __init__(self, scan_history_id, domain_id, hook_type, hook_method, rengine_context=None):
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.hook_type = hook_type
        self.hook_method = hook_method
        self.rengine_context = rengine_context or {}

        # Add function-like attributes for Secator compatibility
        self.__name__ = f"task_{hook_type}_{hook_method}_hook"
        self.__qualname__ = f"SerializableAPITaskHook.{self.__name__}"
        self.__module__ = __name__

    def __call__(self, secator_runner, item=None):
        """Execute the task hook."""
        try:
            if self.hook_type == "file_sync":
                # File sync hooks are not supported in pure API mode
                logger.debug("File sync hooks not supported in pure API mode")
            else:
                logger.error(f"Unknown task hook type: {self.hook_type}")
        except Exception as e:
            logger.error(f"Error executing task hook {self.hook_method}: {e}")


class ReNgineDriver:
    """
    Pure API driver for Secator workers.
    Combines all hooks needed for reNgine integration via API only.
    """

    def __init__(self, scan_history_id, domain_id, notification_config=None, rengine_context=None):
        """
        Initialize API driver.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            notification_config: Optional notification configuration
            rengine_context: Optional reNgine context
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.notification_config = notification_config or {}
        self.rengine_context = rengine_context or {}

        logger.info(f"🔧 ReNgineDriver initialized for scan {scan_history_id}, domain {domain_id}")
        logger.info(f"🔧 API URL: {os.getenv('RENGINE_API_URL', 'NOT SET')}")
        logger.info(f"🔧 API Key: {'SET' if os.getenv('RENGINE_API_KEY') else 'NOT SET'}")

        # Initialize API hooks
        self.db_hooks = DatabaseHooks(scan_history_id, domain_id, rengine_context=self.rengine_context)
        self.progress_hooks = ProgressHooks(scan_history_id, domain_id)

        logger.info("🔧 Hooks initialized successfully")

    def _create_hook_function(self, hook_type, hook_method):
        """Create a simple function for Secator hooks."""

        def hook_function(*args, **kwargs):
            logger.info(
                f"🎯 Hook called: {hook_type}.{hook_method} with args={len(args)}, kwargs={list(kwargs.keys())}"
            )
            try:
                # Recreate the necessary hook objects
                if hook_type == "progress":
                    hook_obj = ProgressHooks(self.scan_history_id)
                elif hook_type == "database":
                    hook_obj = DatabaseHooks(self.scan_history_id, self.domain_id, rengine_context=self.rengine_context)
                else:
                    logger.error(f"Unknown hook type: {hook_type}")
                    return

                # Call the appropriate method
                method = getattr(hook_obj, hook_method)
                logger.info(f"🎯 Executing {hook_type}.{hook_method}")
                result = method(*args, **kwargs)
                logger.info(f"🎯 Hook {hook_type}.{hook_method} completed successfully")
                return result
            except Exception as e:
                logger.error(f"❌ Error executing {hook_type} hook {hook_method}: {e}")
                import traceback

                logger.error(f"❌ Traceback: {traceback.format_exc()}")

        # Set function attributes for debugging
        hook_function.__name__ = f"{hook_type}_{hook_method}_hook"
        hook_function.__qualname__ = f"ReNgineDriver.{hook_function.__name__}"
        hook_function.__module__ = __name__

        return hook_function

    def get_hooks(self):
        """Get all hooks for Secator integration."""
        return {
            # Progress hooks
            "on_init": self._create_hook_function("progress", "on_init"),
            "on_start": self._create_hook_function("progress", "on_start"),
            "on_iter": self._create_hook_function("progress", "on_iter"),
            "on_end": self._create_hook_function("progress", "on_end"),
            # Database hooks
            "on_item": self._create_hook_function("database", "on_item"),
            "on_duplicate": self._create_hook_function("database", "on_duplicate"),
            "on_error": self._create_hook_function("database", "on_error"),
        }

    def get_workflow_hooks(self):
        """Get workflow hooks for Secator integration."""

        def workflow_hook_function(*args, **kwargs):
            logger.info(f"🎯 Workflow hook called with args={len(args)}, kwargs={list(kwargs.keys())}")
            # File sync hooks are not supported in pure API mode
            logger.debug("File sync hooks not supported in pure API mode")

        workflow_hook_function.__name__ = "workflow_hook"
        workflow_hook_function.__qualname__ = "ReNgineDriver.workflow_hook"
        workflow_hook_function.__module__ = __name__

        return {
            "on_workflow_start": workflow_hook_function,
            "on_workflow_complete": workflow_hook_function,
        }

    def get_task_hooks(self):
        """Get task hooks for Secator integration."""

        def task_hook_function(*args, **kwargs):
            logger.info(f"🎯 Task hook called with args={len(args)}, kwargs={list(kwargs.keys())}")
            # File sync hooks are not supported in pure API mode
            logger.debug("File sync hooks not supported in pure API mode")

        task_hook_function.__name__ = "task_hook"
        task_hook_function.__qualname__ = "ReNgineDriver.task_hook"
        task_hook_function.__module__ = __name__

        return {
            "on_task_complete": task_hook_function,
        }

    def get_hooks_config(self):
        """Get hooks configuration for Secator integration."""
        # Create hooks instance
        hooks_instance = APISecatorHooks(
            scan_history_id=self.scan_history_id, domain_id=self.domain_id, rengine_context=self.rengine_context
        )

        # Return hooks in the format expected by Secator
        # According to Secator docs: hooks={Workflow: {...}, Task: {...}}
        from secator.runners import Task, Workflow

        hooks_config = {
            Workflow: {
                "on_init": [hooks_instance.on_init],
                "on_start": [hooks_instance.on_start],
                "on_iter": [hooks_instance.on_iter],
                "on_end": [hooks_instance.on_end],
            },
            Task: {
                "on_init": [hooks_instance.on_init],
                "on_start": [hooks_instance.on_start],
                "on_iter": [hooks_instance.on_iter],
                "on_end": [hooks_instance.on_end],
                "on_item": [hooks_instance.on_item],
                "on_duplicate": [hooks_instance.on_duplicate],
                "on_error": [hooks_instance.on_error],
            },
        }

        logger.info("🔧 get_hooks_config called - returning hooks for Workflow and Task runners")
        logger.info(f"🔧 Workflow hooks: {list(hooks_config[Workflow].keys())}")
        logger.info(f"🔧 Task hooks: {list(hooks_config[Task].keys())}")

        return hooks_config
