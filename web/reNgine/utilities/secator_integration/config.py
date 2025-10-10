"""
Secator configuration management for reNgine integration.

This module handles the configuration of Secator to work seamlessly with
reNgine's existing infrastructure, particularly Redis and Celery.
"""

import os
from typing import Any, Dict

from celery.utils.log import get_task_logger
from django.conf import settings


logger = get_task_logger(__name__)


class SecatorConfig:
    """
    Configuration manager for Secator integration.

    This class manages the configuration of Secator to use reNgine's
    existing Redis and Celery infrastructure.
    """

    def __init__(self):
        self._config_initialized = False
        self._secator_config = None

    def initialize(self) -> None:
        """Initialize Secator configuration with reNgine settings."""
        if self._config_initialized:
            return

        try:
            # Import Secator config only when needed
            from secator.config import Config

            # Create a new Config instance
            config = Config()

            # Configure Secator output directory
            secator_output_dir = os.path.join(settings.BASE_DIR, "secator_outputs")
            os.makedirs(secator_output_dir, exist_ok=True)

            # Set basic configuration
            config.set("output_dir", secator_output_dir)
            config.set("log_level", "INFO")

            # Try to set Redis configuration if supported
            try:
                redis_url = self._get_redis_url()
                config.set("celery.broker_url", redis_url)
                config.set("celery.result_backend", redis_url)
            except Exception as e:
                logger.warning(f"Could not set Redis configuration: {e}")

            self._secator_config = config
            self._config_initialized = True

            logger.info("Secator configuration initialized successfully")

        except ImportError as e:
            logger.error(f"Failed to import Secator: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Secator configuration: {e}")
            raise

    def _get_redis_url(self) -> str:
        """Get Redis URL from reNgine settings."""
        redis_host = getattr(settings, "REDIS_HOST", "localhost")
        redis_port = getattr(settings, "REDIS_PORT", 6379)
        redis_db = getattr(settings, "REDIS_DB", 0)
        redis_password = getattr(settings, "REDIS_PASSWORD", None)

        if redis_password:
            return f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
        else:
            return f"redis://{redis_host}:{redis_port}/{redis_db}"

    def _get_task_routes(self) -> Dict[str, Dict[str, str]]:
        """Get task routes configuration for Secator tasks."""
        return {
            "secator.tasks.*": {"queue": "run_command_queue"},
            "secator.workflows.*": {"queue": "orchestrator_queue"},
            "secator.scans.*": {"queue": "orchestrator_queue"},
        }

    def get_config(self) -> Any:
        """Get the initialized Secator config object."""
        if not self._config_initialized:
            self.initialize()
        return self._secator_config

    def is_initialized(self) -> bool:
        """Check if Secator configuration is initialized."""
        return self._config_initialized


# Global configuration instance
_secator_config = None


def get_secator_config() -> SecatorConfig:
    """Get the global Secator configuration instance."""
    global _secator_config
    if _secator_config is None:
        _secator_config = SecatorConfig()
        _secator_config.initialize()
    return _secator_config


def ensure_secator_initialized() -> None:
    """Ensure Secator is properly initialized."""
    config = get_secator_config()
    if not config.is_initialized():
        config.initialize()
