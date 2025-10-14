"""
SecatorConfigConverter - Convert reNgine configuration to Secator format.

This module handles the conversion of reNgine scan configurations
to Secator-compatible configuration format.
"""

import logging
from typing import Any, Dict

from django.conf import settings


logger = logging.getLogger(__name__)


class SecatorConfigConverter:
    """
    Convert reNgine configuration to Secator format.

    This class handles the conversion of reNgine scan configurations
    to Secator-compatible configuration format.
    """

    def __init__(self):
        """Initialize the SecatorConfigConverter."""
        pass

    def convert(self, scan_config: Any) -> Dict[str, Any]:
        """
        Convert reNgine scan configuration to Secator format.

        Args:
            scan_config: reNgine scan configuration (SecatorScan or EngineType)

        Returns:
            Secator-compatible configuration dictionary
        """
        try:
            if hasattr(scan_config, "execution_mode"):
                # This is a SecatorScan
                return self._convert_secator_scan(scan_config)
            else:
                # This is a legacy EngineType
                return self._convert_engine_type(scan_config)

        except Exception as e:
            logger.error(f"Error converting scan configuration: {e}")
            return self._get_default_config()

    def _convert_secator_scan(self, scan_config: Any) -> Dict[str, Any]:
        """
        Convert SecatorScan to Secator configuration.

        Args:
            scan_config: SecatorScan instance

        Returns:
            Secator configuration dictionary
        """
        config = self._get_default_config()

        # Add scan-specific configuration
        config.update(
            {
                "scan_name": scan_config.name,
                "scan_type": scan_config.scan_type,
                "execution_mode": scan_config.execution_mode,
            }
        )

        # Add workflow or tasks configuration
        if scan_config.execution_mode == "workflow" and scan_config.workflow:
            config["workflow"] = {
                "name": scan_config.workflow.name,
                "type": scan_config.workflow.workflow_type,
                "yaml_config": scan_config.workflow.yaml_configuration,
            }
        elif scan_config.execution_mode == "tasks":
            config["tasks"] = [
                {
                    "name": task.name,
                    "type": task.task_type,
                    "yaml_config": task.yaml_configuration,
                }
                for task in scan_config.tasks.all()
            ]

        return config

    def _convert_engine_type(self, engine_type: Any) -> Dict[str, Any]:
        """
        Convert legacy EngineType to Secator configuration.

        Args:
            engine_type: EngineType instance

        Returns:
            Secator configuration dictionary
        """
        config = self._get_default_config()

        # Add engine-specific configuration
        config.update(
            {
                "scan_name": engine_type.name,
                "scan_type": engine_type.scan_type,
                "execution_mode": "legacy",
            }
        )

        # Parse YAML configuration if available
        if hasattr(engine_type, "yaml_configuration") and engine_type.yaml_configuration:
            try:
                import yaml

                yaml_config = yaml.safe_load(engine_type.yaml_configuration)
                if yaml_config:
                    config.update(yaml_config)
            except Exception as e:
                logger.warning(f"Error parsing YAML configuration: {e}")

        return config

    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default Secator configuration.

        Returns:
            Default configuration dictionary
        """
        return {
            "global": {
                "timeout": 300,
                "concurrency": 20,
                "rate_limit": 150,
            },
            "proxy": {
                "enabled": False,
                "http": "",
                "https": "",
            },
            "output": {
                "format": "json",
                "save_results": True,
                "stream_results": True,
            },
            "celery": {
                "broker_url": getattr(settings, "CELERY_BROKER_URL", "redis://redis:6379/0"),
                "result_backend": getattr(settings, "CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
            },
        }

    def convert_proxy_config(self, proxy_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert reNgine proxy configuration to Secator format.

        Args:
            proxy_config: reNgine proxy configuration

        Returns:
            Secator proxy configuration
        """
        secator_proxy = {
            "enabled": False,
            "http": "",
            "https": "",
        }

        if proxy_config and proxy_config.get("enabled", False):
            secator_proxy["enabled"] = True

            # Convert proxy URL format if needed
            proxy_url = proxy_config.get("url", "")
            if proxy_url:
                secator_proxy["http"] = proxy_url
                secator_proxy["https"] = proxy_url

        return secator_proxy

    def convert_thread_config(self, thread_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert reNgine thread configuration to Secator format.

        Args:
            thread_config: reNgine thread configuration

        Returns:
            Secator thread configuration
        """
        secator_threads = {
            "concurrency": 20,
            "rate_limit": 150,
        }

        if thread_config:
            if "threads" in thread_config:
                secator_threads["concurrency"] = thread_config["threads"]
            if "rate_limit" in thread_config:
                secator_threads["rate_limit"] = thread_config["rate_limit"]

        return secator_threads

    def convert_timeout_config(self, timeout_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert reNgine timeout configuration to Secator format.

        Args:
            timeout_config: reNgine timeout configuration

        Returns:
            Secator timeout configuration
        """
        secator_timeout = {
            "timeout": 300,
        }

        if timeout_config and "timeout" in timeout_config:
            secator_timeout["timeout"] = timeout_config["timeout"]

        return secator_timeout

    def merge_configs(self, *configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge multiple configuration dictionaries recursively.

        Args:
            *configs: Configuration dictionaries to merge

        Returns:
            Merged configuration dictionary
        """
        merged_config = {}

        for config in configs:
            if config:
                merged_config = self._recursive_merge(merged_config, config)

        return merged_config

    def _recursive_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge two dictionaries, preserving nested structures.

        Args:
            base: Base dictionary to merge into
            update: Dictionary to merge from

        Returns:
            Recursively merged dictionary
        """
        result = base.copy()

        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Both values are dictionaries, merge recursively
                result[key] = self._recursive_merge(result[key], value)
            else:
                # Overwrite with new value (or first occurrence)
                result[key] = value

        return result
