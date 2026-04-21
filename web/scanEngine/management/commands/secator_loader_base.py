"""
Base class for Secator loading commands.
Provides common functionality for loading tasks, workflows, and scans from Secator.
"""

from django.core.management.base import BaseCommand


class SecatorLoaderBase(BaseCommand):
    """Base class for Secator loading commands with common functionality."""

    def _determine_scan_type_from_yaml(self, yaml_data: dict) -> str:
        """Determine scan type based on YAML content."""
        # Check for specific keywords in workflows or description
        workflows = yaml_data.get("workflows", {})
        description = yaml_data.get("description", "").lower()

        # Keywords that indicate internal network scanning
        internal_keywords = ["nmap", "naabu", "fping", "cidr", "network", "port"]

        # Check if any internal keywords are present in workflows
        for workflow_name, workflow_config in workflows.items():
            if isinstance(workflow_config, dict):
                workflow_name_lower = workflow_name.lower()
                if any(keyword in workflow_name_lower for keyword in internal_keywords):
                    return "internal_network"

        # Check description for internal keywords
        if any(keyword in description for keyword in internal_keywords):
            return "internal_network"

        # Default to internet for most scans
        return "internet"
