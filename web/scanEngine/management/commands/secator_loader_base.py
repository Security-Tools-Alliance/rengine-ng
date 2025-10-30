"""
Base class for Secator loading commands.
Provides common functionality for loading tasks, workflows, and scans from Secator.
"""

import subprocess
from typing import List

from django.core.management.base import BaseCommand


class SecatorLoaderBase(BaseCommand):
    """Base class for Secator loading commands with common functionality."""

    def _execute_secator_command(self, cmd_parts: List[str]) -> subprocess.CompletedProcess:
        """Execute a secator command and return the result."""
        cmd = ["poetry", "run", "secator"] + cmd_parts
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd="/home/rengine",
            timeout=30,
        )

    def _extract_file_path_from_output(self, lines: List[str], resource_type: str) -> str:
        """Extract file path from secator output lines."""
        for i, line in enumerate(lines):
            if line.strip().startswith("/home/"):
                # The path might be truncated, so we'll construct it
                base_path = line.strip()
                # If the path is truncated, construct the full path
                if base_path.endswith("pyt"):
                    # This is the truncated path, construct the full one
                    return f"/home/rengine/.cache/pypoetry/virtualenvs/celery-rengine-HmEJnPQT-py3.12/lib/python3.12/site-packages/secator/configs/{resource_type}s/{resource_type}.yaml"
                # Check if the next line continues the path
                if i + 1 < len(lines) and lines[i + 1].strip().endswith(".yaml"):
                    return base_path + lines[i + 1].strip()
                return base_path

        # Fallback: construct the path directly
        # For scans, all files are in the scans/ directory
        if resource_type in ["domain", "host", "network", "subdomain", "url"]:
            return f"/home/rengine/.cache/pypoetry/virtualenvs/celery-rengine-HmEJnPQT-py3.12/lib/python3.12/site-packages/secator/configs/scans/{resource_type}.yaml"
        else:
            return f"/home/rengine/.cache/pypoetry/virtualenvs/celery-rengine-HmEJnPQT-py3.12/lib/python3.12/site-packages/secator/configs/{resource_type}s/{resource_type}.yaml"

    def _get_secator_yaml_config(self, command_parts: List[str], resource_type: str) -> str:
        """Get YAML configuration for a Secator resource (workflow, scan, etc.)."""
        try:
            result = self._execute_secator_command(command_parts)

            if result.returncode != 0:
                self.stdout.write(self.style.ERROR(f"Failed to get {resource_type}: {result.stderr}"))
                return ""

            # Secator outputs to stderr for both workflows and scans
            output = result.stderr or result.stdout
            lines = output.strip().split("\n")

            # For scans and workflows, construct the path directly since secator output is truncated
            if resource_type in ["domain", "host", "network", "subdomain", "url"]:
                file_path = f"/home/rengine/.cache/pypoetry/virtualenvs/celery-rengine-HmEJnPQT-py3.12/lib/python3.12/site-packages/secator/configs/scans/{resource_type}.yaml"
            elif resource_type in [
                "cidr_recon",
                "code_scan",
                "host_recon",
                "subdomain_recon",
                "url_bypass",
                "url_crawl",
                "url_dirsearch",
                "url_fuzz",
                "url_params_fuzz",
                "url_vuln",
                "user_hunt",
                "wordpress",
            ]:
                file_path = f"/home/rengine/.cache/pypoetry/virtualenvs/celery-rengine-HmEJnPQT-py3.12/lib/python3.12/site-packages/secator/configs/workflows/{resource_type}.yaml"
            else:
                # Find the file path (first line that starts with /home/)
                file_path = self._extract_file_path_from_output(lines, resource_type)

            # Read the YAML file directly
            with open(file_path, "r", encoding="utf-8") as f:
                yaml_content = f.read()

            return yaml_content.strip()

        except subprocess.TimeoutExpired:
            self.stdout.write(self.style.ERROR(f"Timeout getting {resource_type}"))
            return ""
        except FileNotFoundError:
            self.stdout.write(self.style.ERROR(f"{resource_type.title()} file not found: {file_path}"))
            return ""
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting {resource_type}: {e}"))
            return ""

    def _get_secator_tasks_list(self) -> str:
        """Get the list of available tasks from secator."""
        try:
            result = self._execute_secator_command(["t"])

            if result.returncode != 0:
                self.stdout.write(self.style.ERROR(f"Failed to get tasks list: {result.stderr}"))
                return ""

            return result.stdout

        except subprocess.TimeoutExpired:
            self.stdout.write(self.style.ERROR("Timeout getting tasks list"))
            return ""
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting tasks list: {e}"))
            return ""

    def _parse_tasks_output(self, output: str) -> List[dict]:
        """Parse the output of 'secator t' command to extract task information."""
        import re

        tasks = []
        lines = output.strip().split("\n")

        # Skip header lines and find the actual task list
        in_tasks_section = False
        current_task = None

        for line in lines:
            line = line.strip()

            # Skip empty lines and headers (but not task lines)
            if not line or line.startswith("Usage:"):
                continue

            # Check if we're in the tasks section
            if "Commands" in line:
                in_tasks_section = True
                continue

            # Check if we're leaving the tasks section
            if in_tasks_section and line.startswith("╰─"):
                in_tasks_section = False
                continue

            if in_tasks_section and line.startswith("│"):
                # Remove the border character and parse the task line
                task_line = line[1:].strip()  # Remove leading │

                # Skip continuation lines (lines that don't start with a task name)
                if not task_line or task_line.startswith("─"):
                    continue

                # Use regex to parse task lines
                # Pattern: task_name   category   description
                # Handle multi-line descriptions
                match = re.match(r"^(\w+)\s+([^\s]+)\s+(.+)$", task_line)
                if match:
                    task_name = match.group(1)
                    category = match.group(2)
                    description = match.group(3).rstrip("│").strip()  # Remove trailing │

                    # Save previous task if exists
                    if current_task:
                        tasks.append(current_task)

                    # Start new task
                    current_task = {
                        "name": task_name,
                        "task_type": task_name,
                        "category": category,
                        "description": description,
                        "is_builtin": True,
                        "is_active": True,
                    }
                elif current_task and task_line:
                    # This is a continuation line, append to description
                    current_task["description"] += " " + task_line

        # Don't forget the last task
        if current_task:
            tasks.append(current_task)

        return tasks

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
