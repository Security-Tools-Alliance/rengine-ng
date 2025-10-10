"""
Built-in Secator Workflows Integration.

This module provides integration with Secator's built-in workflows,
which are pre-optimized and tested by the Secator team.
"""

import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from .config import get_secator_config


logger = get_task_logger(__name__)


class SecatorBuiltinWorkflowManager:
    """
    Manages Secator's built-in workflows integration with reNgine.
    These workflows are pre-optimized and tested by the Secator team.
    """

    # Mapping of Secator built-in workflows to their descriptions and use cases
    BUILTIN_WORKFLOWS = {
        "cidr_recon": {
            "name": "CIDR Reconnaissance",
            "description": "Local network reconnaissance for CIDR ranges",
            "input_type": "cidr",
            "use_cases": ["internal_network", "network_discovery"],
            "tools": ["nmap", "masscan", "httpx", "nuclei"],
        },
        "code_scan": {
            "name": "Code Vulnerability Scan",
            "description": "Code vulnerability scanning for repositories",
            "input_type": "repository",
            "use_cases": ["code_analysis", "sast"],
            "tools": ["semgrep", "gitleaks", "trufflehog"],
        },
        "host_recon": {
            "name": "Host Reconnaissance",
            "description": "Comprehensive host reconnaissance",
            "input_type": "host",
            "use_cases": ["host_discovery", "service_enumeration"],
            "tools": ["nmap", "httpx", "nuclei", "ffuf"],
        },
        "subdomain_recon": {
            "name": "Subdomain Discovery",
            "description": "Subdomain discovery and enumeration",
            "input_type": "domain",
            "use_cases": ["subdomain_enumeration", "reconnaissance"],
            "tools": ["subfinder", "dnsx", "httpx", "ffuf", "nuclei"],
        },
        "url_bypass": {
            "name": "URL Bypass",
            "description": "Try bypass techniques for 4xx URLs",
            "input_type": "url",
            "use_cases": ["bypass_techniques", "access_control"],
            "tools": ["ffuf", "httpx"],
        },
        "url_crawl": {
            "name": "URL Crawl (Fast)",
            "description": "Fast URL crawling and discovery",
            "input_type": "url",
            "use_cases": ["url_discovery", "content_crawling"],
            "tools": ["gau", "katana", "httpx", "cariddi"],
        },
        "url_dirsearch": {
            "name": "URL Directory Search",
            "description": "Directory and file discovery",
            "input_type": "url",
            "use_cases": ["directory_enumeration", "file_discovery"],
            "tools": ["ffuf", "gobuster", "dirb"],
        },
        "url_fuzz": {
            "name": "URL Fuzz (Slow)",
            "description": "Comprehensive URL fuzzing",
            "input_type": "url",
            "use_cases": ["parameter_fuzzing", "deep_enumeration"],
            "tools": ["ffuf", "wfuzz", "burp"],
        },
        "url_params_fuzz": {
            "name": "URL Parameters Fuzz",
            "description": "Extract parameters from URL and fuzz them",
            "input_type": "url",
            "use_cases": ["parameter_discovery", "api_testing"],
            "tools": ["paramspider", "ffuf", "httpx"],
        },
        "url_vuln": {
            "name": "URL Vulnerability Scan",
            "description": "URL vulnerability scanning with gf and dalfox",
            "input_type": "url",
            "use_cases": ["vulnerability_scanning", "xss_detection"],
            "tools": ["gf", "dalfox", "httpx"],
        },
        "user_hunt": {
            "name": "User Account Search",
            "description": "User account enumeration and discovery",
            "input_type": "domain",
            "use_cases": ["user_enumeration", "osint"],
            "tools": ["theharvester", "recon-ng", "sherlock"],
        },
        "wordpress": {
            "name": "WordPress Vulnerability Scan",
            "description": "WordPress-specific vulnerability scanning",
            "input_type": "url",
            "use_cases": ["wordpress_security", "cms_scanning"],
            "tools": ["wpscan", "nuclei", "httpx"],
        },
    }

    def __init__(self):
        """Initialize the built-in workflow manager."""
        self.config = get_secator_config()
        # Use a default workspace directory
        self.workspace_dir = os.path.join("/tmp", "secator_workspaces")
        os.makedirs(self.workspace_dir, exist_ok=True)

    def list_builtin_workflows(self) -> List[Dict[str, Any]]:
        """
        List all available built-in Secator workflows.

        Returns:
            List of workflow information dictionaries.
        """
        workflows = []
        for workflow_id, info in self.BUILTIN_WORKFLOWS.items():
            workflows.append(
                {
                    "id": workflow_id,
                    "name": info["name"],
                    "description": info["description"],
                    "input_type": info["input_type"],
                    "use_cases": info["use_cases"],
                    "tools": info["tools"],
                    "type": "builtin",
                }
            )
        return workflows

    def get_workflow_info(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific built-in workflow.

        Args:
            workflow_id: The ID of the built-in workflow.

        Returns:
            Workflow information dictionary or None if not found.
        """
        if workflow_id not in self.BUILTIN_WORKFLOWS:
            return None

        info = self.BUILTIN_WORKFLOWS[workflow_id].copy()
        info["id"] = workflow_id
        info["type"] = "builtin"
        return info

    def execute_builtin_workflow(
        self, workflow_id: str, target: str, ctx: Dict[str, Any], options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a built-in Secator workflow.

        Args:
            workflow_id: The ID of the built-in workflow to execute.
            target: The target to scan (domain, URL, IP, etc.).
            ctx: Context dictionary containing scan_id, domain_id, etc.
            options: Optional workflow-specific options.

        Returns:
            Dictionary containing execution results.
        """
        if workflow_id not in self.BUILTIN_WORKFLOWS:
            return {"success": False, "error": f"Unknown built-in workflow: {workflow_id}"}

        logger.info(f"Executing built-in Secator workflow '{workflow_id}' for target '{target}'")

        try:
            # Create a unique workspace for this execution
            workspace_name = f"rengine_{ctx.get('scan_id', 'unknown')}_{workflow_id}"
            workspace_path = os.path.join(self.workspace_dir, workspace_name)
            os.makedirs(workspace_path, exist_ok=True)

            # Build the Secator command
            cmd = self._build_secator_command(workflow_id, target, workspace_path, options)

            # Execute the command
            result = self._execute_secator_command(cmd, workspace_path)

            # Process results
            processed_results = self._process_secator_results(result, ctx)

            logger.info(f"Built-in workflow '{workflow_id}' completed for target '{target}'")
            return {
                "success": True,
                "workflow_id": workflow_id,
                "target": target,
                "results": processed_results,
                "workspace_path": workspace_path,
            }

        except Exception as e:
            logger.error(f"Error executing built-in workflow '{workflow_id}' for target '{target}': {e}")
            return {"success": False, "error": str(e), "workflow_id": workflow_id, "target": target}

    def _build_secator_command(
        self, workflow_id: str, target: str, workspace_path: str, options: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Build the Secator command for executing a built-in workflow.

        Args:
            workflow_id: The built-in workflow ID.
            target: The target to scan.
            workspace_path: Path to the workspace directory.
            options: Optional workflow-specific options.

        Returns:
            List of command arguments.
        """
        cmd = ["secator", "workflow", workflow_id, "--workspace", workspace_path, "--output", "json", "--quiet"]

        # Add workflow-specific options
        if options:
            for key, value in options.items():
                if isinstance(value, bool):
                    if value:
                        cmd.append(f"--{key}")
                else:
                    cmd.extend([f"--{key}", str(value)])

        # Add the target
        cmd.append(target)

        return cmd

    def _execute_secator_command(self, cmd: List[str], workspace_path: str) -> Dict[str, Any]:
        """
        Execute the Secator command and return results.

        Args:
            cmd: The command to execute.
            workspace_path: Path to the workspace directory.

        Returns:
            Dictionary containing execution results.
        """
        try:
            # Change to workspace directory
            original_cwd = os.getcwd()
            os.chdir(workspace_path)

            # Execute the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout
            )

            # Restore original directory
            os.chdir(original_cwd)

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "workspace_path": workspace_path,
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Secator command timed out: {' '.join(cmd)}")
            return {"returncode": -1, "stdout": "", "stderr": "Command timed out", "workspace_path": workspace_path}
        except Exception as e:
            logger.error(f"Error executing Secator command: {e}")
            return {"returncode": -1, "stdout": "", "stderr": str(e), "workspace_path": workspace_path}

    def _process_secator_results(self, result: Dict[str, Any], ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process Secator execution results and convert them to reNgine format.

        Args:
            result: The result from Secator command execution.
            ctx: Context dictionary.

        Returns:
            List of processed results.
        """
        processed_results = []

        if result["returncode"] != 0:
            logger.error(f"Secator command failed: {result['stderr']}")
            return processed_results

        # Parse JSON output from Secator
        try:
            if result["stdout"]:
                # Secator outputs JSON lines, one per result
                for line in result["stdout"].strip().split("\n"):
                    if line.strip():
                        try:
                            item = json.loads(line)
                            processed_item = self._convert_secator_output(item, ctx)
                            if processed_item:
                                processed_results.append(processed_item)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse JSON line: {line}")
        except Exception as e:
            logger.error(f"Error processing Secator results: {e}")

        return processed_results

    def _convert_secator_output(self, item: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert a single Secator output item to reNgine format.

        Args:
            item: The Secator output item.
            ctx: Context dictionary.

        Returns:
            Converted item or None if not applicable.
        """
        # Map Secator output types to reNgine models
        output_type = item.get("_type", "unknown")

        converted_item = {
            "scan_history_id": ctx.get("scan_id"),
            "domain_id": ctx.get("domain_id"),
            "source": "secator_builtin",
            "raw_data": item,
        }

        if output_type == "subdomain":
            converted_item.update({"subdomain": item.get("host", ""), "is_alive": True})
        elif output_type == "url":
            converted_item.update(
                {
                    "url": item.get("url", ""),
                    "status_code": item.get("status_code"),
                    "content_length": item.get("content_length"),
                    "page_title": item.get("title", ""),
                    "is_alive": True,
                }
            )
        elif output_type == "ip":
            converted_item.update({"ip_address": item.get("ip", ""), "is_alive": item.get("alive", False)})
        elif output_type == "vulnerability":
            converted_item.update(
                {
                    "name": item.get("name", ""),
                    "severity": item.get("severity", "info"),
                    "description": item.get("description", ""),
                    "extracted_results": item,
                }
            )
        else:
            # For unknown types, store as generic result
            converted_item["type"] = output_type
            converted_item["data"] = item

        return converted_item

    def get_workflow_help(self, workflow_id: str) -> Optional[str]:
        """
        Get help information for a built-in workflow.

        Args:
            workflow_id: The ID of the built-in workflow.

        Returns:
            Help text or None if workflow not found.
        """
        if workflow_id not in self.BUILTIN_WORKFLOWS:
            return None

        try:
            cmd = ["secator", "workflow", workflow_id, "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout if result.returncode == 0 else None
        except Exception as e:
            logger.error(f"Error getting help for workflow {workflow_id}: {e}")
            return None
