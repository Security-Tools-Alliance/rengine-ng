"""
ReNgine to Secator workflow converter.

This module converts reNgine's legacy scan engine configurations
to Secator workflow format, maintaining compatibility and functionality.
"""

import os
from typing import Any, Dict, List

from celery.utils.log import get_task_logger
import yaml


logger = get_task_logger(__name__)


class ReNgineToSecatorConverter:
    """
    Converts reNgine scan engine configurations to Secator workflows.

    This converter maintains the functionality of existing scan engines
    while providing the benefits of Secator's declarative workflow format.
    """

    def __init__(self):
        self.tool_mappings = self._initialize_tool_mappings()
        self.port_mappings = self._initialize_port_mappings()

    def _initialize_tool_mappings(self) -> Dict[str, str]:
        """Initialize mappings from reNgine tools to Secator tools."""
        return {
            "subfinder": "subfinder",
            "ctfr": "ctfr",
            "sublist3r": "sublist3r",
            "tlsx": "tlsx",
            "oneforall": "oneforall",
            "netlas": "netlas",
            "amass-passive": "amass",
            "amass-active": "amass",
            "naabu": "naabu",
            "nmap": "nmap",
            "httpx": "httpx",
            "nuclei": "nuclei",
            "dalfox": "dalfox",
            "crlfuzz": "crlfuzz",
            "s3scanner": "s3scanner",
            "gospider": "gospider",
            "hakrawler": "hakrawler",
            "waybackurls": "waybackurls",
            "katana": "katana",
            "gau": "gau",
            "ffuf": "ffuf",
        }

    def _initialize_port_mappings(self) -> Dict[str, str]:
        """Initialize mappings from reNgine port configurations to Secator."""
        return {
            "top-100": "top-100",
            "top-1000": "top-1000",
            "top-10000": "top-10000",
            "common": "top-100",
            "common-uncommon": "top-1000",
            "all": "1-65535",
        }

    def convert_scan_engine_file(self, file_path: str) -> Dict[str, Any]:
        """
        Convert a reNgine scan engine file to Secator workflow format.

        Args:
            file_path: Path to the reNgine scan engine YAML file

        Returns:
            Dict containing the Secator workflow configuration
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                rengine_config = yaml.safe_load(f)

            workflow_name = self._extract_workflow_name(file_path)
            return self.convert_scan_engine_content(rengine_config, workflow_name)

        except Exception as e:
            logger.error(f"Failed to convert scan engine file {file_path}: {e}")
            raise

    def convert_scan_engine_content(self, rengine_config: Dict[str, Any], workflow_name: str) -> Dict[str, Any]:
        """
        Convert reNgine scan engine content to Secator workflow format.

        Args:
            rengine_config: reNgine scan engine configuration
            workflow_name: Name for the workflow

        Returns:
            Dict containing the Secator workflow configuration
        """
        try:
            # Initialize Secator workflow structure
            secator_workflow = {
                "type": "workflow",
                "name": workflow_name,
                "description": f"Converted from reNgine scan engine: {workflow_name}",
                "tags": [rengine_config.get("scan_type", "recon")],
                "input_types": ["domain"],
                "tasks": {},
            }

            # Convert each section of the reNgine config
            self._convert_subdomain_discovery(rengine_config, secator_workflow)
            self._convert_port_scan(rengine_config, secator_workflow)
            self._convert_http_crawl(rengine_config, secator_workflow)
            self._convert_fetch_url(rengine_config, secator_workflow)
            self._convert_vulnerability_scan(rengine_config, secator_workflow)
            self._convert_dir_file_fuzz(rengine_config, secator_workflow)
            self._convert_screenshot(rengine_config, secator_workflow)
            self._convert_osint(rengine_config, secator_workflow)
            self._convert_waf_detection(rengine_config, secator_workflow)

            # Add global configuration
            self._add_global_config(rengine_config, secator_workflow)

            logger.info(f"Successfully converted scan engine to Secator workflow: {workflow_name}")
            return secator_workflow

        except Exception as e:
            logger.error(f"Failed to convert scan engine content: {e}")
            raise

    def _extract_workflow_name(self, file_path: str) -> str:
        """Extract workflow name from file path."""
        filename = os.path.basename(file_path)
        name = os.path.splitext(filename)[0]
        # Convert to valid workflow name (lowercase, underscores)
        return name.lower().replace(" ", "_").replace("-", "_")

    def _convert_subdomain_discovery(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert subdomain discovery configuration."""
        if "subdomain_discovery" not in config:
            return

        subdomain_config = config["subdomain_discovery"]
        tools = subdomain_config.get("uses_tools", ["subfinder"])

        # Use the first tool as primary, others as alternatives
        primary_tool = tools[0] if tools else "subfinder"
        secator_tool = self.tool_mappings.get(primary_tool, primary_tool)

        workflow["tasks"][secator_tool] = {
            "description": "Subdomain discovery",
            "rate_limit": subdomain_config.get("threads", 30),
            "timeout": subdomain_config.get("timeout", 5),
        }

        # Add additional tools if specified
        if len(tools) > 1:
            workflow["tasks"][secator_tool]["additional_tools"] = tools[1:]

    def _convert_port_scan(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert port scan configuration."""
        if "port_scan" not in config:
            return

        port_config = config["port_scan"]
        ports = port_config.get("ports", ["top-1000"])

        # Convert port configuration
        if isinstance(ports, list) and ports:
            port_str = ports[0] if isinstance(ports[0], str) else str(ports[0])
            secator_ports = self.port_mappings.get(port_str, port_str)
        else:
            secator_ports = "top-1000"

        workflow["tasks"]["naabu"] = {
            "description": "Port scanning",
            "rate_limit": port_config.get("rate_limit", 150),
            "timeout": port_config.get("timeout", 5),
            "ports": secator_ports,
            "targets_": [{"type": "subdomain", "field": "host"}],
        }

        # Add nmap if enabled
        if port_config.get("enable_nmap", False):
            workflow["tasks"]["nmap"] = {
                "description": "Service detection",
                "targets_": [{"type": "port", "field": "host:port"}],
                "script": port_config.get("nmap_script", "banner,version,discovery"),
            }

    def _convert_http_crawl(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert HTTP crawl configuration."""
        if "http_crawl" not in config:
            return

        crawl_config = config["http_crawl"]

        # HTTP crawl is typically handled by httpx in Secator
        workflow["tasks"]["httpx"] = {
            "description": "HTTP probing and crawling",
            "rate_limit": crawl_config.get("threads", 30),
            "timeout": crawl_config.get("timeout", 10),
            "targets_": [
                {
                    "type": "port",
                    "field": "host:port",
                    "condition": "item.port in [80, 443, 8080, 8081, 8082, 8443, 3000, 3001, 5000, 9000]",
                }
            ],
        }

    def _convert_fetch_url(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert fetch URL configuration."""
        if "fetch_url" not in config:
            return

        fetch_config = config["fetch_url"]
        tools = fetch_config.get("uses_tools", ["katana"])

        # Use katana as primary URL fetcher
        workflow["tasks"]["katana"] = {
            "description": "URL discovery and crawling",
            "rate_limit": fetch_config.get("threads", 30),
            "timeout": fetch_config.get("timeout", 10),
            "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
        }

        # Add additional URL discovery tools
        if "gau" in tools:
            workflow["tasks"]["gau"] = {
                "description": "URL discovery from archives",
                "targets_": [{"type": "subdomain", "field": "host"}],
            }

    def _convert_vulnerability_scan(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert vulnerability scan configuration."""
        if "vulnerability_scan" not in config:
            return

        vuln_config = config["vulnerability_scan"]

        if vuln_config.get("run_nuclei", True):
            nuclei_config = vuln_config.get("nuclei", {})

            workflow["tasks"]["nuclei"] = {
                "description": "Vulnerability scanning",
                "rate_limit": vuln_config.get("rate_limit", 150),
                "timeout": vuln_config.get("timeout", 5),
                "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
            }

            # Add nuclei-specific configuration
            if nuclei_config.get("severities"):
                workflow["tasks"]["nuclei"]["severities"] = nuclei_config["severities"]

            if nuclei_config.get("tags"):
                workflow["tasks"]["nuclei"]["tags"] = nuclei_config["tags"]

        # Add other vulnerability scanners if enabled
        if vuln_config.get("run_dalfox", False):
            workflow["tasks"]["dalfox"] = {
                "description": "XSS vulnerability scanning",
                "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
            }

    def _convert_dir_file_fuzz(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert directory and file fuzzing configuration."""
        if "dir_file_fuzz" not in config:
            return

        fuzz_config = config["dir_file_fuzz"]

        workflow["tasks"]["ffuf"] = {
            "description": "Directory and file fuzzing",
            "rate_limit": fuzz_config.get("rate_limit", 150),
            "timeout": fuzz_config.get("timeout", 5),
            "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
        }

        # Add wordlist configuration
        if fuzz_config.get("wordlist_name"):
            workflow["tasks"]["ffuf"]["wordlist"] = fuzz_config["wordlist_name"]

    def _convert_screenshot(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert screenshot configuration."""
        if "screenshot" not in config:
            return

        screenshot_config = config["screenshot"]

        workflow["tasks"]["aquatone"] = {
            "description": "Screenshot capture",
            "timeout": screenshot_config.get("timeout", 10),
            "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
        }

    def _convert_osint(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert OSINT configuration."""
        if "osint" not in config:
            return

        osint_config = config["osint"]

        # OSINT is typically handled by custom tools in Secator
        workflow["tasks"]["osint"] = {
            "description": "OSINT gathering",
            "intensity": osint_config.get("intensity", "normal"),
            "targets_": [{"type": "domain", "field": "domain"}],
        }

    def _convert_waf_detection(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Convert WAF detection configuration."""
        if "waf_detection" not in config:
            return

        # WAF detection is typically handled by nuclei in Secator
        workflow["tasks"]["waf_detection"] = {
            "description": "WAF detection",
            "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
        }

    def _add_global_config(self, config: Dict[str, Any], workflow: Dict[str, Any]) -> None:
        """Add global configuration to the workflow."""
        # Add custom headers if specified
        if "custom_header" in config:
            workflow["global_options"] = {"custom_header": config["custom_header"]}

        # Add scan type as metadata
        if "scan_type" in config:
            workflow["metadata"] = {"scan_type": config["scan_type"], "converted_from": "rengine"}

    def convert_all_scan_engines(self, source_dir: str, target_dir: str) -> List[str]:
        """
        Convert all scan engines in a directory to Secator workflows.

        Args:
            source_dir: Directory containing reNgine scan engine files
            target_dir: Directory to save converted Secator workflows

        Returns:
            List of converted workflow file paths
        """
        converted_files = []

        try:
            os.makedirs(target_dir, exist_ok=True)

            for filename in os.listdir(source_dir):
                if filename.endswith(".yaml") and not filename.startswith("."):
                    source_path = os.path.join(source_dir, filename)
                    target_path = os.path.join(target_dir, filename)

                    # Convert the scan engine
                    secator_workflow = self.convert_scan_engine_file(source_path)

                    # Save the converted workflow
                    with open(target_path, "w", encoding="utf-8") as f:
                        yaml.dump(secator_workflow, f, default_flow_style=False, sort_keys=False)

                    converted_files.append(target_path)
                    logger.info(f"Converted: {filename} -> {target_path}")

            logger.info(f"Successfully converted {len(converted_files)} scan engines to Secator workflows")
            return converted_files

        except Exception as e:
            logger.error(f"Failed to convert scan engines: {e}")
            raise
