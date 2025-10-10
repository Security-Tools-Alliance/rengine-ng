"""
Refactored subdomain discovery tasks using distributed utilities.

This module provides subdomain discovery functionality using the distributed utilities
architecture, eliminating circular dependencies and following SOLID, KISS, and DRY principles.

Key components:
1. Subdomain discovery tasks that use distributed utilities
2. No direct imports from other task modules
3. Clean separation of concerns
4. Reusable distributed processing
"""

import json
import os
from typing import Any, Dict, List

from celery.utils.log import get_task_logger
import validators

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    AMASS_WORDLIST,
    SUBDOMAIN_SCAN_DEFAULT_TOOLS,
    TIMEOUT,
    USE_AMASS_CONFIG,
    USE_SUBFINDER_CONFIG,
)
from reNgine.settings import (
    DEFAULT_THREADS,
    RENGINE_TOOL_GITHUB_PATH,
)
from reNgine.utilities.distributed.command import DistributedCommandBuilder
from reNgine.utilities.distributed.utilities import create_balanced_config, get_distributed_utilities


logger = get_task_logger(__name__)


class SubdomainDiscoveryProcessor:
    """Subdomain discovery processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()
        self.dns_processor = self.distributed_utils.get_dns_processor()

    def process_subdomain_discovery_batch(
        self, hosts: List[str], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> Dict[str, Any]:
        """Process a batch of hosts for subdomain discovery"""
        try:
            # Validate hosts
            valid_hosts = [host for host in hosts if validators.domain(host)]
            if not valid_hosts:
                return {"success": False, "error": "No valid hosts provided", "batch_id": batch_id}

            # Execute subdomain discovery commands
            discovery_results = self._execute_subdomain_discovery_commands(valid_hosts, ctx, batch_id, **kwargs)

            # Parse discovery results
            parsed_results = self._parse_subdomain_discovery_results(discovery_results, ctx, batch_id, **kwargs)

            # Resolve discovered subdomains
            resolved_results = self._resolve_discovered_subdomains(parsed_results, ctx, batch_id, **kwargs)

            # Save subdomains using distributed database processor
            saved_results = self._save_discovered_subdomains(resolved_results, ctx, batch_id, **kwargs)

            return {
                "success": True,
                "batch_id": batch_id,
                "processed_hosts": len(valid_hosts),
                "discovered_subdomains": len(parsed_results),
                "saved_subdomains": saved_results.get("saved_count", 0),
                "results": saved_results,
            }

        except Exception as e:
            logger.error(f"Subdomain discovery batch processing failed for batch {batch_id}: {e}")
            return {"success": False, "error": str(e), "batch_id": batch_id}

    def _execute_subdomain_discovery_commands(
        self, hosts: List[str], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """Execute subdomain discovery commands using distributed command processor"""
        commands = []
        tools = ctx.get("tools", SUBDOMAIN_SCAN_DEFAULT_TOOLS)

        for host in hosts:
            for tool in tools:
                if tool == "subfinder":
                    command = self._build_subfinder_command(host, ctx)
                elif tool == "amass":
                    command = self._build_amass_command(host, ctx)
                elif tool == "assetfinder":
                    command = self._build_assetfinder_command(host, ctx)
                else:
                    continue

                if command:
                    commands.append(
                        {
                            "command": command,
                            "host": host,
                            "tool": tool,
                            "output_file": f"/tmp/{tool}_{batch_id}_{hash(host)}.txt",
                        }
                    )

        # Execute commands using distributed command processor
        command_result = self.command_processor.execute_commands_batch(
            [cmd["command"] for cmd in commands], batch_id, **kwargs
        )

        return commands if command_result.is_successful else []

    def _build_subfinder_command(self, host: str, ctx: Dict[str, Any]) -> str:
        """Build subfinder command"""
        command_builder = DistributedCommandBuilder("subfinder")
        command_builder.add_flag("-silent")
        command_builder.add_flag("-json")
        command_builder.add_option("-d", host)
        command_builder.add_option("-t", ctx.get("threads", DEFAULT_THREADS))
        command_builder.add_option("-timeout", ctx.get("timeout", TIMEOUT))

        # Add config file if available
        if USE_SUBFINDER_CONFIG:
            config_path = os.path.join(RENGINE_TOOL_GITHUB_PATH, "subfinder", "config.yaml")
            if os.path.exists(config_path):
                command_builder.add_option("-config", config_path)

        return command_builder.build()

    def _build_amass_command(self, host: str, ctx: Dict[str, Any]) -> str:
        """Build amass command"""
        command_builder = DistributedCommandBuilder("amass")
        command_builder.add_flag("enum")
        command_builder.add_flag("-silent")
        command_builder.add_flag("-json")
        command_builder.add_option("-d", host)
        command_builder.add_option("-t", ctx.get("threads", DEFAULT_THREADS))
        command_builder.add_option("-timeout", ctx.get("timeout", TIMEOUT))

        # Add wordlist if available
        if AMASS_WORDLIST and os.path.exists(AMASS_WORDLIST):
            command_builder.add_option("-w", AMASS_WORDLIST)

        # Add config file if available
        if USE_AMASS_CONFIG:
            config_path = os.path.join(RENGINE_TOOL_GITHUB_PATH, "amass", "config.ini")
            if os.path.exists(config_path):
                command_builder.add_option("-config", config_path)

        return command_builder.build()

    def _build_assetfinder_command(self, host: str, ctx: Dict[str, Any]) -> str:
        """Build assetfinder command"""
        command_builder = DistributedCommandBuilder("assetfinder")
        command_builder.add_flag("-subs-only")
        command_builder.add_argument(host)

        return command_builder.build()

    def _parse_subdomain_discovery_results(
        self, discovery_results: List[Dict[str, Any]], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> List[str]:
        """Parse subdomain discovery results"""
        discovered_subdomains = set()

        for result in discovery_results:
            output_file = result.get("output_file")
            if not output_file or not os.path.exists(output_file):
                continue

            try:
                with open(output_file, "r") as f:
                    if result.get("tool") in ["subfinder", "amass"]:
                        # JSON output
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                if "host" in data:
                                    discovered_subdomains.add(data["host"])
                            except json.JSONDecodeError:
                                continue
                    else:
                        # Text output
                        for line in f:
                            subdomain = line.strip()
                            if subdomain and validators.domain(subdomain):
                                discovered_subdomains.add(subdomain)
            except Exception as e:
                logger.error(f"Error parsing subdomain discovery results from {output_file}: {e}")
                continue

        return list(discovered_subdomains)

    def _resolve_discovered_subdomains(
        self, subdomains: List[str], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """Resolve discovered subdomains using distributed DNS processor"""
        if not subdomains:
            return []

        # Resolve subdomains using distributed DNS processor
        dns_result = self.dns_processor.resolve_domains_batch(subdomains, batch_id, **kwargs)

        if not dns_result.is_successful:
            logger.error(f"DNS resolution failed for batch {batch_id}: {dns_result.errors}")
            return []

        # Prepare resolved subdomain data
        resolved_subdomains = [
            {
                "name": subdomain,
                "ip_addresses": dns_result.data.get("resolved_ips", []),
                "scan_history": ctx.get("scan_history"),
                "domain": ctx.get("domain"),
            }
            for subdomain in subdomains
        ]

        return resolved_subdomains

    def _save_discovered_subdomains(
        self, resolved_subdomains: List[Dict[str, Any]], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> Dict[str, Any]:
        """Save discovered subdomains using distributed database processor"""
        if not resolved_subdomains:
            return {"saved_count": 0}

        # Save using distributed subdomain processor
        save_result = self.subdomain_processor.save_subdomains_batch(resolved_subdomains, batch_id, **kwargs)

        return {
            "saved_count": len(save_result.data.get("saved_subdomains", [])),
            "skipped_count": len(save_result.data.get("skipped_subdomains", [])),
            "errors": save_result.errors,
        }


@app.task(name="subdomain_discovery_distributed", queue="io_queue", base=RengineTask, bind=True)
def subdomain_discovery_distributed(self, host=None, ctx=None, description=None, **kwargs):
    """
    Distributed subdomain discovery task using distributed utilities.

    This task replaces the legacy subdomain_discovery task with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting distributed subdomain discovery for host: {host}")

    try:
        # Create distributed configuration
        config = create_balanced_config()
        if ctx.get("large_scan", False):
            config.batch_size = 10
            config.worker_timeout = 600

        # Initialize subdomain discovery processor
        processor = SubdomainDiscoveryProcessor(config)

        # Process host
        hosts = [host] if host else []
        if not hosts:
            return {"success": False, "error": "No host provided for subdomain discovery"}

        # Process hosts in batches
        batch_size = config.batch_size
        results = []

        for i in range(0, len(hosts), batch_size):
            batch_hosts = hosts[i : i + batch_size]
            batch_id = f"subdomain_discovery_batch_{i // batch_size + 1}"

            batch_result = processor.process_subdomain_discovery_batch(batch_hosts, ctx, batch_id, **kwargs)
            results.append(batch_result)

        # Aggregate results
        total_processed = sum(r.get("processed_hosts", 0) for r in results)
        total_discovered = sum(r.get("discovered_subdomains", 0) for r in results)
        total_saved = sum(r.get("saved_subdomains", 0) for r in results)
        failed_batches = len([r for r in results if not r.get("success", False)])

        logger.info(
            f"Distributed subdomain discovery completed: {total_processed} hosts processed, {total_discovered} subdomains discovered, {total_saved} saved"
        )

        return {
            "success": True,
            "total_hosts": len(hosts),
            "processed_hosts": total_processed,
            "discovered_subdomains": total_discovered,
            "saved_subdomains": total_saved,
            "failed_batches": failed_batches,
            "results": results,
        }

    except Exception as e:
        logger.error(f"Distributed subdomain discovery failed: {e}")
        return {"success": False, "error": str(e), "host": host}


@app.task(name="subdomain_enumeration_distributed", queue="io_queue", base=RengineTask, bind=True)
def subdomain_enumeration_distributed(self, domain_id=None, ctx=None, description=None, **kwargs):
    """
    Distributed subdomain enumeration task using distributed utilities.

    This task handles subdomain enumeration for a specific domain using distributed processing.
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting distributed subdomain enumeration for domain {domain_id}")

    try:
        # Get domain information
        from targetApp.models import Domain

        domain = Domain.objects.get(id=domain_id)

        # Create distributed configuration
        config = create_balanced_config()

        # Initialize subdomain discovery processor
        processor = SubdomainDiscoveryProcessor(config)

        # Update context with domain information
        ctx.update({"domain": domain, "scan_history": ctx.get("scan_history")})

        # Process domain
        result = processor.process_subdomain_discovery_batch(
            [domain.name], ctx, f"subdomain_enum_{domain_id}", **kwargs
        )

        logger.info(f"Distributed subdomain enumeration completed for domain {domain_id}")

        return result

    except Exception as e:
        logger.error(f"Distributed subdomain enumeration failed for domain {domain_id}: {e}")
        return {"success": False, "error": str(e), "domain_id": domain_id}


# Legacy task wrapper for backward compatibility
@app.task(name="subdomain_discovery", queue="io_queue", base=RengineTask, bind=True)
def subdomain_discovery(self, host=None, ctx=None, description=None, **kwargs):
    """
    Legacy subdomain discovery task - now redirects to distributed system.

    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy subdomain_discovery task called - redirecting to distributed system")

    # Redirect to distributed task
    return subdomain_discovery_distributed.delay(host=host, ctx=ctx, description=description, **kwargs).get()


@app.task(name="subdomain_discovery_orchestrator", queue="orchestrator_queue", base=RengineTask, bind=True)
def subdomain_discovery_orchestrator(self, scan_id: int, **kwargs):
    """
    Orchestrate subdomain discovery for a scan.

    This task coordinates the subdomain discovery process across multiple workers
    and manages the overall workflow.

    Args:
        scan_id: ID of the scan to process
        **kwargs: Additional arguments

    Returns:
        Dict containing orchestration results
    """
    logger.info(f"Starting subdomain discovery orchestration for scan {scan_id}")

    try:
        # Use the distributed subdomain discovery system
        result = subdomain_discovery_distributed.delay(
            host=None,  # Will be determined from scan
            ctx={"scan_id": scan_id},
            description=f"Orchestrator - scan {scan_id}",
            **kwargs,
        )

        # Wait for completion with timeout
        orchestration_result = result.get(timeout=3600)  # 1 hour timeout
        logger.info(f"Subdomain discovery orchestration completed for scan {scan_id}")
        return orchestration_result

    except Exception as e:
        logger.error(f"Subdomain discovery orchestration failed for scan {scan_id}: {e}")
        return {"success": False, "error": str(e), "scan_id": scan_id, "discovered_subdomains": 0}


@app.task(name="subdomain_discovery_batch", queue="io_queue", base=RengineTask, bind=True)
def subdomain_discovery_batch(self, scan_id: int, **kwargs):
    """
    Process subdomain discovery in batches for a scan.

    This task handles subdomain discovery in smaller batches to improve
    performance and resource management.

    Args:
        scan_id: ID of the scan to process
        **kwargs: Additional arguments

    Returns:
        Dict containing batch processing results
    """
    logger.info(f"Starting subdomain discovery batch processing for scan {scan_id}")

    try:
        # Use the distributed subdomain discovery system
        result = subdomain_discovery_distributed.delay(
            host=None,  # Will be determined from scan
            ctx={"scan_id": scan_id},
            description=f"Batch - scan {scan_id}",
            **kwargs,
        )

        # Wait for completion with timeout
        batch_result = result.get(timeout=1800)  # 30 minute timeout
        logger.info(f"Subdomain discovery batch processing completed for scan {scan_id}")
        return batch_result

    except Exception as e:
        logger.error(f"Subdomain discovery batch processing failed for scan {scan_id}: {e}")
        return {"success": False, "error": str(e), "scan_id": scan_id, "discovered_subdomains": 0}
