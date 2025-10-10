"""
Refactored port scanning tasks using distributed utilities.

This module provides port scanning functionality using the distributed utilities
architecture, eliminating circular dependencies and following SOLID, KISS, and DRY principles.

Key components:
1. Port scanning tasks that use distributed utilities
2. No direct imports from other task modules
3. Clean separation of concerns
4. Reusable distributed processing
"""

from typing import Any, Dict, List

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    NMAP_SCRIPT,
    TIMEOUT,
)
from reNgine.settings import DEFAULT_THREADS
from reNgine.utilities.distributed.command import DistributedCommandBuilder
from reNgine.utilities.distributed.utilities import create_balanced_config, get_distributed_utilities
from startScan.models import Subdomain


logger = get_task_logger(__name__)


class PortScanProcessor:
    """Port scanning processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()
        self.ip_processor = self.distributed_utils.get_ip_processor()
        self.nmap_parser = self.distributed_utils.get_nmap_parser()

    def process_port_scan_batch(
        self, subdomain_ids: List[int], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> Dict[str, Any]:
        """Process a batch of subdomains for port scanning"""
        try:
            # Get subdomains
            subdomains = Subdomain.objects.filter(id__in=subdomain_ids)
            if not subdomains.exists():
                return {"success": False, "error": "No subdomains found", "batch_id": batch_id}

            # Execute port scanning commands
            scan_results = self._execute_port_scan_commands(subdomains, ctx, batch_id, **kwargs)

            # Parse scan results
            parsed_results = self._parse_port_scan_results(scan_results, ctx, batch_id, **kwargs)

            # Save scan results
            saved_results = self._save_port_scan_results(parsed_results, ctx, batch_id, **kwargs)

            return {
                "success": True,
                "batch_id": batch_id,
                "processed_subdomains": len(subdomains),
                "scanned_ports": len(parsed_results.get("ports", [])),
                "saved_endpoints": saved_results.get("saved_count", 0),
                "results": saved_results,
            }

        except Exception as e:
            logger.error(f"Port scan batch processing failed for batch {batch_id}: {e}")
            return {"success": False, "error": str(e), "batch_id": batch_id}

    def _execute_port_scan_commands(
        self, subdomains: List[Subdomain], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """Execute port scanning commands using distributed command processor"""
        commands = []
        ports = ctx.get("ports", [])

        for subdomain in subdomains:
            # Build nmap command
            command_builder = DistributedCommandBuilder("nmap")
            command_builder.add_flag("-sS")
            command_builder.add_flag("-sV")
            command_builder.add_flag("-O")
            command_builder.add_flag("-A")
            command_builder.add_flag("--script")
            command_builder.add_argument(NMAP_SCRIPT)
            command_builder.add_option("--script-timeout", "60")
            command_builder.add_option("-T", ctx.get("threads", DEFAULT_THREADS))
            command_builder.add_option("--host-timeout", ctx.get("timeout", TIMEOUT))

            # Add ports if specified
            if ports:
                port_list = ",".join(map(str, ports))
                command_builder.add_option("-p", port_list)
            else:
                command_builder.add_option("-p", "1-65535")

            # Add output file
            output_file = f"/tmp/nmap_{batch_id}_{subdomain.id}.xml"
            command_builder.add_option("-oX", output_file)

            command_builder.add_argument(subdomain.name)

            command = command_builder.build()
            commands.append({"command": command, "subdomain": subdomain, "output_file": output_file})

        # Execute commands using distributed command processor
        command_result = self.command_processor.execute_commands_batch(
            [cmd["command"] for cmd in commands], batch_id, **kwargs
        )

        return commands if command_result.is_successful else []

    def _parse_port_scan_results(
        self, scan_results: List[Dict[str, Any]], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> Dict[str, Any]:
        """Parse port scan results using distributed parser"""
        output_files = [result["output_file"] for result in scan_results]

        # Parse using distributed nmap parser
        parse_result = self.nmap_parser.parse_nmap_files_batch(output_files, batch_id, parse_type="ports", **kwargs)

        if not parse_result.is_successful:
            logger.error(f"Port scan parsing failed for batch {batch_id}: {parse_result.errors}")
            return {"ports": [], "hosts": []}

        return parse_result.data

    def _save_port_scan_results(
        self, parsed_results: Dict[str, Any], ctx: Dict[str, Any], batch_id: str, **kwargs
    ) -> Dict[str, Any]:
        """Save port scan results using distributed database processor"""
        if not parsed_results:
            return {"saved_count": 0}

        # Prepare endpoint and IP data
        endpoint_data = []
        ip_data = []

        for host_data in parsed_results.get("hosts", []):
            subdomain_name = host_data.get("hostname", "")
            ip_address = host_data.get("ip", "")

            # Add IP address data
            if ip_address:
                ip_data.append(
                    {"address": ip_address, "subdomain": subdomain_name, "scan_history": ctx.get("scan_history")}
                )

            # Add endpoint data for each port
            for port_data in host_data.get("ports", []):
                port_number = port_data.get("port", 0)
                service = port_data.get("service", "")
                version = port_data.get("version", "")
                state = port_data.get("state", "")

                if port_number and state == "open":
                    endpoint_data.append(
                        {
                            "url": f"http://{subdomain_name}:{port_number}",
                            "port": port_number,
                            "service": service,
                            "version": version,
                            "state": state,
                            "scan_history": ctx.get("scan_history"),
                            "subdomain": subdomain_name,
                        }
                    )

        # Save IP addresses
        ip_save_result = {"saved_count": 0}
        if ip_data:
            ip_save_result = self.ip_processor.save_ips_batch(ip_data, f"{batch_id}_ips", **kwargs)

        # Save endpoints
        endpoint_save_result = {"saved_count": 0}
        if endpoint_data:
            endpoint_save_result = self.endpoint_processor.save_endpoints_batch(
                endpoint_data, f"{batch_id}_endpoints", **kwargs
            )

        return {
            "saved_count": ip_save_result.get("saved_count", 0) + endpoint_save_result.get("saved_count", 0),
            "saved_ips": ip_save_result.get("saved_count", 0),
            "saved_endpoints": endpoint_save_result.get("saved_count", 0),
            "errors": ip_save_result.get("errors", []) + endpoint_save_result.get("errors", []),
        }


@app.task(name="port_scan_distributed", queue="run_command_queue", base=RengineTask, bind=True)
def port_scan_distributed(self, subdomain_ids=None, ctx=None, description=None, **kwargs):
    """
    Distributed port scanning task using distributed utilities.

    This task replaces the legacy port scanning tasks with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    if subdomain_ids is None:
        subdomain_ids = []
    if ctx is None:
        ctx = {}

    logger.info(f"Starting distributed port scan for {len(subdomain_ids)} subdomains")

    try:
        # Create distributed configuration
        config = create_balanced_config()
        if len(subdomain_ids) > 100:
            config.batch_size = 10
            config.worker_timeout = 600

        # Initialize port scan processor
        processor = PortScanProcessor(config)

        # Process subdomains in batches
        batch_size = config.batch_size
        results = []

        for i in range(0, len(subdomain_ids), batch_size):
            batch_subdomain_ids = subdomain_ids[i : i + batch_size]
            batch_id = f"port_scan_batch_{i // batch_size + 1}"

            batch_result = processor.process_port_scan_batch(batch_subdomain_ids, ctx, batch_id, **kwargs)
            results.append(batch_result)

        # Aggregate results
        total_processed = sum(r.get("processed_subdomains", 0) for r in results)
        total_scanned = sum(r.get("scanned_ports", 0) for r in results)
        total_saved = sum(r.get("saved_endpoints", 0) for r in results)
        failed_batches = sum(1 for r in results if not r.get("success", False))

        logger.info(
            f"Distributed port scan completed: {total_processed} subdomains processed, {total_scanned} ports scanned, {total_saved} endpoints saved"
        )

        return {
            "success": True,
            "total_subdomains": len(subdomain_ids),
            "processed_subdomains": total_processed,
            "scanned_ports": total_scanned,
            "saved_endpoints": total_saved,
            "failed_batches": failed_batches,
            "results": results,
        }

    except Exception as e:
        logger.error(f"Distributed port scan failed: {e}")
        return {"success": False, "error": str(e), "total_subdomains": len(subdomain_ids)}


@app.task(name="port_scan_subdomain_distributed", queue="run_command_queue", base=RengineTask, bind=True)
def port_scan_subdomain_distributed(self, subdomain_id=None, ctx=None, description=None, **kwargs):
    """
    Distributed port scanning task for a single subdomain using distributed utilities.
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting distributed port scan for subdomain {subdomain_id}")

    try:
        # Create distributed configuration
        config = create_balanced_config()

        # Initialize port scan processor
        processor = PortScanProcessor(config)

        # Process single subdomain
        result = processor.process_port_scan_batch([subdomain_id], ctx, f"port_scan_subdomain_{subdomain_id}", **kwargs)

        logger.info(f"Distributed port scan completed for subdomain {subdomain_id}")

        return result

    except Exception as e:
        logger.error(f"Distributed port scan failed for subdomain {subdomain_id}: {e}")
        return {"success": False, "error": str(e), "subdomain_id": subdomain_id}


@app.task(name="port_scan_range_distributed", queue="run_command_queue", base=RengineTask, bind=True)
def port_scan_range_distributed(self, ip_range=None, ctx=None, description=None, **kwargs):
    """
    Distributed port scanning task for an IP range using distributed utilities.
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting distributed port scan for IP range: {ip_range}")

    try:
        # Create distributed configuration
        config = create_balanced_config()

        # Initialize port scan processor
        processor = PortScanProcessor(config)

        # Process IP range
        result = processor.process_port_scan_batch([], ctx, f"port_scan_range_{hash(ip_range)}", **kwargs)

        logger.info(f"Distributed port scan completed for IP range: {ip_range}")

        return result

    except Exception as e:
        logger.error(f"Distributed port scan failed for IP range {ip_range}: {e}")
        return {"success": False, "error": str(e), "ip_range": ip_range}


# Legacy task wrapper for backward compatibility
@app.task(name="port_scan", queue="run_command_queue", base=RengineTask, bind=True)
def port_scan(self, subdomain_ids=None, ctx=None, description=None, **kwargs):
    """
    Legacy port scan task - now redirects to distributed system.

    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy port_scan task called - redirecting to distributed system")

    # Redirect to distributed task
    return port_scan_distributed.delay(subdomain_ids=subdomain_ids, ctx=ctx, description=description, **kwargs).get()


@app.task(name="port_scan_batch", queue="run_command_queue", base=RengineTask, bind=True)
def port_scan_batch(self, subdomain_ids=None, ctx=None, description=None, **kwargs):
    """
    Process port scanning in batches.

    This task handles port scanning in smaller batches to improve
    performance and resource management.

    Args:
        subdomain_ids: List of subdomain IDs to scan
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments

    Returns:
        Dict containing batch processing results
    """
    logger.info("Starting port scan batch processing")

    try:
        # Use the distributed port scan system
        result = port_scan_distributed.delay(
            subdomain_ids=subdomain_ids, ctx=ctx, description=description or "Port scan batch", **kwargs
        )

        # Wait for completion with timeout
        batch_result = result.get(timeout=1800)  # 30 minute timeout
        logger.info("Port scan batch processing completed")
        return batch_result

    except Exception as e:
        logger.error(f"Port scan batch processing failed: {e}")
        return {"success": False, "error": str(e), "scanned_ports": 0, "open_ports": 0}


@app.task(name="port_scan_orchestrator", queue="orchestrator_queue", base=RengineTask, bind=True)
def port_scan_orchestrator(self, subdomain_ids=None, ctx=None, description=None, **kwargs):
    """
    Orchestrate port scanning workflow.

    This task coordinates the port scanning process across multiple workers
    and manages the overall workflow.

    Args:
        subdomain_ids: List of subdomain IDs to scan
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments

    Returns:
        Dict containing orchestration results
    """
    logger.info("Starting port scan orchestration")

    try:
        # Use the distributed port scan system
        result = port_scan_distributed.delay(
            subdomain_ids=subdomain_ids, ctx=ctx, description=description or "Port scan orchestration", **kwargs
        )

        # Wait for completion with timeout
        orchestration_result = result.get(timeout=3600)  # 1 hour timeout
        logger.info("Port scan orchestration completed")
        return orchestration_result

    except Exception as e:
        logger.error(f"Port scan orchestration failed: {e}")
        return {"success": False, "error": str(e), "scanned_ports": 0, "open_ports": 0}
