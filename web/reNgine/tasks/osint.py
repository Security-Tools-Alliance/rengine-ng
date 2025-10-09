"""
Refactored OSINT tasks using distributed utilities.

This module provides OSINT functionality using the distributed utilities
architecture, eliminating circular dependencies and following SOLID, KISS, and DRY principles.

Key components:
1. OSINT tasks that use distributed utilities
2. No direct imports from other task modules
3. Clean separation of concerns
4. Reusable distributed processing
"""

import json
import os
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger
import validators

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    OSINT_DEFAULT_LOOKUPS,
    OSINT_DEFAULT_CONFIG,
    THREADS,
    TIMEOUT,
)
from reNgine.settings import DEFAULT_THREADS
from reNgine.utilities.distributed.utilities import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config
)
from reNgine.utilities.distributed.command import (
    DistributedCommandExecutor,
    DistributedCommandBuilder
)
from reNgine.utilities.distributed.database import (
    DistributedSubdomainProcessor
)
from reNgine.utilities.distributed.network import (
    DistributedDNSProcessor
)
from targetApp.models import Domain

logger = get_task_logger(__name__)


class OSINTProcessor:
    """OSINT processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()
        self.dns_processor = self.distributed_utils.get_dns_processor()
    
    def process_osint_scan_batch(
        self,
        domain_id: int,
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Process OSINT scan for a domain"""
        try:
            # Get domain
            domain = Domain.objects.get(id=domain_id)
            
            # Execute OSINT commands
            scan_results = self._execute_osint_commands(
                domain, ctx, batch_id, **kwargs
            )
            
            # Parse OSINT results
            parsed_results = self._parse_osint_results(
                scan_results, ctx, batch_id, **kwargs
            )
            
            # Save OSINT results
            saved_results = self._save_osint_results(
                parsed_results, ctx, batch_id, **kwargs
            )
            
            return {
                "success": True,
                "batch_id": batch_id,
                "domain_id": domain_id,
                "found_subdomains": len(parsed_results.get("subdomains", [])),
                "found_emails": len(parsed_results.get("emails", [])),
                "found_employees": len(parsed_results.get("employees", [])),
                "saved_results": saved_results.get("saved_count", 0),
                "results": saved_results
            }
            
        except Exception as e:
            logger.error(f"OSINT scan batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "batch_id": batch_id
            }
    
    def _execute_osint_commands(
        self,
        domain: Domain,
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Execute OSINT commands using distributed command processor"""
        commands = []
        tools = ctx.get("osint_tools", OSINT_DEFAULT_LOOKUPS)
        
        for tool in tools:
            if tool == "theharvester":
                command = self._build_theharvester_command(domain, ctx)
            elif tool == "metagoofil":
                command = self._build_metagoofil_command(domain, ctx)
            elif tool == "sublist3r":
                command = self._build_sublist3r_command(domain, ctx)
            elif tool == "dnsrecon":
                command = self._build_dnsrecon_command(domain, ctx)
            else:
                continue
            
            if command:
                commands.append({
                    "command": command,
                    "domain": domain,
                    "tool": tool,
                    "output_file": f"/tmp/{tool}_{batch_id}_{domain.id}.txt"
                })
        
        # Execute commands using distributed command processor
        command_result = self.command_processor.execute_commands_batch(
            [cmd["command"] for cmd in commands],
            batch_id,
            **kwargs
        )
        
        return commands if command_result.is_successful else []
    
    def _build_theharvester_command(self, domain: Domain, ctx: Dict[str, Any]) -> str:
        """Build theharvester command"""
        command_builder = DistributedCommandBuilder("theHarvester")
        command_builder.add_option("-d", domain.name)
        command_builder.add_option("-b", "all")
        command_builder.add_option("-l", ctx.get("limit", 500))
        command_builder.add_flag("-f")
        
        return command_builder.build()
    
    def _build_metagoofil_command(self, domain: Domain, ctx: Dict[str, Any]) -> str:
        """Build metagoofil command"""
        command_builder = DistributedCommandBuilder("metagoofil")
        command_builder.add_option("-d", domain.name)
        command_builder.add_option("-t", ctx.get("file_types", "pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx"))
        command_builder.add_option("-l", ctx.get("limit", 200))
        command_builder.add_flag("-o")
        
        return command_builder.build()
    
    def _build_sublist3r_command(self, domain: Domain, ctx: Dict[str, Any]) -> str:
        """Build sublist3r command"""
        command_builder = DistributedCommandBuilder("sublist3r")
        command_builder.add_option("-d", domain.name)
        command_builder.add_option("-t", ctx.get("threads", DEFAULT_THREADS))
        command_builder.add_flag("-o")
        
        return command_builder.build()
    
    def _build_dnsrecon_command(self, domain: Domain, ctx: Dict[str, Any]) -> str:
        """Build dnsrecon command"""
        command_builder = DistributedCommandBuilder("dnsrecon")
        command_builder.add_option("-d", domain.name)
        command_builder.add_flag("-t")
        command_builder.add_argument("std")
        
        return command_builder.build()
    
    def _parse_osint_results(
        self,
        scan_results: List[Dict[str, Any]],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Parse OSINT results"""
        parsed_results = {
            "subdomains": [],
            "emails": [],
            "employees": [],
            "documents": []
        }
        
        for result in scan_results:
            output_file = result.get("output_file")
            tool = result.get("tool")
            
            if not output_file or not os.path.exists(output_file):
                continue
            
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    
                    if tool == "theharvester":
                        self._parse_theharvester_output(content, parsed_results)
                    elif tool == "metagoofil":
                        self._parse_metagoofil_output(content, parsed_results)
                    elif tool == "sublist3r":
                        self._parse_sublist3r_output(content, parsed_results)
                    elif tool == "dnsrecon":
                        self._parse_dnsrecon_output(content, parsed_results)
                        
            except Exception as e:
                logger.error(f"Error parsing OSINT results from {output_file}: {e}")
                continue
        
        return parsed_results
    
    def _parse_theharvester_output(self, content: str, parsed_results: Dict[str, Any]) -> None:
        """Parse theharvester output"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if '@' in line and '.' in line:
                # Extract email addresses
                import re
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)
                parsed_results["emails"].extend(emails)
            elif '.' in line and not line.startswith('['):
                # Extract subdomains
                if validators.domain(line):
                    parsed_results["subdomains"].append(line)
    
    def _parse_metagoofil_output(self, content: str, parsed_results: Dict[str, Any]) -> None:
        """Parse metagoofil output"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('['):
                # Extract document information
                parsed_results["documents"].append(line)
    
    def _parse_sublist3r_output(self, content: str, parsed_results: Dict[str, Any]) -> None:
        """Parse sublist3r output"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and validators.domain(line):
                parsed_results["subdomains"].append(line)
    
    def _parse_dnsrecon_output(self, content: str, parsed_results: Dict[str, Any]) -> None:
        """Parse dnsrecon output"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and '.' in line:
                # Extract DNS records
                if validators.domain(line.split()[0] if ' ' in line else line):
                    parsed_results["subdomains"].append(line)
    
    def _save_osint_results(
        self,
        parsed_results: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Save OSINT results using distributed database processor"""
        if not parsed_results:
            return {"saved_count": 0}
        
        # Prepare subdomain data
        subdomain_data = []
        for subdomain_name in parsed_results.get("subdomains", []):
            subdomain_data.append({
                "name": subdomain_name,
                "scan_history": ctx.get("scan_history"),
                "domain": ctx.get("domain")
            })
        
        # Save subdomains
        subdomain_save_result = {"saved_count": 0}
        if subdomain_data:
            subdomain_save_result = self.subdomain_processor.save_subdomains_batch(
                subdomain_data, f"{batch_id}_subdomains", **kwargs
            )
        
        # Save other OSINT data (emails, employees, documents)
        # This would typically involve saving to specific OSINT models
        other_save_result = {"saved_count": 0}
        
        return {
            "saved_count": subdomain_save_result.get("saved_count", 0) + other_save_result.get("saved_count", 0),
            "saved_subdomains": subdomain_save_result.get("saved_count", 0),
            "saved_other": other_save_result.get("saved_count", 0),
            "errors": subdomain_save_result.get("errors", []) + other_save_result.get("errors", [])
        }


@app.task(name="osint_scan_distributed", queue="io_queue", base=RengineTask, bind=True)
def osint_scan_distributed(
    self,
    domain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Distributed OSINT scanning task using distributed utilities.
    
    This task replaces the legacy OSINT tasks with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    if ctx is None:
        ctx = {}
    
    logger.info(f"Starting distributed OSINT scan for domain {domain_id}")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        
        # Initialize OSINT processor
        processor = OSINTProcessor(config)
        
        # Process OSINT scan
        result = processor.process_osint_scan_batch(
            domain_id, ctx, f"osint_scan_{domain_id}", **kwargs
        )
        
        logger.info(f"Distributed OSINT scan completed for domain {domain_id}")
        
        return result
        
    except Exception as e:
        logger.error(f"Distributed OSINT scan failed for domain {domain_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "domain_id": domain_id
        }


@app.task(name="osint_scan_tool_distributed", queue="io_queue", base=RengineTask, bind=True)
def osint_scan_tool_distributed(
    self,
    tool_name=None,
    domain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Distributed OSINT scanning task for a specific tool using distributed utilities.
    """
    if ctx is None:
        ctx = {}
    
    logger.info(f"Starting distributed OSINT scan for tool {tool_name} on domain {domain_id}")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        
        # Initialize OSINT processor
        processor = OSINTProcessor(config)
        
        # Update context with specific tool
        ctx.update({"osint_tools": [tool_name]})
        
        # Process OSINT scan
        result = processor.process_osint_scan_batch(
            domain_id, ctx, f"osint_scan_{tool_name}_{domain_id}", **kwargs
        )
        
        logger.info(f"Distributed OSINT scan completed for tool {tool_name} on domain {domain_id}")
        
        return result
        
    except Exception as e:
        logger.error(f"Distributed OSINT scan failed for tool {tool_name} on domain {domain_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "tool_name": tool_name,
            "domain_id": domain_id
        }


# Legacy task wrapper for backward compatibility
@app.task(name="osint_scan", queue="io_queue", base=RengineTask, bind=True)
def osint_scan(
    self,
    domain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Legacy OSINT scan task - now redirects to distributed system.
    
    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy osint_scan task called - redirecting to distributed system")
    
    # Redirect to distributed task
    return osint_scan_distributed.delay(
        domain_id=domain_id,
        ctx=ctx,
        description=description,
        **kwargs
    ).get()


@app.task(name="osint_scan_batch", queue="io_queue", base=RengineTask, bind=True)
def osint_scan_batch(
    self,
    domain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Process OSINT scanning in batches.
    
    This task handles OSINT scanning in smaller batches to improve
    performance and resource management.
    
    Args:
        domain_id: ID of the domain to scan
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments
    
    Returns:
        Dict containing batch processing results
    """
    logger.info("Starting OSINT scan batch processing")
    
    try:
        # Use the distributed OSINT scan system
        result = osint_scan_distributed.delay(
            domain_id=domain_id,
            ctx=ctx,
            description=description or "OSINT scan batch",
            **kwargs
        )
        
        # Wait for completion with timeout
        batch_result = result.get(timeout=1800)  # 30 minute timeout
        logger.info("OSINT scan batch processing completed")
        return batch_result
        
    except Exception as e:
        logger.error(f"OSINT scan batch processing failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "scanned_domains": 0,
            "osint_results": 0
        }


@app.task(name="osint_scan_orchestrator", queue="orchestrator_queue", base=RengineTask, bind=True)
def osint_scan_orchestrator(
    self,
    domain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Orchestrate OSINT scanning workflow.
    
    This task coordinates the OSINT scanning process across multiple workers
    and manages the overall workflow.
    
    Args:
        domain_id: ID of the domain to scan
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments
    
    Returns:
        Dict containing orchestration results
    """
    logger.info("Starting OSINT scan orchestration")
    
    try:
        # Use the distributed OSINT scan system
        result = osint_scan_distributed.delay(
            domain_id=domain_id,
            ctx=ctx,
            description=description or "OSINT scan orchestration",
            **kwargs
        )
        
        # Wait for completion with timeout
        orchestration_result = result.get(timeout=3600)  # 1 hour timeout
        logger.info("OSINT scan orchestration completed")
        return orchestration_result
        
    except Exception as e:
        logger.error(f"OSINT scan orchestration failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "scanned_domains": 0,
            "osint_results": 0
        }
