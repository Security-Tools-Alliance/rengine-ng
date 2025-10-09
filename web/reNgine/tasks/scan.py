"""
Refactored scan orchestration tasks using distributed utilities.

This module provides scan orchestration functionality using the distributed utilities
architecture, eliminating circular dependencies and following SOLID, KISS, and DRY principles.

Key components:
1. Scan orchestration tasks that use distributed utilities
2. No direct imports from other task modules
3. Clean separation of concerns
4. Reusable distributed processing
"""

import json
import os
import uuid
from typing import Any, Dict, List, Optional

from celery import chain
from celery.utils.log import get_task_logger
from django.utils import timezone
import yaml

from reNgine.celery import app
from reNgine.definitions import (
    CELERY_TASK_STATUS_MAP,
    FAILED_TASK,
    GF_PATTERNS,
    LIVE_SCAN,
    RUNNING_TASK,
    SCHEDULED_SCAN,
)
from reNgine.settings import RENGINE_RESULTS
from reNgine.utilities.distributed.utilities import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config
)
from reNgine.utilities.distributed.database import (
    DistributedSubdomainProcessor
)
from startScan.models import ScanHistory, SubScan
from targetApp.models import Domain

logger = get_task_logger(__name__)


class ScanOrchestrationProcessor:
    """Scan orchestration processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()
    
    def process_scan_orchestration(
        self,
        scan_history_id: int,
        domain_id: int,
        ctx: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Process scan orchestration using distributed utilities"""
        try:
            # Get scan history and domain
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(id=domain_id)
            
            # Update scan status
            scan_history.status = RUNNING_TASK
            scan_history.save()
            
            # Initialize scan orchestration
            orchestration_result = self._initialize_scan_orchestration(
                scan_history, domain, ctx, **kwargs
            )
            
            if not orchestration_result.get("success", False):
                scan_history.status = FAILED_TASK
                scan_history.save()
                return orchestration_result
            
            # Execute distributed scan phases
            scan_results = self._execute_distributed_scan_phases(
                scan_history, domain, ctx, **kwargs
            )
            
            # Finalize scan
            return self._finalize_scan_orchestration(
                scan_history, domain, scan_results, **kwargs
            )
            
        except Exception as e:
            logger.error(f"Scan orchestration failed for scan {scan_history_id}: {e}")
            try:
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                scan_history.status = FAILED_TASK
                scan_history.save()
            except:
                pass
            
            return {
                "success": False,
                "error": str(e),
                "scan_history_id": scan_history_id
            }
    
    def _initialize_scan_orchestration(
        self,
        scan_history: ScanHistory,
        domain: Domain,
        ctx: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Initialize scan orchestration"""
        try:
            # Create scan directory
            scan_dir = f"{RENGINE_RESULTS}/{scan_history.id}"
            os.makedirs(scan_dir, exist_ok=True)
            
            # Initialize scan context
            scan_context = {
                "scan_history": scan_history,
                "domain": domain,
                "scan_dir": scan_dir,
                "engine_id": ctx.get("engine_id"),
                "scan_type": ctx.get("scan_type", LIVE_SCAN),
                "imported_subdomains": ctx.get("imported_subdomains", []),
                "out_of_scope_subdomains": ctx.get("out_of_scope_subdomains", []),
                "url_filter": ctx.get("url_filter", ""),
                "initiated_by_id": ctx.get("initiated_by_id")
            }
            
            # Save imported subdomains if any
            if scan_context["imported_subdomains"]:
                save_result = self.subdomain_processor.save_subdomains_batch(
                    scan_context["imported_subdomains"],
                    f"imported_subdomains_{scan_history.id}",
                    **kwargs
                )
                
                if not save_result.is_successful:
                    logger.warning(f"Failed to save imported subdomains: {save_result.errors}")
            
            return {
                "success": True,
                "scan_context": scan_context
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize scan orchestration: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _execute_distributed_scan_phases(
        self,
        scan_history: ScanHistory,
        domain: Domain,
        ctx: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Execute distributed scan phases"""
        try:
            scan_results = {
                "subdomain_discovery": None,
                "port_scanning": None,
                "http_crawling": None,
                "vulnerability_scanning": None,
                "osint": None
            }
            
            # Phase 1: Subdomain Discovery
            if ctx.get("enable_subdomain_discovery", True):
                logger.info(f"Starting subdomain discovery for scan {scan_history.id}")
                
                # Import here to avoid circular dependencies
                from reNgine.tasks.subdomain import subdomain_discovery_distributed
                
                subdomain_result = subdomain_discovery_distributed.delay(
                    host=domain.name,
                    ctx={
                        "scan_history": scan_history,
                        "domain": domain,
                        "tools": ctx.get("subdomain_tools", []),
                        "threads": ctx.get("threads", 10),
                        "timeout": ctx.get("timeout", 300)
                    }
                ).get()
                
                scan_results["subdomain_discovery"] = subdomain_result
            
            # Phase 2: Port Scanning
            if ctx.get("enable_port_scanning", True):
                logger.info(f"Starting port scanning for scan {scan_history.id}")
                
                # Import here to avoid circular dependencies
                from reNgine.tasks.port_scan import port_scan_distributed
                
                port_result = port_scan_distributed.delay(
                    subdomain_ids=ctx.get("subdomain_ids", []),
                    ctx={
                        "scan_history": scan_history,
                        "domain": domain,
                        "ports": ctx.get("ports", []),
                        "threads": ctx.get("threads", 10)
                    }
                ).get()
                
                scan_results["port_scanning"] = port_result
            
            # Phase 3: HTTP Crawling
            if ctx.get("enable_http_crawling", True):
                logger.info(f"Starting HTTP crawling for scan {scan_history.id}")
                
                # Import here to avoid circular dependencies
                from reNgine.tasks.http import http_crawl_distributed
                
                http_result = http_crawl_distributed.delay(
                    urls=ctx.get("urls", []),
                    ctx={
                        "scan_history": scan_history,
                        "domain": domain,
                        "threads": ctx.get("threads", 10),
                        "timeout": ctx.get("timeout", 10)
                    }
                ).get()
                
                scan_results["http_crawling"] = http_result
            
            # Phase 4: Vulnerability Scanning
            if ctx.get("enable_vulnerability_scanning", True):
                logger.info(f"Starting vulnerability scanning for scan {scan_history.id}")
                
                # Import here to avoid circular dependencies
                from reNgine.tasks.vulnerability import vulnerability_scan_distributed
                
                vuln_result = vulnerability_scan_distributed.delay(
                    endpoint_ids=ctx.get("endpoint_ids", []),
                    ctx={
                        "scan_history": scan_history,
                        "domain": domain,
                        "nuclei_templates": ctx.get("nuclei_templates", []),
                        "threads": ctx.get("threads", 10)
                    }
                ).get()
                
                scan_results["vulnerability_scanning"] = vuln_result
            
            # Phase 5: OSINT
            if ctx.get("enable_osint", True):
                logger.info(f"Starting OSINT for scan {scan_history.id}")
                
                # Import here to avoid circular dependencies
                from reNgine.tasks.osint import osint_scan_distributed
                
                osint_result = osint_scan_distributed.delay(
                    domain_id=domain.id,
                    ctx={
                        "scan_history": scan_history,
                        "domain": domain,
                        "osint_tools": ctx.get("osint_tools", []),
                        "threads": ctx.get("threads", 10)
                    }
                ).get()
                
                scan_results["osint"] = osint_result
            
            return {
                "success": True,
                "scan_results": scan_results
            }
            
        except Exception as e:
            logger.error(f"Failed to execute distributed scan phases: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _finalize_scan_orchestration(
        self,
        scan_history: ScanHistory,
        domain: Domain,
        scan_results: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Finalize scan orchestration"""
        try:
            # Update scan history with results
            scan_history.status = CELERY_TASK_STATUS_MAP.get("SUCCESS", "SUCCESS")
            scan_history.scan_status = "COMPLETED"
            scan_history.completed_at = timezone.now()
            scan_history.save()
            
            # Send notification
            try:
                from reNgine.tasks.notification import send_scan_notification_distributed
                send_scan_notification_distributed.delay(
                    scan_history_id=scan_history.id,
                    status="completed"
                )
            except Exception as e:
                logger.warning(f"Failed to send scan notification: {e}")
            
            # Generate report
            try:
                from reNgine.tasks.reporting import generate_scan_report_distributed
                generate_scan_report_distributed.delay(
                    scan_history_id=scan_history.id
                )
            except Exception as e:
                logger.warning(f"Failed to generate scan report: {e}")
            
            return {
                "success": True,
                "scan_history_id": scan_history.id,
                "scan_results": scan_results,
                "message": "Scan orchestration completed successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to finalize scan orchestration: {e}")
            return {
                "success": False,
                "error": str(e)
            }


@app.task(name="initiate_scan_distributed", bind=False, queue="orchestrator_queue")
def initiate_scan_distributed(
    scan_history_id,
    domain_id,
    engine_id=None,
    scan_type=LIVE_SCAN,
    results_dir=RENGINE_RESULTS,
    imported_subdomains=[],
    out_of_scope_subdomains=[],
    initiated_by_id=None,
    url_filter="",
    **kwargs
):
    """
    Distributed scan initiation task using distributed utilities.
    
    This task replaces the legacy initiate_scan task with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    logger.info(f"Starting distributed scan initiation for scan {scan_history_id}")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        
        # Initialize scan orchestration processor
        processor = ScanOrchestrationProcessor(config)
        
        # Prepare scan context
        scan_context = {
            "engine_id": engine_id,
            "scan_type": scan_type,
            "results_dir": results_dir,
            "imported_subdomains": imported_subdomains,
            "out_of_scope_subdomains": out_of_scope_subdomains,
            "initiated_by_id": initiated_by_id,
            "url_filter": url_filter,
            "enable_subdomain_discovery": kwargs.get("enable_subdomain_discovery", True),
            "enable_port_scanning": kwargs.get("enable_port_scanning", True),
            "enable_http_crawling": kwargs.get("enable_http_crawling", True),
            "enable_vulnerability_scanning": kwargs.get("enable_vulnerability_scanning", True),
            "enable_osint": kwargs.get("enable_osint", True),
            "subdomain_tools": kwargs.get("subdomain_tools", []),
            "ports": kwargs.get("ports", []),
            "urls": kwargs.get("urls", []),
            "endpoint_ids": kwargs.get("endpoint_ids", []),
            "nuclei_templates": kwargs.get("nuclei_templates", []),
            "osint_tools": kwargs.get("osint_tools", []),
            "threads": kwargs.get("threads", 10),
            "timeout": kwargs.get("timeout", 300)
        }
        
        # Process scan orchestration
        result = processor.process_scan_orchestration(
            scan_history_id, domain_id, scan_context, **kwargs
        )
        
        logger.info(f"Distributed scan initiation completed for scan {scan_history_id}")
        
        return result
        
    except Exception as e:
        logger.error(f"Distributed scan initiation failed for scan {scan_history_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "scan_history_id": scan_history_id
        }


@app.task(name="schedule_scan_distributed", bind=False, queue="orchestrator_queue")
def schedule_scan_distributed(
    domain_id,
    engine_id=None,
    scan_type=SCHEDULED_SCAN,
    scheduled_time=None,
    **kwargs
):
    """
    Distributed scan scheduling task using distributed utilities.
    
    This task handles scan scheduling using distributed processing.
    """
    logger.info(f"Starting distributed scan scheduling for domain {domain_id}")
    
    try:
        # Create scan history
        from reNgine.utilities.distributed.database import create_scan_object
        
        scan_history = create_scan_object(
            domain_id=domain_id,
            engine_id=engine_id,
            scan_type=scan_type,
            scheduled_time=scheduled_time,
            **kwargs
        )
        
        if not scan_history:
            return {
                "success": False,
                "error": "Failed to create scan history"
            }
        
        # Schedule the scan
        if scheduled_time:
            # Schedule for later execution
            initiate_scan_distributed.apply_async(
                args=[scan_history.id, domain_id],
                kwargs={
                    "engine_id": engine_id,
                    "scan_type": scan_type,
                    **kwargs
                },
                eta=scheduled_time
            )
        else:
            # Execute immediately
            initiate_scan_distributed.delay(
                scan_history.id,
                domain_id,
                engine_id=engine_id,
                scan_type=scan_type,
                **kwargs
            )
        
        return {
            "success": True,
            "scan_history_id": scan_history.id,
            "scheduled_time": scheduled_time,
            "message": "Scan scheduled successfully"
        }
        
    except Exception as e:
        logger.error(f"Distributed scan scheduling failed for domain {domain_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "domain_id": domain_id
        }


# Legacy task wrapper for backward compatibility
@app.task(name="initiate_scan", bind=False, queue="orchestrator_queue")
def initiate_scan(
    scan_history_id,
    domain_id,
    engine_id=None,
    scan_type=LIVE_SCAN,
    results_dir=RENGINE_RESULTS,
    imported_subdomains=[],
    out_of_scope_subdomains=[],
    initiated_by_id=None,
    url_filter="",
    **kwargs
):
    """
    Legacy scan initiation task - now redirects to distributed system.
    
    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy initiate_scan task called - redirecting to distributed system")
    
    # Redirect to distributed task
    return initiate_scan_distributed.delay(
        scan_history_id,
        domain_id,
        engine_id=engine_id,
        scan_type=scan_type,
        results_dir=results_dir,
        imported_subdomains=imported_subdomains,
        out_of_scope_subdomains=out_of_scope_subdomains,
        initiated_by_id=initiated_by_id,
        url_filter=url_filter,
        **kwargs
    ).get()


@app.task(name="scan_orchestrator", bind=False, queue="orchestrator_queue")
def scan_orchestrator(
    scan_history_id,
    domain_id,
    engine_id=None,
    scan_type=LIVE_SCAN,
    **kwargs
):
    """
    Orchestrate a complete scan workflow.
    
    This task coordinates the entire scan process including subdomain discovery,
    port scanning, vulnerability scanning, and reporting.
    
    Args:
        scan_history_id: ID of the scan history record
        domain_id: ID of the domain to scan
        engine_id: ID of the scan engine to use
        scan_type: Type of scan to perform
        **kwargs: Additional arguments
    
    Returns:
        Dict containing orchestration results
    """
    logger.info(f"Starting scan orchestration for scan {scan_history_id}")
    
    try:
        # Use the distributed scan initiation system
        result = initiate_scan_distributed.delay(
            scan_history_id,
            domain_id,
            engine_id=engine_id,
            scan_type=scan_type,
            **kwargs
        )
        
        # Wait for completion with timeout
        orchestration_result = result.get(timeout=7200)  # 2 hour timeout
        logger.info(f"Scan orchestration completed for scan {scan_history_id}")
        return orchestration_result
        
    except Exception as e:
        logger.error(f"Scan orchestration failed for scan {scan_history_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "scan_history_id": scan_history_id,
            "domain_id": domain_id
        }


@app.task(name="scan_coordinator", bind=False, queue="orchestrator_queue")
def scan_coordinator(
    scan_history_id,
    domain_id,
    **kwargs
):
    """
    Coordinate scan execution and manage dependencies.
    
    This task manages the coordination between different scan phases and ensures
    proper sequencing of tasks.
    
    Args:
        scan_history_id: ID of the scan history record
        domain_id: ID of the domain to scan
        **kwargs: Additional arguments
    
    Returns:
        Dict containing coordination results
    """
    logger.info(f"Starting scan coordination for scan {scan_history_id}")
    
    try:
        # Use the distributed scan initiation system
        result = initiate_scan_distributed.delay(
            scan_history_id,
            domain_id,
            **kwargs
        )
        
        # Wait for completion with timeout
        coordination_result = result.get(timeout=3600)  # 1 hour timeout
        logger.info(f"Scan coordination completed for scan {scan_history_id}")
        return coordination_result
        
    except Exception as e:
        logger.error(f"Scan coordination failed for scan {scan_history_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "scan_history_id": scan_history_id,
            "domain_id": domain_id
        }


@app.task(name="initiate_subscan", bind=False, queue="orchestrator_queue")
def initiate_subscan(subdomain_id, engine_id=None, scan_type=None, results_dir=None, url_filter=""):
    """Initiate a new subscan.

    Args:
        subdomain_id (int): Subdomain id.
        engine_id (int): Engine ID.
        scan_type (int): Scan type (port_scan, subdomain_discovery, vulnerability_scan...).
        results_dir (str): Results directory.
        url_filter (str): URL path. Default: ''
    """
    import uuid
    import json
    import yaml
    from celery import chain
    from django.utils import timezone
    from reNgine.settings import RENGINE_RESULTS
    from reNgine.definitions import RUNNING_TASK, FAILED_TASK
    from reNgine.tasks import get_scan_tasks
    from reNgine.tasks.reporting import generate_report
    from reNgine.tasks.notification import send_notification
    from reNgine.utilities.path import is_safe_path
    from scanEngine.models import EngineType
    from startScan.models import Subdomain, ScanHistory, Domain, SubScan

    if results_dir is None:
        results_dir = RENGINE_RESULTS

    # Get all available tasks
    available_tasks = get_scan_tasks()

    subscan = None
    try:
        # Get Subdomain, Domain and ScanHistory
        subdomain = Subdomain.objects.get(pk=subdomain_id)
        scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
        domain = Domain.objects.get(pk=subdomain.target_domain.id)

        logger.info(f"Initiating subscan for subdomain {subdomain.name} on celery")

        # Get EngineType
        engine_id = engine_id or scan.scan_type.id
        engine = EngineType.objects.get(pk=engine_id)

        # Get YAML config
        config = yaml.safe_load(engine.yaml_configuration)
        config_subscan = config.get(scan_type)

        # Create scan activity of SubScan Model
        subscan = SubScan(
            start_scan_date=timezone.now(),
            celery_ids=[initiate_subscan.request.id],
            scan_history=scan,
            subdomain=subdomain,
            type=scan_type,
            status=RUNNING_TASK,
            engine=engine,
        )
        subscan.save()

        # Create results directory
        try:
            uuid_scan = uuid.uuid1()
            # Create safe path for results directory
            results_path = f"{domain.name}/subscans/{uuid_scan}"
            if not is_safe_path(RENGINE_RESULTS, results_path):
                raise ValueError("Unsafe path detected")
            results_dir = f"{RENGINE_RESULTS}/{results_path}"
        except (ValueError, OSError) as e:
            logger.error(f"Failed to create results directory: {str(e)}")
            subscan.status = FAILED_TASK
            subscan.error_message = "Failed to create results directory, scan failed"
            subscan.save()
            return {"success": False, "error": subscan.error_message}

        # Get task method from available tasks
        method = available_tasks.get(scan_type)
        if not method:
            logger.warning(
                f"Task {scan_type} is not supported by reNgine-ng. Available tasks: {list(available_tasks.keys())}"
            )
            subscan.status = FAILED_TASK
            subscan.error_message = f"Unsupported task type: {scan_type}"
            subscan.save()
            return {"success": False, "error": f"Task {scan_type} is not supported by reNgine-ng"}

        # Add task to scan history
        if scan_type not in scan.tasks:
            scan.tasks.append(scan_type)
            scan.save()

        # Send start notification
        send_notification.delay(
            f"Subscan {scan_type} started for {subdomain.name}",
            scan_history_id=scan.id,
            subscan_id=subscan.id
        )

        # Build context
        ctx = {
            "scan_history_id": scan.id,
            "subscan_id": subscan.id,
            "engine_id": engine_id,
            "domain_id": domain.id,
            "subdomain_id": subdomain.id,
            "yaml_configuration": config,
            "yaml_configuration_subscan": config_subscan,
            "results_dir": results_dir,
            "url_filter": url_filter,
        }

        ctx_str = json.dumps(ctx, indent=2)
        logger.warning(f"Starting subscan {subscan.id} with context:\n{ctx_str}")

        # Build header + callback
        workflow = method.si(ctx=ctx)
        callback = generate_report.si(ctx=ctx).set(link_error=[generate_report.si(ctx=ctx)])

        # Run Celery tasks
        task = chain(workflow, callback).on_error(callback).delay()
        subscan.celery_ids.append(task.id)
        subscan.save()

        return {"success": True, "task_id": task.id}
    except Exception as e:
        logger.exception(e)
        if subscan:
            subscan.status = FAILED_TASK
            subscan.error_message = str(e)
            subscan.save()
        return {"success": False, "error": str(e)}
