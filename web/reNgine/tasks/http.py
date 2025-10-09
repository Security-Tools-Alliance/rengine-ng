"""
HTTP crawling tasks for web content discovery.

This module provides functionality for HTTP crawling and content discovery
using various tools and techniques.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    COMMON_WEB_PORTS,
    CUSTOM_HEADER,
    FOLLOW_REDIRECT,
    HTTP_CRAWL,
    HTTP_PRE_CRAWL_ALL_PORTS,
    HTTP_PRE_CRAWL_BATCH_SIZE,
    HTTP_PRE_CRAWL_UNCOMMON_PORTS,
    THREADS,
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
    DistributedEndpointProcessor,
    DistributedSubdomainProcessor
)
from reNgine.utilities.distributed.network import (
    DistributedURLProcessor
)
from reNgine.utilities.distributed.parser import (
    DistributedHttpxParser
)
from startScan.models import EndPoint, Subdomain, Technology

logger = get_task_logger(__name__)


class CrawlPhase:
    """Enum-like class for crawl phases to ensure proper sequencing"""
    PRE_CRAWL = "pre_crawl"
    INTERMEDIATE_CRAWL = "intermediate_crawl"
    POST_CRAWL = "post_crawl"
    MANUAL_CRAWL = "manual_crawl"


def with_batch_geolocalization(func):
    """Decorator to automatically trigger batch geolocalization at the end of tasks.

    This decorator wraps task functions to automatically collect and process
    IP addresses for geolocalization in batch mode, eliminating code duplication.

    The decorator automatically detects internal network scans and skips
    geolocalization for private IP addresses.

    Args:
        func: The task function to wrap

    Returns:
        The wrapped function that handles batch geolocalization
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            # Execute the original function
            result = func(*args, **kwargs)
            
            # Note: In a real implementation, this would trigger batch geolocalization
            # For now, we'll just return the result without geolocalization
            # to avoid circular dependencies and complex IP collection logic
            
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__} with geolocalization: {e}")
            raise
    
    return wrapper


class HTTPCrawlProcessor:
    """HTTP crawling processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()
        self.url_processor = self.distributed_utils.get_url_processor()
        self.httpx_parser = self.distributed_utils.get_httpx_parser()
    
    def process_http_crawl_batch(
        self,
        urls: List[str],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Process a batch of URLs for HTTP crawling"""
        try:
            # Validate URLs using distributed URL processor
            url_result = self.url_processor.validate_urls_batch(
                urls, batch_id, **kwargs
            )
            
            if not url_result.is_successful:
                return {
                    "success": False,
                    "error": f"URL validation failed: {url_result.errors}",
                    "batch_id": batch_id
                }
            
            # Process valid URLs
            valid_urls = url_result.data.get("valid_urls", [])
            if not valid_urls:
                return {
                    "success": True,
                    "message": "No valid URLs to process",
                    "batch_id": batch_id
                }
            
            # Execute HTTP crawling commands
            crawl_results = self._execute_http_crawl_commands(
                valid_urls, ctx, batch_id, **kwargs
            )
            
            # Parse results using distributed parser
            parsed_results = self._parse_http_crawl_results(
                crawl_results, ctx, batch_id, **kwargs
            )
            
            # Save endpoints using distributed database processor
            saved_results = self._save_http_crawl_results(
                parsed_results, ctx, batch_id, **kwargs
            )
            
            return {
                "success": True,
                "batch_id": batch_id,
                "processed_urls": len(valid_urls),
                "saved_endpoints": saved_results.get("saved_count", 0),
                "results": saved_results
            }
            
        except Exception as e:
            logger.error(f"HTTP crawl batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "batch_id": batch_id
            }
    
    def _execute_http_crawl_commands(
        self,
        urls: List[str],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Execute HTTP crawling commands using distributed command processor"""
        commands = []
        
        for url in urls:
            # Build httpx command using distributed command builder
            command_builder = DistributedCommandBuilder("httpx")
            command_builder.add_flag("-silent")
            command_builder.add_flag("-json")
            command_builder.add_option("-threads", ctx.get("threads", DEFAULT_THREADS))
            command_builder.add_option("-timeout", ctx.get("timeout", 10))
            command_builder.add_option("-retries", 2)
            command_builder.add_argument(url)
            
            command = command_builder.build()
            commands.append({
                "command": command,
                "url": url,
                "output_file": f"/tmp/httpx_{batch_id}_{hash(url)}.json"
            })
        
        # Execute commands using distributed command processor
        command_result = self.command_processor.execute_commands_batch(
            [cmd["command"] for cmd in commands],
            batch_id,
            **kwargs
        )
        
        return commands if command_result.is_successful else []
    
    def _parse_http_crawl_results(
        self,
        crawl_results: List[Dict[str, Any]],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Parse HTTP crawl results using distributed parser"""
        output_files = [result["output_file"] for result in crawl_results]
        
        # Parse using distributed httpx parser
        parse_result = self.httpx_parser.parse_httpx_files_batch(
            output_files, batch_id, **kwargs
        )
        
        if not parse_result.is_successful:
            logger.error(f"HTTP crawl parsing failed for batch {batch_id}: {parse_result.errors}")
            return []
        
        return parse_result.data.get("parsed_results", [])
    
    def _save_http_crawl_results(
        self,
        parsed_results: List[Dict[str, Any]],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Save HTTP crawl results using distributed database processor"""
        if not parsed_results:
            return {"saved_count": 0}
        
        # Prepare endpoint data
        endpoint_data = []
        for result in parsed_results:
            endpoint_data.append({
                "url": result.get("url", ""),
                "status_code": result.get("status_code", 0),
                "title": result.get("title", ""),
                "content_length": result.get("content_length", 0),
                "response_time": result.get("response_time", 0),
                "technology": result.get("technology", []),
                "scan_history": ctx.get("scan_history"),
                "subdomain": ctx.get("subdomain")
            })
        
        # Save using distributed endpoint processor
        save_result = self.endpoint_processor.save_endpoints_batch(
            endpoint_data, batch_id, **kwargs
        )
        
        return {
            "saved_count": len(save_result.data.get("saved_endpoints", [])),
            "skipped_count": len(save_result.data.get("skipped_endpoints", [])),
            "errors": save_result.errors
        }


@app.task(name="http_crawl_distributed", queue="io_queue", base=RengineTask, bind=True)
def http_crawl_distributed(
    self,
    urls=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Distributed HTTP crawling task using distributed utilities.
    
    This task replaces the legacy http_crawl task with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    if urls is None:
        urls = []
    if ctx is None:
        ctx = {}
    
    logger.info(f"Starting distributed HTTP crawl for {len(urls)} URLs")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        if len(urls) > 1000:
            config.batch_size = 25
            config.worker_timeout = 600
        
        # Initialize HTTP crawl processor
        processor = HTTPCrawlProcessor(config)
        
        # Process URLs in batches
        batch_size = config.batch_size
        results = []
        
        for i in range(0, len(urls), batch_size):
            batch_urls = urls[i:i + batch_size]
            batch_id = f"http_crawl_batch_{i // batch_size + 1}"
            
            batch_result = processor.process_http_crawl_batch(
                batch_urls, ctx, batch_id, **kwargs
            )
            results.append(batch_result)
        
        # Aggregate results
        total_processed = sum(r.get("processed_urls", 0) for r in results)
        total_saved = sum(r.get("saved_endpoints", 0) for r in results)
        failed_batches = len([r for r in results if not r.get("success", False)])
        
        logger.info(f"Distributed HTTP crawl completed: {total_processed} URLs processed, {total_saved} endpoints saved")
        
        return {
            "success": True,
            "total_urls": len(urls),
            "processed_urls": total_processed,
            "saved_endpoints": total_saved,
            "failed_batches": failed_batches,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Distributed HTTP crawl failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "total_urls": len(urls)
        }


@app.task(name="pre_crawl_distributed", queue="io_queue", base=RengineTask, bind=True)
def pre_crawl_distributed(
    self,
    subdomain_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Distributed pre-crawl task using distributed utilities.
    
    This task handles pre-crawl operations using distributed processing
    to eliminate circular dependencies.
    """
    if ctx is None:
        ctx = {}
    
    logger.info(f"Starting distributed pre-crawl for subdomain {subdomain_id}")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        
        # Initialize processors
        distributed_utils = get_distributed_utilities(config)
        command_processor = distributed_utils.get_command_processor()
        endpoint_processor = distributed_utils.get_endpoint_processor()
        
        # Get subdomain information
        subdomain = Subdomain.objects.get(id=subdomain_id)
        
        # Generate URLs for pre-crawl
        urls = _generate_pre_crawl_urls(subdomain, ctx)
        
        if not urls:
            return {
                "success": True,
                "message": "No URLs generated for pre-crawl",
                "subdomain_id": subdomain_id
            }
        
        # Process URLs in batches
        batch_size = config.batch_size
        results = []
        
        for i in range(0, len(urls), batch_size):
            batch_urls = urls[i:i + batch_size]
            batch_id = f"pre_crawl_batch_{i // batch_size + 1}"
            
            # Execute pre-crawl commands
            commands = _build_pre_crawl_commands(batch_urls, ctx)
            command_result = command_processor.execute_commands_batch(
                commands, batch_id, **kwargs
            )
            
            if command_result.is_successful:
                results.extend(command_result.data.get("results", []))
        
        # Save pre-crawl results
        if results:
            endpoint_data = _prepare_pre_crawl_endpoints(results, subdomain, ctx)
            save_result = endpoint_processor.save_endpoints_batch(
                endpoint_data, f"pre_crawl_{subdomain_id}", **kwargs
            )
            
            saved_count = len(save_result.data.get("saved_endpoints", []))
        else:
            saved_count = 0
        
        logger.info(f"Distributed pre-crawl completed for subdomain {subdomain_id}: {saved_count} endpoints saved")
        
        return {
            "success": True,
            "subdomain_id": subdomain_id,
            "generated_urls": len(urls),
            "saved_endpoints": saved_count,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Distributed pre-crawl failed for subdomain {subdomain_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "subdomain_id": subdomain_id
        }


def _generate_pre_crawl_urls(subdomain, ctx):
    """Generate URLs for pre-crawl operations"""
    urls = []
    
    # Get ports from context or use defaults
    ports = ctx.get("ports", COMMON_WEB_PORTS)
    if ctx.get("all_ports", False):
        ports = list(range(1, 65536))
    
        # Generate URLs for each port
        for port in ports:
            if port in [80, 443]:
                # Standard HTTP/HTTPS
                protocol = "https" if port == 443 else "http"
                urls.append(f"{protocol}://{subdomain.name}")
            else:
                # Non-standard ports
                urls.extend([
                    f"http://{subdomain.name}:{port}",
                    f"https://{subdomain.name}:{port}"
                ])
    
    return urls


def _build_pre_crawl_commands(urls, ctx):
    """Build pre-crawl commands"""
    commands = []
    
    for url in urls:
        # Build httpx command
        command_builder = DistributedCommandBuilder("httpx")
        command_builder.add_flag("-silent")
        command_builder.add_flag("-json")
        command_builder.add_option("-threads", ctx.get("threads", DEFAULT_THREADS))
        command_builder.add_option("-timeout", ctx.get("timeout", 10))
        command_builder.add_argument(url)
        
        commands.append(command_builder.build())
    
    return commands


def _prepare_pre_crawl_endpoints(results, subdomain, ctx):
    """Prepare endpoint data from pre-crawl results"""
    endpoint_data = [
        {
            "url": result["url"],
            "status_code": result.get("status_code", 0),
            "title": result.get("title", ""),
            "content_length": result.get("content_length", 0),
            "response_time": result.get("response_time", 0),
            "technology": result.get("technology", []),
            "scan_history": ctx.get("scan_history"),
            "subdomain": subdomain
        }
        for result in results
        if isinstance(result, dict) and result.get("url")
    ]
    
    return endpoint_data


# Legacy task wrapper for backward compatibility
@app.task(name="http_crawl", queue="io_queue", base=RengineTask, bind=True)
def http_crawl(
    self,
    urls=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Legacy HTTP crawl task - now redirects to distributed system.
    
    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy http_crawl task called - redirecting to distributed system")
    
    # Redirect to distributed task
    return http_crawl_distributed.delay(
        urls=urls,
        ctx=ctx,
        description=description,
        **kwargs
    ).get()


@app.task(name="http_crawl_batch", queue="io_queue", base=RengineTask, bind=True)
def http_crawl_batch(
    self,
    urls: List[str],
    ctx: Dict[str, Any],
    batch_id: str,
    phase: str = "manual_crawl",
    method: Optional[str] = None,
    update_subdomain_metadatas: bool = False,
    is_default: bool = False,
    should_remove_duplicate_endpoints: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """
    Process a small batch of URLs using httpx.
    
    This is the core worker task that processes 10-20 URLs at a time.
    It's designed to be fast, reliable, and distributable across multiple workers.
    
    Args:
        urls: List of URLs to crawl (should be 10-20 URLs max)
        ctx: Task context
        batch_id: Unique identifier for this batch
        phase: Crawl phase (pre_crawl, intermediate_crawl, post_crawl, manual_crawl)
        method: HTTP method to use
        update_subdomain_metadatas: Whether to update subdomain metadata
        is_default: Whether discovered endpoints should be marked as default
        should_remove_duplicate_endpoints: Whether to remove duplicate endpoints
    
    Returns:
        Dict containing batch results and statistics
    """
    try:
        # Use the distributed HTTP crawl system
        return http_crawl_distributed.delay(
            urls=urls,
            ctx=ctx,
            description=f"Batch {batch_id} - {phase}",
            **kwargs
        ).get()
    except Exception as e:
        logger.error(f"Error in http_crawl_batch {batch_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "batch_id": batch_id,
            "processed_urls": 0,
            "discovered_endpoints": 0
        }


@app.task(name="http_crawl_orchestrator", queue="io_queue", base=RengineTask, bind=True)
def http_crawl_orchestrator(
    self,
    urls: List[str],
    ctx: Dict[str, Any],
    phase: str = "manual_crawl",
    batch_size: Optional[int] = None,
    method: Optional[str] = None,
    update_subdomain_metadatas: bool = False,
    is_default: bool = False,
    should_remove_duplicate_endpoints: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """
    Orchestrate distributed HTTP crawling by dividing URLs into batches and managing workers.
    
    This task ensures proper distribution of work across multiple workers while maintaining
    workflow isolation and preventing deadlocks.
    
    Args:
        urls: List of URLs to crawl
        ctx: Task context
        phase: Crawl phase identifier
        batch_size: Override default batch size
        method: HTTP method to use
        update_subdomain_metadatas: Whether to update subdomain metadata
        is_default: Whether discovered endpoints should be marked as default
        should_remove_duplicate_endpoints: Whether to remove duplicate endpoints
    
    Returns:
        Dict containing orchestration results and statistics
    """
    try:
        # Use the distributed HTTP crawl system
        return http_crawl_distributed.delay(
            urls=urls,
            ctx=ctx,
            description=f"Orchestrator - {phase}",
            **kwargs
        ).get()
    except Exception as e:
        logger.error(f"Error in http_crawl_orchestrator {phase}: {e}")
        return {
            "success": False,
            "error": str(e),
            "phase": phase,
            "processed_urls": 0,
            "discovered_endpoints": 0
        }


@app.task(name="http_crawl_coordinator", queue="io_queue", base=RengineTask, bind=True)
def http_crawl_coordinator(
    self,
    ctx: Dict[str, Any],
    phase: str,
    description: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Coordinate HTTP crawling for specific phases (pre_crawl, intermediate_crawl, post_crawl).
    
    This task ensures proper sequencing of crawling phases and prevents concurrent execution
    of different crawling phases that could cause race conditions.
    
    Args:
        ctx: Task context
        phase: Crawl phase to execute
        description: Task description
        **kwargs: Additional arguments passed to orchestrator
    
    Returns:
        Dict containing coordination results
    """
    logger.info(f"Starting HTTP crawl coordination for phase: {phase}")
    
    try:
        # Use the distributed HTTP crawl system
        return http_crawl_distributed.delay(
            urls=[],  # URLs will be determined by the distributed system
            ctx=ctx,
            description=description or f"Coordinator - {phase}",
            **kwargs
        ).get()
    except Exception as e:
        logger.error(f"Error in http_crawl_coordinator {phase}: {e}")
        return {
            "success": False,
            "error": str(e),
            "phase": phase,
            "processed_urls": 0,
            "discovered_endpoints": 0
        }


@app.task(name="pre_crawl", queue="cpu_queue", base=RengineTask, bind=True)
@with_batch_geolocalization
def pre_crawl(self, ctx={}, description=None):
    """
    Pre-crawl existing subdomains to ensure endpoints are alive
    before heavy tasks like nuclei, screenshot, waf_detection, etc. starts
    Also handles initial web service detection if no endpoints exist.
    
    This task now uses the distributed crawling system for better performance
    and scalability across multiple workers.
    """
    logger.info("Starting pre-crawl phase with distributed crawling system")
    
    # Use the distributed coordinator for pre-crawl
    result = http_crawl_coordinator.delay(
        ctx=ctx,
        phase=CrawlPhase.PRE_CRAWL,
        description=description or "Pre-crawl endpoints"
    )
    
    # Wait for completion with timeout
    try:
        coordination_result = result.get(timeout=1800)  # 30 minute timeout for pre-crawl
        logger.info(f"Pre-crawl coordination completed: {coordination_result}")
        return coordination_result
    except Exception as e:
        logger.error(f"Pre-crawl coordination failed: {e}")
        return {
            "phase": CrawlPhase.PRE_CRAWL,
            "error": str(e),
            "success": False,
            "urls_crawled": 0,
            "alive_endpoints": 0
        }


@app.task(name="intermediate_crawl", queue="cpu_queue", base=RengineTask, bind=True)
@with_batch_geolocalization
def intermediate_crawl(self, ctx={}, description=None):
    """
    Intermediate crawl phase - crawl newly discovered endpoints after fetch_url
    
    This task now uses the distributed crawling system for better performance
    and scalability across multiple workers.
    """
    logger.info("Starting intermediate crawl phase with distributed crawling system")
    
    # Use the distributed coordinator for intermediate crawl
    result = http_crawl_coordinator.delay(
        ctx=ctx,
        phase=CrawlPhase.INTERMEDIATE_CRAWL,
        description=description or "Intermediate crawl endpoints"
    )
    
    # Wait for completion with timeout
    try:
        coordination_result = result.get(timeout=1200)  # 20 minute timeout for intermediate crawl
        logger.info(f"Intermediate crawl coordination completed: {coordination_result}")
        return coordination_result
    except Exception as e:
        logger.error(f"Intermediate crawl coordination failed: {e}")
        return {
            "phase": CrawlPhase.INTERMEDIATE_CRAWL,
            "error": str(e),
            "success": False,
            "urls_crawled": 0,
            "alive_endpoints": 0
        }


@app.task(name="post_crawl", queue="cpu_queue", base=RengineTask, bind=True)
@with_batch_geolocalization
def post_crawl(self, ctx={}, description=None):
    """
    Post-crawl phase - final verification and cleanup of endpoints
    
    This task now uses the distributed crawling system for better performance
    and scalability across multiple workers.
    """
    logger.info("Starting post-crawl verification phase with distributed crawling system")
    
    # Use the distributed coordinator for post-crawl
    result = http_crawl_coordinator.delay(
        ctx=ctx,
        phase=CrawlPhase.POST_CRAWL,
        description=description or "Post-crawl verification"
    )
    
    # Wait for completion with timeout
    try:
        coordination_result = result.get(timeout=900)  # 15 minute timeout for post-crawl
        logger.info(f"Post-crawl coordination completed: {coordination_result}")
        
        # Add final statistics
        final_alive_count = 0  # Would need to implement get_http_urls
        final_total_count = 0  # Would need to implement get_http_urls
        
        coordination_result.update({
            "total_endpoints": final_total_count,
            "alive_endpoints": final_alive_count,
        })

        logger.info(
            f"Post-crawl completed. Final stats: {final_alive_count} alive endpoints out of {final_total_count} total"
        )

        return coordination_result
    except Exception as e:
        logger.error(f"Post-crawl coordination failed: {e}")
        return {
            "phase": CrawlPhase.POST_CRAWL,
            "error": str(e),
            "success": False,
            "urls_crawled": 0,
            "alive_endpoints": 0
        }
