"""
Secator distributed processor for reNgine integration.

This module provides the main interface between reNgine's distributed processing
system and Secator workflows, ensuring seamless integration and result handling.
"""

import time
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from reNgine.utilities.database_interface import DatabaseInterface
from reNgine.utilities.distributed.base import (
    DistributedConfig,
    DistributedResult,
    DistributedTaskBase,
    ProcessingStatus,
)
from reNgine.utilities.distributed.command import DistributedCommandExecutor
from reNgine.utilities.distributed.database import DistributedDatabaseProcessor

from .config import ensure_secator_initialized


logger = get_task_logger(__name__)


class SecatorDistributedProcessor(DistributedTaskBase):
    """
    Main processor for executing Secator workflows via reNgine's distributed system.

    This class bridges Secator's workflow execution with reNgine's distributed
    processing infrastructure, providing seamless integration and result handling.
    """

    def __init__(self, config: Optional[DistributedConfig] = None, db_interface: Optional[DatabaseInterface] = None):
        super().__init__(config)
        self.db_interface = db_interface
        self.command_executor = DistributedCommandExecutor(config, db_interface)
        self.database_processor = DistributedDatabaseProcessor(config, db_interface)
        self._secator_initialized = False

    def get_task_name(self) -> str:
        return "secator_distributed_processor"

    def get_queue_name(self) -> str:
        return "orchestrator_queue"

    def initialize_secator(self) -> None:
        """Initialize Secator configuration."""
        if not self._secator_initialized:
            ensure_secator_initialized()
            self._secator_initialized = True
            logger.info("Secator initialized for distributed processing")

    def execute_secator_workflow(
        self, workflow_config: Dict[str, Any], target: str, ctx: Dict[str, Any], batch_id: Optional[str] = None
    ) -> DistributedResult[Dict[str, Any]]:
        """
        Execute a Secator workflow using reNgine's distributed processing.

        Args:
            workflow_config: Secator workflow configuration
            target: Target to scan (domain, IP, URL, etc.)
            ctx: Context containing scan information
            batch_id: Optional batch identifier

        Returns:
            DistributedResult containing execution results
        """
        start_time = time.time()
        batch_id = batch_id or self.create_batch_id("secator_workflow")

        self.log_processing_start(batch_id, 1)
        self.initialize_secator()

        result = DistributedResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                # Load and execute Secator workflow
                workflow_results = self._execute_secator_workflow_internal(workflow_config, target, ctx)

                # Process and save results
                saved_results = self._process_secator_results(workflow_results, ctx, batch_id)

                # Update result
                result.data = {
                    "workflow_name": workflow_config.get("name", "unknown"),
                    "target": target,
                    "results_count": len(workflow_results),
                    "saved_count": saved_results.get("saved_count", 0),
                    "errors": saved_results.get("errors", []),
                }

                result.status = ProcessingStatus.COMPLETED
                result.processing_time = time.time() - start_time

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Secator workflow execution failed for {batch_id}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result

    def _execute_secator_workflow_internal(
        self, workflow_config: Dict[str, Any], target: str, ctx: Dict[str, Any]
    ) -> List[Any]:
        """
        Execute Secator workflow internally.

        Args:
            workflow_config: Secator workflow configuration
            target: Target to scan
            ctx: Context information

        Returns:
            List of workflow results
        """
        try:
            # Import Secator components
            from secator.runners import Workflow
            from secator.template import TemplateLoader

            # Create workflow from config
            template = TemplateLoader.from_dict(workflow_config)
            workflow = Workflow(template, target)

            # Execute workflow and collect results
            results = []
            for result in workflow.run():
                results.append(result)

                # Log progress
                if hasattr(result, "_type"):
                    logger.debug(
                        f"Secator result: {result._type} - {getattr(result, 'url', getattr(result, 'host', 'unknown'))}"
                    )

            logger.info(f"Secator workflow completed: {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Failed to execute Secator workflow: {e}")
            raise

    def _process_secator_results(self, results: List[Any], ctx: Dict[str, Any], batch_id: str) -> Dict[str, Any]:
        """
        Process and save Secator results to reNgine database.

        Args:
            results: List of Secator results
            ctx: Context information
            batch_id: Batch identifier

        Returns:
            Dict containing processing summary
        """
        saved_count = 0
        errors = []

        try:
            for result in results:
                try:
                    # Convert Secator result to reNgine format
                    rengine_data = self._convert_secator_result(result, ctx)

                    if rengine_data:
                        # Save to database using distributed processor
                        save_result = self.database_processor.process_records_batch([rengine_data], batch_id, ctx)

                        if save_result.is_successful:
                            saved_count += 1
                        else:
                            errors.extend(save_result.errors)

                except Exception as e:
                    error_msg = f"Failed to process result: {e}"
                    errors.append(error_msg)
                    logger.error(error_msg)

            logger.info(f"Processed {len(results)} Secator results, saved {saved_count}")

        except Exception as e:
            error_msg = f"Failed to process Secator results: {e}"
            errors.append(error_msg)
            logger.error(error_msg)

        return {"saved_count": saved_count, "errors": errors}

    def _convert_secator_result(self, result: Any, ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert Secator result to reNgine database format.

        Args:
            result: Secator result object
            ctx: Context information

        Returns:
            Dict containing reNgine-formatted data or None
        """
        try:
            # Get result type
            result_type = getattr(result, "_type", "unknown")

            # Convert based on result type
            if result_type == "subdomain":
                return self._convert_subdomain_result(result, ctx)
            elif result_type == "ip":
                return self._convert_ip_result(result, ctx)
            elif result_type == "port":
                return self._convert_port_result(result, ctx)
            elif result_type == "url":
                return self._convert_url_result(result, ctx)
            elif result_type == "vulnerability":
                return self._convert_vulnerability_result(result, ctx)
            elif result_type == "tag":
                return self._convert_tag_result(result, ctx)
            else:
                logger.debug(f"Unknown result type: {result_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to convert Secator result: {e}")
            return None

    def _convert_subdomain_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator subdomain result to reNgine format."""
        return {
            "name": getattr(result, "host", ""),
            "scan_history_id": ctx.get("scan_id"),
            "domain_id": ctx.get("domain_id"),
            "is_imported_subdomain": False,
            "is_important": False,
            "is_http": getattr(result, "is_http", False),
            "is_https": getattr(result, "is_https", False),
            "http_url": getattr(result, "http_url", ""),
            "https_url": getattr(result, "https_url", ""),
            "port": getattr(result, "port", None),
            "ip_addresses": getattr(result, "ips", []),
            "cname": getattr(result, "cname", ""),
            "cdn": getattr(result, "cdn", False),
            "waf": getattr(result, "waf", ""),
            "technologies": getattr(result, "technologies", []),
            "title": getattr(result, "title", ""),
            "banner": getattr(result, "banner", ""),
            "response_time": getattr(result, "response_time", 0),
            "http_status": getattr(result, "status_code", None),
            "content_length": getattr(result, "content_length", 0),
            "content_type": getattr(result, "content_type", ""),
            "server": getattr(result, "server", ""),
            "powered_by": getattr(result, "powered_by", ""),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def _convert_ip_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator IP result to reNgine format."""
        return {
            "address": getattr(result, "ip", ""),
            "scan_history_id": ctx.get("scan_id"),
            "subdomain_id": ctx.get("subdomain_id"),
            "is_cdn": getattr(result, "cdn", False),
            "is_private": getattr(result, "private", False),
            "is_cloud": getattr(result, "cloud", False),
            "country": getattr(result, "country", ""),
            "city": getattr(result, "city", ""),
            "asn": getattr(result, "asn", ""),
            "asn_org": getattr(result, "asn_org", ""),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def _convert_port_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator port result to reNgine format."""
        return {
            "port": getattr(result, "port", 0),
            "scan_history_id": ctx.get("scan_id"),
            "subdomain_id": ctx.get("subdomain_id"),
            "is_open": getattr(result, "open", True),
            "service_name": getattr(result, "service", ""),
            "service_version": getattr(result, "version", ""),
            "banner": getattr(result, "banner", ""),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def _convert_url_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator URL result to reNgine format."""
        return {
            "http_url": getattr(result, "url", ""),
            "scan_history_id": ctx.get("scan_id"),
            "subdomain_id": ctx.get("subdomain_id"),
            "method": getattr(result, "method", "GET"),
            "status_code": getattr(result, "status_code", 0),
            "content_length": getattr(result, "content_length", 0),
            "content_type": getattr(result, "content_type", ""),
            "title": getattr(result, "title", ""),
            "response_time": getattr(result, "response_time", 0),
            "server": getattr(result, "server", ""),
            "powered_by": getattr(result, "powered_by", ""),
            "technologies": getattr(result, "technologies", []),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def _convert_vulnerability_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator vulnerability result to reNgine format."""
        return {
            "name": getattr(result, "name", ""),
            "scan_history_id": ctx.get("scan_id"),
            "subdomain_id": ctx.get("subdomain_id"),
            "endpoint_id": ctx.get("endpoint_id"),
            "severity": getattr(result, "severity", "info"),
            "description": getattr(result, "description", ""),
            "solution": getattr(result, "solution", ""),
            "reference": getattr(result, "reference", ""),
            "cve": getattr(result, "cve", ""),
            "cwe": getattr(result, "cwe", ""),
            "owasp": getattr(result, "owasp", ""),
            "tags": getattr(result, "tags", []),
            "template_id": getattr(result, "template_id", ""),
            "template_url": getattr(result, "template_url", ""),
            "matcher_name": getattr(result, "matcher_name", ""),
            "extracted_results": getattr(result, "extracted_results", []),
            "curl_command": getattr(result, "curl_command", ""),
            "http_url": getattr(result, "url", ""),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def _convert_tag_result(self, result: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Secator tag result to reNgine format."""
        return {
            "name": getattr(result, "name", ""),
            "scan_history_id": ctx.get("scan_id"),
            "subdomain_id": ctx.get("subdomain_id"),
            "endpoint_id": ctx.get("endpoint_id"),
            "tag_type": getattr(result, "type", ""),
            "description": getattr(result, "description", ""),
            "severity": getattr(result, "severity", "info"),
            "match": getattr(result, "match", ""),
            "discovered_by": "secator",
            "discovered_date": time.time(),
        }

    def execute_secator_task(
        self, task_name: str, target: str, ctx: Dict[str, Any], **kwargs
    ) -> DistributedResult[Dict[str, Any]]:
        """
        Execute a single Secator task.

        Args:
            task_name: Name of the Secator task to execute
            target: Target to scan
            ctx: Context information
            **kwargs: Additional task parameters

        Returns:
            DistributedResult containing execution results
        """
        start_time = time.time()
        batch_id = self.create_batch_id(f"secator_task_{task_name}")

        self.log_processing_start(batch_id, 1)
        self.initialize_secator()

        result = DistributedResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                # Import and execute Secator task
                from secator.tasks import get_task_by_name

                task_class = get_task_by_name(task_name)
                if not task_class:
                    raise ValueError(f"Unknown Secator task: {task_name}")

                # Execute task
                task_instance = task_class(target, **kwargs)
                task_results = list(task_instance.run())

                # Process results
                saved_results = self._process_secator_results(task_results, ctx, batch_id)

                # Update result
                result.data = {
                    "task_name": task_name,
                    "target": target,
                    "results_count": len(task_results),
                    "saved_count": saved_results.get("saved_count", 0),
                    "errors": saved_results.get("errors", []),
                }

                result.status = ProcessingStatus.COMPLETED
                result.processing_time = time.time() - start_time

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Secator task execution failed for {task_name}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result
