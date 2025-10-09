"""
Refactored reporting tasks using distributed utilities.

This module provides reporting functionality using the distributed utilities
architecture, eliminating circular dependencies and following SOLID, KISS, and DRY principles.

Key components:
1. Reporting tasks that use distributed utilities
2. No direct imports from other task modules
3. Clean separation of concerns
4. Reusable distributed processing
"""

import json
import os
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utilities.distributed.utilities import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config
)
from reNgine.utilities.distributed.database import (
    DistributedSubdomainProcessor
)
from startScan.models import ScanHistory

logger = get_task_logger(__name__)


class ReportingProcessor:
    """Reporting processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()
    
    def process_report_generation_batch(
        self,
        scan_history_id: int,
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Process report generation for a scan"""
        try:
            # Get scan history
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            
            # Generate report data
            report_data = self._generate_report_data(
                scan_history, ctx, batch_id, **kwargs
            )
            
            # Generate report files
            report_files = self._generate_report_files(
                report_data, ctx, batch_id, **kwargs
            )
            
            # Save report records
            saved_results = self._save_report_records(
                report_files, ctx, batch_id, **kwargs
            )
            
            return {
                "success": True,
                "batch_id": batch_id,
                "scan_history_id": scan_history_id,
                "generated_reports": len(report_files),
                "saved_records": saved_results.get("saved_count", 0),
                "results": saved_results
            }
            
        except Exception as e:
            logger.error(f"Report generation batch processing failed for batch {batch_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "batch_id": batch_id
            }
    
    def _generate_report_data(
        self,
        scan_history: ScanHistory,
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate report data"""
        try:
            # Collect scan data
            scan_data = {
                "scan_info": {
                    "id": scan_history.id,
                    "domain": scan_history.domain.name if scan_history.domain else "Unknown",
                    "started_at": scan_history.started_at,
                    "completed_at": scan_history.completed_at,
                    "status": scan_history.status,
                    "scan_type": scan_history.scan_type
                },
                "subdomains": [],
                "endpoints": [],
                "vulnerabilities": [],
                "ports": [],
                "technologies": []
            }
            
            # Get subdomains
            subdomains = scan_history.subdomain_set.all()
            for subdomain in subdomains:
                scan_data["subdomains"].append({
                    "name": subdomain.name,
                    "ip_addresses": [ip.address for ip in subdomain.ip_addresses.all()],
                    "discovered_at": subdomain.discovered_at
                })
            
            # Get endpoints
            endpoints = scan_history.endpoint_set.all()
            for endpoint in endpoints:
                scan_data["endpoints"].append({
                    "url": endpoint.http_url,
                    "status_code": endpoint.http_status,
                    "title": endpoint.page_title,
                    "content_length": endpoint.content_length,
                    "response_time": endpoint.response_time,
                    "technologies": [tech.name for tech in endpoint.technologies.all()]
                })
            
            # Get vulnerabilities
            vulnerabilities = scan_history.vulnerability_set.all()
            for vulnerability in vulnerabilities:
                scan_data["vulnerabilities"].append({
                    "name": vulnerability.name,
                    "severity": vulnerability.severity,
                    "description": vulnerability.description,
                    "endpoint": vulnerability.endpoint.http_url if vulnerability.endpoint else None,
                    "discovered_at": vulnerability.discovered_at
                })
            
            # Get ports
            ports = scan_history.port_set.all()
            for port in ports:
                scan_data["ports"].append({
                    "number": port.number,
                    "service": port.service,
                    "version": port.version,
                    "state": port.state,
                    "subdomain": port.subdomain.name if port.subdomain else None
                })
            
            # Get technologies
            technologies = scan_history.technology_set.all()
            for technology in technologies:
                scan_data["technologies"].append({
                    "name": technology.name,
                    "version": technology.version,
                    "endpoint": technology.endpoint.http_url if technology.endpoint else None
                })
            
            return scan_data
            
        except Exception as e:
            logger.error(f"Failed to generate report data: {e}")
            return {}
    
    def _generate_report_files(
        self,
        report_data: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Generate report files"""
        report_files = []
        
        try:
            # Generate JSON report
            json_report = self._generate_json_report(report_data, ctx, batch_id)
            if json_report:
                report_files.append(json_report)
            
            # Generate HTML report
            html_report = self._generate_html_report(report_data, ctx, batch_id)
            if html_report:
                report_files.append(html_report)
            
            # Generate CSV report
            csv_report = self._generate_csv_report(report_data, ctx, batch_id)
            if csv_report:
                report_files.append(csv_report)
            
            # Generate PDF report
            pdf_report = self._generate_pdf_report(report_data, ctx, batch_id)
            if pdf_report:
                report_files.append(pdf_report)
            
        except Exception as e:
            logger.error(f"Failed to generate report files: {e}")
        
        return report_files
    
    def _generate_json_report(
        self,
        report_data: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str
    ) -> Optional[Dict[str, Any]]:
        """Generate JSON report"""
        try:
            report_file = f"/tmp/scan_report_{batch_id}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return {
                "type": "json",
                "file_path": report_file,
                "size": os.path.getsize(report_file)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return None
    
    def _generate_html_report(
        self,
        report_data: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str
    ) -> Optional[Dict[str, Any]]:
        """Generate HTML report"""
        try:
            report_file = f"/tmp/scan_report_{batch_id}.html"
            
            # Generate HTML content
            html_content = self._create_html_content(report_data)
            
            with open(report_file, 'w') as f:
                f.write(html_content)
            
            return {
                "type": "html",
                "file_path": report_file,
                "size": os.path.getsize(report_file)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return None
    
    def _generate_csv_report(
        self,
        report_data: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str
    ) -> Optional[Dict[str, Any]]:
        """Generate CSV report"""
        try:
            report_file = f"/tmp/scan_report_{batch_id}.csv"
            
            # Generate CSV content
            csv_content = self._create_csv_content(report_data)
            
            with open(report_file, 'w') as f:
                f.write(csv_content)
            
            return {
                "type": "csv",
                "file_path": report_file,
                "size": os.path.getsize(report_file)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return None
    
    def _generate_pdf_report(
        self,
        report_data: Dict[str, Any],
        ctx: Dict[str, Any],
        batch_id: str
    ) -> Optional[Dict[str, Any]]:
        """Generate PDF report"""
        try:
            report_file = f"/tmp/scan_report_{batch_id}.pdf"
            
            # Generate PDF content
            # This would typically use a PDF generation library
            # For now, we'll create a placeholder
            
            with open(report_file, 'w') as f:
                f.write("PDF Report Placeholder")
            
            return {
                "type": "pdf",
                "file_path": report_file,
                "size": os.path.getsize(report_file)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return None
    
    def _create_html_content(self, report_data: Dict[str, Any]) -> str:
        """Create HTML content for report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Report - {report_data.get('scan_info', {}).get('domain', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .vulnerability {{ background-color: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .subdomain {{ background-color: #e6f3ff; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .endpoint {{ background-color: #e6ffe6; padding: 10px; margin: 5px 0; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Scan Report</h1>
                <p><strong>Domain:</strong> {report_data.get('scan_info', {}).get('domain', 'Unknown')}</p>
                <p><strong>Scan ID:</strong> {report_data.get('scan_info', {}).get('id', 'Unknown')}</p>
                <p><strong>Status:</strong> {report_data.get('scan_info', {}).get('status', 'Unknown')}</p>
                <p><strong>Started:</strong> {report_data.get('scan_info', {}).get('started_at', 'Unknown')}</p>
                <p><strong>Completed:</strong> {report_data.get('scan_info', {}).get('completed_at', 'Unknown')}</p>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p>Subdomains: {len(report_data.get('subdomains', []))}</p>
                <p>Endpoints: {len(report_data.get('endpoints', []))}</p>
                <p>Vulnerabilities: {len(report_data.get('vulnerabilities', []))}</p>
                <p>Ports: {len(report_data.get('ports', []))}</p>
                <p>Technologies: {len(report_data.get('technologies', []))}</p>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {''.join([f'<div class="vulnerability"><strong>{vuln.get("name", "Unknown")}</strong> - {vuln.get("severity", "Unknown")}<br>{vuln.get("description", "No description")}</div>' for vuln in report_data.get('vulnerabilities', [])])}
            </div>
            
            <div class="section">
                <h2>Subdomains</h2>
                {''.join([f'<div class="subdomain"><strong>{sub.get("name", "Unknown")}</strong><br>IPs: {", ".join(sub.get("ip_addresses", []))}</div>' for sub in report_data.get('subdomains', [])])}
            </div>
            
            <div class="section">
                <h2>Endpoints</h2>
                {''.join([f'<div class="endpoint"><strong>{endpoint.get("url", "Unknown")}</strong><br>Status: {endpoint.get("status_code", "Unknown")} | Title: {endpoint.get("title", "No title")}</div>' for endpoint in report_data.get('endpoints', [])])}
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _create_csv_content(self, report_data: Dict[str, Any]) -> str:
        """Create CSV content for report"""
        csv_content = "Type,Name,Details\n"
        
        # Add vulnerabilities
        for vuln in report_data.get('vulnerabilities', []):
            csv_content += f"Vulnerability,{vuln.get('name', 'Unknown')},{vuln.get('severity', 'Unknown')}\n"
        
        # Add subdomains
        for sub in report_data.get('subdomains', []):
            csv_content += f"Subdomain,{sub.get('name', 'Unknown')},{', '.join(sub.get('ip_addresses', []))}\n"
        
        # Add endpoints
        for endpoint in report_data.get('endpoints', []):
            csv_content += f"Endpoint,{endpoint.get('url', 'Unknown')},{endpoint.get('status_code', 'Unknown')}\n"
        
        return csv_content
    
    def _save_report_records(
        self,
        report_files: List[Dict[str, Any]],
        ctx: Dict[str, Any],
        batch_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Save report records"""
        try:
            # Create report records
            report_records = []
            for report_file in report_files:
                report_records.append({
                    "scan_history": ctx.get("scan_history"),
                    "report_type": report_file.get("type", "unknown"),
                    "file_path": report_file.get("file_path", ""),
                    "file_size": report_file.get("size", 0),
                    "generated_at": timezone.now()
                })
            
            # Save using distributed database processor
            save_result = self.subdomain_processor.save_reports_batch(
                report_records, f"{batch_id}_reports", **kwargs
            )
            
            return {
                "saved_count": len(save_result.data.get("saved_reports", [])),
                "errors": save_result.errors
            }
            
        except Exception as e:
            logger.error(f"Failed to save report records: {e}")
            return {
                "saved_count": 0,
                "errors": [str(e)]
            }


@app.task(name="generate_scan_report_distributed", queue="reporting_queue", base=RengineTask, bind=True)
def generate_scan_report_distributed(
    self,
    scan_history_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Distributed scan report generation task using distributed utilities.
    
    This task replaces the legacy reporting tasks with a distributed approach
    that eliminates circular dependencies and follows modular design principles.
    """
    if ctx is None:
        ctx = {}
    
    logger.info(f"Starting distributed scan report generation for scan {scan_history_id}")
    
    try:
        # Create distributed configuration
        config = create_balanced_config()
        
        # Initialize reporting processor
        processor = ReportingProcessor(config)
        
        # Process report generation
        result = processor.process_report_generation_batch(
            scan_history_id, ctx, f"scan_report_{scan_history_id}", **kwargs
        )
        
        logger.info(f"Distributed scan report generation completed for scan {scan_history_id}")
        
        return result
        
    except Exception as e:
        logger.error(f"Distributed scan report generation failed for scan {scan_history_id}: {e}")
        return {
            "success": False,
            "error": str(e),
            "scan_history_id": scan_history_id
        }


# Legacy task wrapper for backward compatibility
@app.task(name="report", queue="reporting_queue", base=RengineTask, bind=True)
def report(
    self,
    scan_history_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Legacy report task - now redirects to distributed system.
    
    This maintains backward compatibility while using the new distributed architecture.
    """
    logger.info("Legacy report task called - redirecting to distributed system")
    
    # Redirect to distributed task
    return generate_scan_report_distributed.delay(
        scan_history_id=scan_history_id,
        ctx=ctx,
        description=description,
        **kwargs
    ).get()


@app.task(name="generate_report", bind=False, queue="reporting_queue")
def generate_report(ctx=None, description=None):
    """
    Generate a comprehensive scan report.
    
    This task creates a detailed report of the scan results including
    subdomains, endpoints, vulnerabilities, and other findings.
    
    Args:
        ctx: Task context containing scan information
        description: Task description shown in UI
    
    Returns:
        Dict containing report generation results
    """
    if ctx is None:
        ctx = {}
    
    try:
        # Get scan information from context
        scan_id = ctx.get("scan_history_id")
        subscan_id = ctx.get("subscan_id")
        engine_id = ctx.get("engine_id")
        
        if not scan_id:
            raise ValueError("scan_history_id is required in context")
        
        # Import Django models lazily to avoid AppRegistryNotReady
        from startScan.models import ScanHistory, SubScan
        
        # Get scan object
        scan = ScanHistory.objects.filter(pk=scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found")
        
        # Get subscan if provided
        subscan = None
        if subscan_id:
            subscan = SubScan.objects.filter(pk=subscan_id).first()
        
        # Use the distributed report generation system
        result = generate_scan_report_distributed.delay(
            scan_history_id=scan_id,
            ctx=ctx,
            description=description or "Generate comprehensive report",
            subscan_id=subscan_id,
            engine_id=engine_id
        )
        
        # Wait for completion with timeout
        report_result = result.get(timeout=1800)  # 30 minute timeout
        
        logger.info(f"Report generated successfully for scan {scan_id}")
        return {
            "success": True,
            "scan_id": scan_id,
            "subscan_id": subscan_id,
            "report_path": report_result.get("report_path"),
            "report_size": report_result.get("report_size"),
            "sections": report_result.get("sections", [])
        }
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        return {
            "success": False,
            "error": str(e),
            "scan_id": ctx.get("scan_history_id"),
            "subscan_id": ctx.get("subscan_id")
        }


@app.task(name="generate_report_batch", queue="reporting_queue", base=RengineTask, bind=True)
def generate_report_batch(
    self,
    scan_history_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Process report generation in batches.
    
    This task handles report generation in smaller batches to improve
    performance and resource management.
    
    Args:
        scan_history_id: ID of the scan history
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments
    
    Returns:
        Dict containing batch processing results
    """
    logger.info("Starting report generation batch processing")
    
    try:
        # Use the distributed report generation system
        result = generate_scan_report_distributed.delay(
            scan_history_id=scan_history_id,
            ctx=ctx,
            description=description or "Report generation batch",
            **kwargs
        )
        
        # Wait for completion with timeout
        batch_result = result.get(timeout=1800)  # 30 minute timeout
        logger.info("Report generation batch processing completed")
        return batch_result
        
    except Exception as e:
        logger.error(f"Report generation batch processing failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "reports_generated": 0
        }


@app.task(name="generate_report_orchestrator", queue="orchestrator_queue", base=RengineTask, bind=True)
def generate_report_orchestrator(
    self,
    scan_history_id=None,
    ctx=None,
    description=None,
    **kwargs
):
    """
    Orchestrate report generation workflow.
    
    This task coordinates the report generation process across multiple workers
    and manages the overall workflow.
    
    Args:
        scan_history_id: ID of the scan history
        ctx: Task context
        description: Task description
        **kwargs: Additional arguments
    
    Returns:
        Dict containing orchestration results
    """
    logger.info("Starting report generation orchestration")
    
    try:
        # Use the distributed report generation system
        result = generate_scan_report_distributed.delay(
            scan_history_id=scan_history_id,
            ctx=ctx,
            description=description or "Report generation orchestration",
            **kwargs
        )
        
        # Wait for completion with timeout
        orchestration_result = result.get(timeout=3600)  # 1 hour timeout
        logger.info("Report generation orchestration completed")
        return orchestration_result
        
    except Exception as e:
        logger.error(f"Report generation orchestration failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "reports_generated": 0
        }
