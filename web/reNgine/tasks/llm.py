"""
LLM tasks for vulnerability report generation.

This module provides functionality for generating vulnerability reports
using Large Language Models (LLM) and converting markdown to HTML.
"""

from typing import Optional, Tuple, Dict, Any, List

from urllib.parse import urlparse

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.llm.llm import LLMVulnerabilityReportGenerator
from reNgine.llm.utils import (
    convert_markdown_to_html,
    get_llm_vuln_input_description,
    is_empty_llm_report,
    is_empty_text,
)
from reNgine.utilities.distributed.utilities import (
    get_distributed_utilities,
    ProcessorType,
    create_balanced_config
)
from reNgine.utilities.core.data import (
    is_iterable,
    chunk_list,
    remove_duplicates
)
from reNgine.utilities.core.validation import (
    is_valid_url
)
from reNgine.utilities.core.formatting import (
    format_duration,
    format_bytes
)
from reNgine.utilities.core.network import (
    parse_url,
    extract_path_from_url
)
from startScan.models import LLMVulnerabilityReport, Vulnerability


logger = get_task_logger(__name__)


class LLMProcessor:
    """LLM processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.vulnerability_processor = self.distributed_utils.get_vulnerability_processor()
    
    def generate_vulnerability_report(
        self,
        vulnerability_id: Optional[int] = None,
        vuln_tuple: Optional[Tuple[str, str]] = None,
        force_regenerate: bool = False
    ) -> Dict[str, Any]:
        """Generate vulnerability report using LLM"""
        try:
            # Get title, path and full_url from either vulnerability_id or vuln_tuple
            if vulnerability_id:
                lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
                lookup_url = urlparse(lookup_vulnerability.http_url)
                title = lookup_vulnerability.name
                path = lookup_url.path
                full_url = lookup_vulnerability.http_url
            elif vuln_tuple:
                title, provided = vuln_tuple
                # If provided looks like a full URL, use as full_url and derive path; else treat as path
                try:
                    parsed = urlparse(provided)
                    if parsed.scheme in ("http", "https") and parsed.netloc:
                        full_url = provided
                        path = parsed.path or "/"
                        logger.debug("vuln_tuple second element treated as full URL: %s", full_url)
                    else:
                        # Treat as path-only; normalize to start with '/'
                        normalized_path = provided if str(provided).startswith("/") else f"/{provided}"
                        path = normalized_path
                        # No domain context available; use the provided value for LLM context as-is
                        full_url = provided
                        logger.debug("vuln_tuple second element treated as path: %s", path)
                except Exception:
                    # Fallback to treating the provided value as path-like
                    normalized_path = provided if str(provided).startswith("/") else f"/{provided}"
                    path = normalized_path
                    full_url = provided
                    logger.debug("vuln_tuple parsing failed; treated as path: %s", path)
            else:
                raise ValueError("Either vulnerability_id or vuln_tuple must be provided")

            logger.info(f"Processing vulnerability: {title}, PATH: {path}")

            stored = LLMVulnerabilityReport.objects.filter(url_path=path, title=title).first()

            should_use_cached = stored and not is_empty_llm_report(stored) and not force_regenerate
            if should_use_cached:
                # Try to extract model name from raw stored description tag [LLM:model]
                model_from_tag = None
                stripped_desc = stored.description or ""
                try:
                    if stripped_desc.startswith("[LLM:") and "]" in stripped_desc:
                        end_idx = stripped_desc.index("]")
                        model_from_tag = stripped_desc[5:end_idx]
                        stripped_desc = stripped_desc[end_idx + 1 :].strip()
                except (ValueError, IndexError):
                    # Malformed tag; ignore and continue without model_from_tag
                    model_from_tag = None

                response = {
                    "status": True,
                    "llm_model": model_from_tag,
                    "id": vulnerability_id,
                    # pass raw (stripped) text so we can run unified conversion below
                    "description": stripped_desc,
                    "impact": stored.impact or "",
                    "remediation": stored.remediation or "",
                    "references": stored.references or "",
                }
                logger.info(f"Found stored report: {stored}")
            else:
                # Generate or regenerate report when not found or empty
                # Pass full URL to LLM input for accurate context
                vulnerability_description = get_llm_vuln_input_description(title, full_url)
                llm_generator = LLMVulnerabilityReportGenerator()
                response = llm_generator.get_vulnerability_report(vulnerability_description)

                # Only persist non-empty successful responses
                raw_description = response.get("description")
                raw_impact = response.get("impact")
                raw_remediation = response.get("remediation")
                raw_references = response.get("references")

                # Normalize list-like empty references
                if is_empty_text(raw_references):
                    raw_references = ""

                has_content = any(
                    not is_empty_text(v) for v in [raw_description, raw_impact, raw_remediation, raw_references]
                )

                if response.get("status") and has_content:
                    # Update existing empty record
                    # Save with model tag for consistent display and future cache
                    tagged_desc = (
                        f"[LLM:{llm_generator.model_name}]\n{raw_description}"
                        if llm_generator and llm_generator.model_name
                        else raw_description
                    )
                    if stored:
                        stored.description = tagged_desc
                        stored.impact = raw_impact
                        stored.remediation = raw_remediation
                        stored.references = raw_references
                        stored.save()
                        logger.info("Updated existing empty LLM report in database")
                    else:
                        llm_report = LLMVulnerabilityReport(
                            url_path=path,
                            title=title,
                            description=tagged_desc,
                            impact=raw_impact,
                            remediation=raw_remediation,
                            references=raw_references,
                        )
                        llm_report.save()
                        logger.info("Added new report to database")
                    response["llm_model"] = (
                        llm_generator.model_name if llm_generator and hasattr(llm_generator, "model_name") else None
                    )
                    response["id"] = vulnerability_id
                else:
                    logger.warning("LLM report generation returned empty content; skipping DB save")
                    # Ensure response reports failure to trigger UI fallback instead of showing empty fields
                    response = {
                        "status": False,
                        "error": "LLM returned empty response. Please try again or choose a different model.",
                    }

            # Update all matching vulnerabilities
            vulnerabilities = Vulnerability.objects.filter(name=title, http_url__icontains=path)

            for vuln in vulnerabilities:
                # Update vulnerability fields only when present
                if isinstance(response.get("description"), str) and not is_empty_text(response.get("description")):
                    vuln.description = response.get("description")
                if isinstance(response.get("impact"), str) and not is_empty_text(response.get("impact")):
                    vuln.impact = response.get("impact")
                if isinstance(response.get("remediation"), str) and not is_empty_text(response.get("remediation")):
                    vuln.remediation = response.get("remediation")
                if isinstance(response.get("references"), str) and not is_empty_text(response.get("references")):
                    vuln.references = response.get("references")
                vuln.is_llm_used = True

                vuln.save()
                logger.info(f"Updated vulnerability {vuln.id} with LLM report")

            if response.get("status"):
                # Normalize list-like empty references again for rendering
                if is_empty_text(response.get("references")):
                    response["references"] = ""
                # Strip leading [LLM:...] tag from description for UI placement under the title
                if (
                    isinstance(response.get("description"), str)
                    and response["description"].startswith("[LLM:")
                    and "]" in response["description"]
                ):
                    response["description"] = response["description"][response["description"].index("]") + 1 :].strip()
                response["description"] = convert_markdown_to_html(response.get("description", ""))
                response["impact"] = convert_markdown_to_html(response.get("impact", ""))
                response["remediation"] = convert_markdown_to_html(response.get("remediation", ""))
                response["references"] = convert_markdown_to_html(response.get("references", ""))

            return response

        except Exception as e:
            error_msg = f"Error in get_vulnerability_report: {str(e)}"
            logger.error(error_msg)
            return {"status": False, "error": error_msg}
    
    def generate_batch_vulnerability_reports(
        self,
        vulnerability_ids: List[int],
        force_regenerate: bool = False
    ) -> Dict[str, Any]:
        """Generate vulnerability reports for multiple vulnerabilities"""
        try:
            results = []
            successful = 0
            failed = 0
            
            for vuln_id in vulnerability_ids:
                try:
                    result = self.generate_vulnerability_report(
                        vulnerability_id=vuln_id,
                        force_regenerate=force_regenerate
                    )
                    
                    if result.get("status"):
                        successful += 1
                    else:
                        failed += 1
                    
                    results.append({
                        "vulnerability_id": vuln_id,
                        "result": result
                    })
                    
                except Exception as e:
                    logger.error(f"Failed to generate report for vulnerability {vuln_id}: {e}")
                    failed += 1
                    results.append({
                        "vulnerability_id": vuln_id,
                        "result": {"status": False, "error": str(e)}
                    })
            
            return {
                "success": True,
                "total_vulnerabilities": len(vulnerability_ids),
                "successful_reports": successful,
                "failed_reports": failed,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Batch vulnerability report generation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_vulnerabilities": len(vulnerability_ids)
            }
    
    def convert_markdown_to_html_distributed(
        self,
        markdown_text: str
    ) -> str:
        """Convert markdown to HTML using distributed utilities"""
        try:
            if not markdown_text or is_empty_text(markdown_text):
                return ""
            
            return convert_markdown_to_html(markdown_text)
            
        except Exception as e:
            logger.error(f"Markdown to HTML conversion failed: {e}")
            return markdown_text  # Return original text if conversion fails


# Celery tasks

@app.task(name="llm_vulnerability_report", bind=False, queue="cpu_queue")
def llm_vulnerability_report(
    vulnerability_id: Optional[int] = None,
    vuln_tuple: Optional[Tuple[str, str]] = None,
    force_regenerate: bool = False,
):
    """
    Generate and store Vulnerability Report using LLM.
    Can be called either with a vulnerability_id or a vuln_tuple (title, url_or_path).

    Args:
        vulnerability_id (int, optional): Vulnerability ID to fetch Description
        vuln_tuple (tuple[str, str], optional):
            Contract: (title, url_or_path)
            - url_or_path may be:
              - A full URL (e.g. "https://example.com/login"): will be used as-is for LLM context,
                and its path component will be extracted for DB matching.
              - A URL path only (e.g. "/login" or "login"): will be treated as the path used for
                DB matching. For the LLM context, it will be passed through as provided; for best
                results, pass a full URL when available.

    Returns:
        dict: LLM response containing description, impact, remediation and references
    """
    logger.info("Getting LLM Vulnerability Description")
    
    # Use distributed LLM processor
    processor = LLMProcessor()
    
    return processor.generate_vulnerability_report(
        vulnerability_id=vulnerability_id,
        vuln_tuple=vuln_tuple,
        force_regenerate=force_regenerate
    )


@app.task(name="llm_vulnerability_report_batch", bind=False, queue="cpu_queue")
def llm_vulnerability_report_batch(
    vulnerability_ids: List[int],
    force_regenerate: bool = False
):
    """
    Generate vulnerability reports for multiple vulnerabilities using LLM.

    Args:
        vulnerability_ids (list): List of vulnerability IDs
        force_regenerate (bool): Whether to force regenerate existing reports

    Returns:
        dict: Batch generation results
    """
    logger.info(f"Generating LLM vulnerability reports for {len(vulnerability_ids)} vulnerabilities")
    
    # Use distributed LLM processor
    processor = LLMProcessor()
    
    return processor.generate_batch_vulnerability_reports(
        vulnerability_ids=vulnerability_ids,
        force_regenerate=force_regenerate
    )


# Utility functions for easy access

def generate_vulnerability_report_distributed(
    vulnerability_id: Optional[int] = None,
    vuln_tuple: Optional[Tuple[str, str]] = None,
    force_regenerate: bool = False
) -> Dict[str, Any]:
    """
    Generate vulnerability report using distributed processing.
    """
    processor = LLMProcessor()
    return processor.generate_vulnerability_report(
        vulnerability_id=vulnerability_id,
        vuln_tuple=vuln_tuple,
        force_regenerate=force_regenerate
    )


def generate_batch_vulnerability_reports_distributed(
    vulnerability_ids: List[int],
    force_regenerate: bool = False
) -> Dict[str, Any]:
    """
    Generate batch vulnerability reports using distributed processing.
    """
    processor = LLMProcessor()
    return processor.generate_batch_vulnerability_reports(
        vulnerability_ids=vulnerability_ids,
        force_regenerate=force_regenerate
    )


def convert_markdown_to_html_distributed(
    markdown_text: str
) -> str:
    """
    Convert markdown to HTML using distributed processing.
    """
    processor = LLMProcessor()
    return processor.convert_markdown_to_html_distributed(markdown_text)


def validate_llm_input(
    vulnerability_id: Optional[int] = None,
    vuln_tuple: Optional[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Validate LLM input parameters.
    
    Args:
        vulnerability_id: Vulnerability ID
        vuln_tuple: Vulnerability tuple (title, url_or_path)
        
    Returns:
        Validation result
    """
    validation_result = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    if not vulnerability_id and not vuln_tuple:
        validation_result["valid"] = False
        validation_result["errors"].append("Either vulnerability_id or vuln_tuple must be provided")
        return validation_result
    
    if vulnerability_id and vuln_tuple:
        validation_result["warnings"].append("Both vulnerability_id and vuln_tuple provided, using vulnerability_id")
    
    if vulnerability_id:
        try:
            vulnerability = Vulnerability.objects.get(id=vulnerability_id)
            if not vulnerability.name:
                validation_result["warnings"].append("Vulnerability has no name")
            if not vulnerability.http_url:
                validation_result["warnings"].append("Vulnerability has no URL")
        except Vulnerability.DoesNotExist:
            validation_result["valid"] = False
            validation_result["errors"].append(f"Vulnerability with ID {vulnerability_id} not found")
    
    if vuln_tuple:
        if not isinstance(vuln_tuple, (list, tuple)) or len(vuln_tuple) != 2:
            validation_result["valid"] = False
            validation_result["errors"].append("vuln_tuple must be a tuple/list with exactly 2 elements")
        else:
            title, url_or_path = vuln_tuple
            if not title or not isinstance(title, str):
                validation_result["valid"] = False
                validation_result["errors"].append("vuln_tuple title must be a non-empty string")
            
            if not url_or_path or not isinstance(url_or_path, str):
                validation_result["valid"] = False
                validation_result["errors"].append("vuln_tuple url_or_path must be a non-empty string")
    
    return validation_result


def get_llm_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from LLM generation results.
    
    Args:
        results: LLM generation results
        
    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_processed": 0,
            "successful_generations": 0,
            "failed_generations": 0,
            "cached_reports": 0,
            "success_rate": 0
        }
    
    if "results" in results:  # Batch results
        total_processed = results.get("total_vulnerabilities", 0)
        successful = results.get("successful_reports", 0)
        failed = results.get("failed_reports", 0)
        cached = 0  # Count cached reports from individual results
        
        for result in results.get("results", []):
            if result.get("result", {}).get("status") and "Found stored report" in str(result.get("result", {})):
                cached += 1
        
        success_rate = (successful / total_processed * 100) if total_processed > 0 else 0
        
        return {
            "total_processed": total_processed,
            "successful_generations": successful,
            "failed_generations": failed,
            "cached_reports": cached,
            "success_rate": success_rate
        }
    else:  # Single result
        return {
            "total_processed": 1,
            "successful_generations": 1 if results.get("status") else 0,
            "failed_generations": 0 if results.get("status") else 1,
            "cached_reports": 1 if "Found stored report" in str(results) else 0,
            "success_rate": 100 if results.get("status") else 0
        }


def filter_llm_results(
    results: Dict[str, Any],
    status_filter: Optional[str] = None,
    model_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Filter LLM results based on criteria.
    
    Args:
        results: LLM results
        status_filter: Filter by status ("success", "failed", "cached")
        model_filter: Filter by LLM model name
        
    Returns:
        Filtered results
    """
    if "results" not in results:  # Single result
        return results
    
    filtered_results = results.copy()
    filtered_results["results"] = []
    
    for result in results.get("results", []):
        result_data = result.get("result", {})
        
        # Filter by status
        if status_filter:
            if status_filter == "success" and not result_data.get("status"):
                continue
            if status_filter == "failed" and result_data.get("status"):
                continue
            if status_filter == "cached" and "Found stored report" not in str(result_data):
                continue
        
        # Filter by model
        if model_filter and result_data.get("llm_model") != model_filter:
            continue
        
        filtered_results["results"].append(result)
    
    # Update counts
    filtered_results["total_vulnerabilities"] = len(filtered_results["results"])
    filtered_results["successful_reports"] = sum(
        1 for r in filtered_results["results"] 
        if r.get("result", {}).get("status")
    )
    filtered_results["failed_reports"] = (
        filtered_results["total_vulnerabilities"] - filtered_results["successful_reports"]
    )
    
    return filtered_results
