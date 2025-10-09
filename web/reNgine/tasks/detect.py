"""
Detection tasks for WAF and CMS detection.

This module provides functionality for detecting Web Application Firewalls (WAF)
and Content Management Systems (CMS) using various security tools.
"""

import json
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.settings import RENGINE_TOOL_PATH
from reNgine.utilities.distributed import (
    get_distributed_utilities,
    DistributedCommandBuilder
)
from reNgine.utilities.core import (
    is_valid_url
)
from reNgine.utilities.url import get_subdomain_from_url
from reNgine.utilities.endpoint import ensure_endpoints_crawled_and_execute
from startScan.models import Subdomain, Waf

logger = get_task_logger(__name__)


class DetectionProcessor:
    """Detection processor using distributed utilities"""
    
    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
    
    def build_wafw00f_command(
        self,
        input_file: str,
        output_file: str,
        format_type: str = "json"
    ) -> str:
        """Build wafw00f command using distributed command builder"""
        command_builder = DistributedCommandBuilder("wafw00f")
        
        # Add input file
        command_builder.add_option("-i", input_file)
        
        # Add output file
        command_builder.add_option("-o", output_file)
        
        # Add format
        command_builder.add_option("-f", format_type)
        
        return command_builder.build()
    
    def build_cmseek_command(
        self,
        url: str,
        random_agent: bool = True,
        batch_mode: bool = True,
        follow_redirect: bool = True
    ) -> str:
        """Build cmseek command using distributed command builder"""
        command_builder = DistributedCommandBuilder("cmseek")
        
        # Add flags
        if random_agent:
            command_builder.add_flag("--random-agent")
        
        if batch_mode:
            command_builder.add_flag("--batch")
        
        if follow_redirect:
            command_builder.add_flag("--follow-redirect")
        
        # Add URL
        command_builder.add_option("-u", url)
        
        return command_builder.build()
    
    def execute_waf_detection(
        self,
        urls: List[str],
        input_file: str,
        output_file: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute WAF detection using distributed command processor"""
        try:
            # Write URLs to input file
            with open(input_file, 'w') as f:
                f.write('\n'.join(urls))
            
            # Build command
            command = self.build_wafw00f_command(input_file, output_file)
            
            # Execute command
            result = self.command_processor.execute_commands_batch(
                [command], "waf_detection", timeout=300, **kwargs
            )
            
            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "output_file": output_file,
                    "execution_time": result.processing_time
                }
            else:
                return {
                    "success": False,
                    "command": command,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time
                }
                
        except Exception as e:
            logger.error(f"WAF detection execution failed: {e}")
            return {
                "success": False,
                "command": command,
                "error": str(e),
                "execution_time": 0
            }
    
    def execute_cms_detection(
        self,
        url: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute CMS detection using distributed command processor"""
        try:
            # Build command
            command = self.build_cmseek_command(url)
            
            # Execute command
            result = self.command_processor.execute_commands_batch(
                [command], "cms_detection", timeout=600, **kwargs
            )
            
            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "url": url,
                    "execution_time": result.processing_time
                }
            else:
                return {
                    "success": False,
                    "command": command,
                    "url": url,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time
                }
                
        except Exception as e:
            logger.error(f"CMS detection execution failed: {e}")
            return {
                "success": False,
                "command": command,
                "url": url,
                "error": str(e),
                "execution_time": 0
            }


# Celery tasks

@app.task(name="waf_detection", queue="io_queue", base=RengineTask, bind=True)
def waf_detection(self, ctx={}, description=None):
    """
    Uses wafw00f to check for the presence of a WAF.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of startScan.models.Waf objects.
    """

    def _execute_waf_detection(ctx, description):
        input_path = str(Path(self.results_dir) / "input_endpoints_waf_detection.txt")

        # Get alive endpoints from DB
        urls = get_http_urls(is_alive=True, write_filepath=input_path, get_only_default_urls=True, ctx=ctx)
        if not urls:
            logger.error("No alive URLs found for WAF detection. Skipping.")
            return

        # Use distributed detection processor
        processor = DetectionProcessor()
        result = processor.execute_waf_detection(
            urls=urls,
            input_file=input_path,
            output_file=self.output_path
        )

        if not result["success"]:
            logger.error(f"WAF detection failed: {result.get('error', 'Unknown error')}")
            return

        if not os.path.isfile(self.output_path):
            logger.error(f"Could not find {self.output_path}")
            return

        with open(self.output_path) as file:
            wafs = json.load(file)

        for waf_data in wafs:
            if not waf_data.get("detected") or not waf_data.get("firewall"):
                continue

            # Add waf to db
            waf, _ = Waf.objects.get_or_create(name=waf_data["firewall"], manufacturer=waf_data.get("manufacturer", ""))

            # Add waf info to Subdomain in DB
            subdomain_name = get_subdomain_from_url(waf_data["url"])
            logger.info(f"Wafw00f Subdomain : {subdomain_name}")

            try:
                subdomain = Subdomain.objects.get(
                    name=subdomain_name,
                    scan_history=self.scan,
                )
                # Clear existing WAFs and set the new one
                subdomain.waf.clear()
                subdomain.waf.add(waf)
                subdomain.save()
            except Subdomain.DoesNotExist:
                logger.warning(f"Subdomain {subdomain_name} was not found in the db, skipping waf detection.")

        return wafs

    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_waf_detection, ctx, description)


@app.task(name="run_wafw00f", bind=False, queue="run_command_queue")
def run_wafw00f(url):
    """
    Run wafw00f for a single URL using distributed command processor.
    
    Args:
        url: URL to check for WAF
        
    Returns:
        WAF detection result
    """
    try:
        logger.info(f"Starting WAF detection for URL: {url}")
        
        # Use distributed detection processor
        processor = DetectionProcessor()
        
        # Build command
        command = f"wafw00f {url}"
        
        # Execute command
        result = processor.command_processor.execute_commands_batch(
            [command], "single_wafw00f", timeout=300
        )
        
        if result.is_successful:
            output = result.data.get("output", "")
            logger.info(f"Raw output from wafw00f: {output}")
            
            if match := re.search(r"behind (.+)", output):
                result_text = match[1]
                logger.info(f"WAF detected: {result_text}")
                return result_text
            else:
                logger.info("No WAF detected")
                return "No WAF detected"
        else:
            error = result.errors[0] if result.errors else "Unknown error"
            logger.error(f"WAF detection failed: {error}")
            return f"WAF detection failed: {error}"
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"Unexpected error: {str(e)}"


@app.task(name="run_cmseek", queue="run_command_queue")
def run_cmseek(url):
    """
    Run CMSeeK for a single URL using distributed command processor.
    
    Args:
        url: URL to check for CMS
        
    Returns:
        CMS detection result
    """
    try:
        logger.info(f"Starting CMS detection for URL: {url}")
        
        # Use distributed detection processor
        processor = DetectionProcessor()
        
        # Execute CMS detection
        result = processor.execute_cms_detection(url)
        
        if not result["success"]:
            logger.error(f"CMS detection failed: {result.get('error', 'Unknown error')}")
            return {"status": False, "message": result.get("error", "Unknown error")}
        
        # Parse CMSeeK output
        base_path = f"{RENGINE_TOOL_PATH}/.github/CMSeeK/Result"
        domain_name = urlparse(url).netloc
        json_path = os.path.join(base_path, domain_name, "cms.json")

        if os.path.isfile(json_path):
            with open(json_path, "r") as f:
                cms_data = json.load(f)

            if cms_data.get("cms_name"):
                # CMS detected
                result_data = {"status": True}
                result_data |= cms_data

            # Clean up CMSeeK results
            try:
                shutil.rmtree(os.path.dirname(json_path))
            except Exception as e:
                logger.error(f"Error cleaning up CMSeeK results: {e}")

            return result_data

        # CMS not detected
        return {"status": False, "message": "Could not detect CMS!"}

    except Exception as e:
        logger.error(f"Error running CMSeeK: {e}")
        return {"status": False, "message": str(e)}


# Utility functions for easy access

def detect_waf_distributed(
    urls: List[str],
    input_file: str,
    output_file: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Detect WAF using distributed processing.
    """
    processor = DetectionProcessor()
    return processor.execute_waf_detection(
        urls=urls,
        input_file=input_file,
        output_file=output_file,
        **kwargs
    )


def detect_cms_distributed(
    url: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Detect CMS using distributed processing.
    """
    processor = DetectionProcessor()
    return processor.execute_cms_detection(
        url=url,
        **kwargs
    )


def parse_wafw00f_output(output: str) -> Optional[str]:
    """
    Parse wafw00f output to extract WAF information.
    
    Args:
        output: Raw wafw00f output
        
    Returns:
        WAF name if detected, None otherwise
    """
    if match := re.search(r"behind (.+)", output):
        return match[1]
    return None


def parse_cmseek_output(json_path: str) -> Optional[Dict[str, Any]]:
    """
    Parse CMSeeK JSON output.
    
    Args:
        json_path: Path to CMSeeK JSON output file
        
    Returns:
        CMS data if found, None otherwise
    """
    try:
        if os.path.isfile(json_path):
            with open(json_path, "r") as f:
                cms_data = json.load(f)
            
            if cms_data.get("cms_name"):
                return cms_data
    except Exception as e:
        logger.error(f"Error parsing CMSeeK output: {e}")
    
    return None


def cleanup_detection_results(results_dir: str, patterns: List[str] = None) -> None:
    """
    Clean up detection result files.
    
    Args:
        results_dir: Directory containing results
        patterns: File patterns to clean up
    """
    if patterns is None:
        patterns = ["*.json", "*.txt", "*.log"]
    
    for pattern in patterns:
        try:
            import glob
            files = glob.glob(os.path.join(results_dir, pattern))
            for file in files:
                os.remove(file)
        except Exception as e:
            logger.error(f"Error cleaning up {pattern}: {e}")


def validate_detection_input(urls: List[str]) -> List[str]:
    """
    Validate URLs for detection tasks.
    
    Args:
        urls: List of URLs to validate
        
    Returns:
        List of valid URLs
    """
    valid_urls = []
    
    for url in urls:
        if is_valid_url(url):
            valid_urls.append(url)
        else:
            logger.warning(f"Invalid URL for detection: {url}")
    
    return valid_urls


def get_detection_statistics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics from detection results.
    
    Args:
        results: List of detection results
        
    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_checked": 0,
            "waf_detected": 0,
            "cms_detected": 0,
            "no_detection": 0
        }
    
    total_checked = len(results)
    waf_detected = sum(1 for r in results if r.get("waf_detected"))
    cms_detected = sum(1 for r in results if r.get("cms_detected"))
    no_detection = total_checked - waf_detected - cms_detected
    
    return {
        "total_checked": total_checked,
        "waf_detected": waf_detected,
        "cms_detected": cms_detected,
        "no_detection": no_detection,
        "waf_percentage": (waf_detected / total_checked * 100) if total_checked > 0 else 0,
        "cms_percentage": (cms_detected / total_checked * 100) if total_checked > 0 else 0
    }
