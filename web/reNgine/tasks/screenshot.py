"""
Screenshot tasks for web page screenshots.

This module provides functionality for taking screenshots of web pages
using tools like EyeWitness for visual reconnaissance.
"""

import csv
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    DEFAULT_SCAN_INTENSITY,
    INTENSITY,
    SCREENSHOT,
    THREADS,
    TIMEOUT,
)
from reNgine.settings import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_THREADS,
    RENGINE_RESULTS,
)
from reNgine.tasks.notification import send_file_to_discord
from reNgine.utilities.core import extract_columns, remove_file_or_pattern
from reNgine.utilities.core.validation import is_valid_url
from reNgine.utilities.distributed.command import DistributedCommandBuilder
from reNgine.utilities.distributed.utilities import get_distributed_utilities
from reNgine.utilities.endpoint import ensure_endpoints_crawled_and_execute
from reNgine.utilities.notification import get_output_file_name
from reNgine.utilities.url import get_http_urls
from scanEngine.models import Notification
from startScan.models import EndPoint


logger = get_task_logger(__name__)


class ScreenshotProcessor:
    """Screenshot processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()

    def build_eyewitness_command(
        self, input_file: str, output_dir: str, timeout: int = 10, threads: int = 10, no_prompt: bool = True
    ) -> str:
        """Build EyeWitness command using distributed command builder"""
        command_builder = DistributedCommandBuilder("EyeWitness")

        # Add input file
        command_builder.add_option("-f", input_file)

        # Add output directory
        command_builder.add_option("-d", output_dir)

        # Add timeout
        if timeout > 0:
            command_builder.add_option("--timeout", timeout)

        # Add threads
        if threads > 0:
            command_builder.add_option("--threads", threads)

        # Add no-prompt flag
        if no_prompt:
            command_builder.add_flag("--no-prompt")

        return command_builder.build()

    def execute_eyewitness_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute EyeWitness command using distributed command processor"""
        try:
            result = self.command_processor.execute_commands_batch(
                [command], "eyewitness_screenshot", timeout=1800, **kwargs
            )

            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "output": result.data.get("output", ""),
                    "execution_time": result.processing_time,
                }
            else:
                return {
                    "success": False,
                    "command": command,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time,
                }

        except Exception as e:
            logger.error(f"EyeWitness command execution failed: {e}")
            return {"success": False, "command": command, "error": str(e), "execution_time": 0}

    def process_eyewitness_results(self, output_file: str, scan_history=None) -> List[Dict[str, Any]]:
        """Process EyeWitness results and update endpoints"""
        screenshot_paths = []

        try:
            if not os.path.isfile(output_file):
                logger.error(f"Could not find EyeWitness results file: {output_file}")
                return screenshot_paths

            with open(output_file, "r") as file:
                reader = csv.reader(file)
                header = next(reader)  # Skip header row
                indices = [
                    header.index(col)
                    for col in ["Protocol", "Port", "Domain", "Request Status", "Screenshot Path", " Source Path"]
                ]

                for row in reader:
                    try:
                        protocol, port, subdomain_name, status, screenshot_path, source_path = extract_columns(
                            row, indices
                        )

                        if status == "Successful":
                            screenshot_paths.append(screenshot_path)

                            # Construct the full URL from protocol, subdomain and port
                            if port and port not in ["80", "443"]:
                                full_url = f"{protocol}://{subdomain_name}:{port}"
                            else:
                                full_url = f"{protocol}://{subdomain_name}"

                            # Find the matching endpoint
                            endpoint_query = EndPoint.objects.filter(http_url=full_url)
                            if scan_history:
                                endpoint_query = endpoint_query.filter(scan_history=scan_history)

                            if endpoint_query.exists():
                                endpoint = endpoint_query.first()
                                endpoint.screenshot_path = screenshot_path.replace(RENGINE_RESULTS, "")
                                endpoint.save()
                                logger.warning(f"Added screenshot for {full_url} to endpoint in DB")
                            else:
                                logger.warning(f"No endpoint found for {full_url}, skipping screenshot assignment")

                    except Exception as e:
                        logger.error(f"Error processing EyeWitness result row: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error processing EyeWitness results: {e}")

        return screenshot_paths

    def cleanup_screenshot_files(self, screenshots_path: str, **kwargs) -> Dict[str, Any]:
        """Clean up screenshot result files"""
        try:
            # Remove all db, html extra files in screenshot results
            patterns = ["*.csv", "*.db", "*.js", "*.html", "*.css"]
            cleanup_results = []

            for pattern in patterns:
                try:
                    remove_file_or_pattern(screenshots_path, pattern=pattern, **kwargs)
                    cleanup_results.append(f"Cleaned up {pattern}")
                except Exception as e:
                    logger.error(f"Error cleaning up {pattern}: {e}")
                    cleanup_results.append(f"Failed to clean up {pattern}: {e}")

            # Delete source folder
            try:
                remove_file_or_pattern(str(Path(screenshots_path) / "source"), **kwargs)
                cleanup_results.append("Cleaned up source folder")
            except Exception as e:
                logger.error(f"Error cleaning up source folder: {e}")
                cleanup_results.append(f"Failed to clean up source folder: {e}")

            return {"success": True, "cleanup_results": cleanup_results}

        except Exception as e:
            logger.error(f"Screenshot cleanup failed: {e}")
            return {"success": False, "error": str(e)}


# Celery tasks


@app.task(name="screenshot", queue="io_queue", base=RengineTask, bind=True)
def screenshot(self, ctx={}, description=None):
    """Uses EyeWitness to gather screenshot of a domain and/or url.

    Args:
        description (str, optional): Task description shown in UI.
    """

    # Use the smart crawl-then-execute pattern
    def _execute_screenshot(ctx, description):
        # Config
        screenshots_path = str(Path(self.results_dir) / "screenshots")
        output_path = str(Path(self.results_dir) / "screenshots" / self.filename)
        alive_endpoints_file = str(Path(self.results_dir) / "endpoints_alive.txt")
        config = self.yaml_configuration.get(SCREENSHOT) or {}
        intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
        timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
        threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

        # If intensity is normal, grab only the root endpoints of each subdomain
        strict = intensity == "normal"

        # Get URLs to take screenshot of
        urls = get_http_urls(
            is_alive=True, strict=strict, write_filepath=alive_endpoints_file, get_only_default_urls=True, ctx=ctx
        )
        if not urls:
            logger.error("No alive URLs found for screenshot. Skipping.")
            return

        # Send start notif
        notification = Notification.objects.first()
        send_output_file = notification.send_scan_output_file if notification else False

        # Use distributed screenshot processor
        processor = ScreenshotProcessor()

        # Build EyeWitness command
        command = processor.build_eyewitness_command(
            input_file=alive_endpoints_file, output_dir=screenshots_path, timeout=timeout, threads=threads
        )

        # Execute EyeWitness command
        result = processor.execute_eyewitness_command(
            command, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id
        )

        if not result["success"]:
            logger.error(f"EyeWitness command failed: {result.get('error', 'Unknown error')}")
            return

        if not os.path.isfile(output_path):
            logger.error(f"Could not load EyeWitness results at {output_path} for {self.domain.name}.")
            return

        # Process EyeWitness results
        screenshot_paths = processor.process_eyewitness_results(output_path, self.scan)

        # Clean up screenshot files
        cleanup_result = processor.cleanup_screenshot_files(
            screenshots_path, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id
        )

        if not cleanup_result["success"]:
            logger.warning(f"Screenshot cleanup had issues: {cleanup_result.get('error', 'Unknown error')}")

        # Send finish notifs
        screenshots_str = "• " + "\n• ".join([f"`{path}`" for path in screenshot_paths])
        self.notify(fields={"Screenshots": screenshots_str})
        if send_output_file:
            for path in screenshot_paths:
                title = get_output_file_name(self.scan_id, self.subscan_id, self.filename)
                send_file_to_discord.delay(path, title)

        return screenshot_paths

    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_screenshot, ctx, description)


# Utility functions for easy access


def take_screenshots_distributed(
    urls: List[str], output_dir: str, timeout: int = 10, threads: int = 10, **kwargs
) -> Dict[str, Any]:
    """
    Take screenshots using distributed processing.
    """
    processor = ScreenshotProcessor()

    # Write URLs to input file
    input_file = str(Path(output_dir) / "input_urls.txt")
    with open(input_file, "w") as f:
        f.write("\n".join(urls))

    # Build command
    command = processor.build_eyewitness_command(
        input_file=input_file, output_dir=output_dir, timeout=timeout, threads=threads
    )

    # Execute command
    result = processor.execute_eyewitness_command(command, **kwargs)

    if result["success"]:
        # Process results
        output_file = str(Path(output_dir) / "screenshots.csv")
        screenshot_paths = processor.process_eyewitness_results(output_file)

        return {
            "success": True,
            "command": command,
            "screenshot_paths": screenshot_paths,
            "execution_time": result["execution_time"],
        }
    else:
        return {
            "success": False,
            "command": command,
            "error": result.get("error", "Unknown error"),
            "execution_time": result["execution_time"],
        }


def build_eyewitness_command_distributed(input_file: str, output_dir: str, **kwargs) -> str:
    """
    Build EyeWitness command using distributed command builder.
    """
    processor = ScreenshotProcessor()
    return processor.build_eyewitness_command(input_file=input_file, output_dir=output_dir, **kwargs)


def validate_screenshot_input(urls: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Validate screenshot input parameters.

    Args:
        urls: List of URLs to screenshot
        output_dir: Output directory for screenshots

    Returns:
        Validation result
    """
    validation_result = {"valid": True, "errors": [], "warnings": []}

    # Validate URLs
    if not urls:
        validation_result["valid"] = False
        validation_result["errors"].append("No URLs provided")
    else:
        valid_urls = []
        for url in urls:
            if is_valid_url(url):
                valid_urls.append(url)
            else:
                validation_result["warnings"].append(f"Invalid URL: {url}")

        if not valid_urls:
            validation_result["valid"] = False
            validation_result["errors"].append("No valid URLs found")

    # Validate output directory
    if not output_dir:
        validation_result["valid"] = False
        validation_result["errors"].append("No output directory provided")
    else:
        output_path = Path(output_dir)
        if not output_path.exists():
            try:
                output_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                validation_result["valid"] = False
                validation_result["errors"].append(f"Cannot create output directory: {e}")
        elif not output_path.is_dir():
            validation_result["valid"] = False
            validation_result["errors"].append("Output path exists but is not a directory")

    return validation_result


def get_screenshot_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from screenshot results.

    Args:
        results: Screenshot results

    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_urls": 0,
            "successful_screenshots": 0,
            "failed_screenshots": 0,
            "success_rate": 0,
            "execution_time": 0,
        }

    screenshot_paths = results.get("screenshot_paths", [])
    total_urls = len(screenshot_paths) + len(results.get("failed_screenshots", []))
    successful_screenshots = len(screenshot_paths)
    failed_screenshots = total_urls - successful_screenshots
    execution_time = results.get("execution_time", 0)

    success_rate = (successful_screenshots / total_urls * 100) if total_urls > 0 else 0

    return {
        "total_urls": total_urls,
        "successful_screenshots": successful_screenshots,
        "failed_screenshots": failed_screenshots,
        "success_rate": success_rate,
        "execution_time": execution_time,
    }


def cleanup_screenshot_results(output_dir: str, **kwargs) -> Dict[str, Any]:
    """
    Clean up screenshot result files.
    """
    processor = ScreenshotProcessor()
    return processor.cleanup_screenshot_files(output_dir, **kwargs)


def filter_screenshot_results(results: Dict[str, Any], status_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Filter screenshot results based on criteria.

    Args:
        results: Screenshot results
        status_filter: Filter by status ("success", "failed")

    Returns:
        Filtered results
    """
    if not results or "screenshot_paths" not in results:
        return results

    filtered_results = results.copy()

    if status_filter == "success":
        # Only return successful screenshots
        filtered_results["screenshot_paths"] = results.get("screenshot_paths", [])
    elif status_filter == "failed":
        # Only return failed screenshots (would need to track these separately)
        filtered_results["screenshot_paths"] = []
        filtered_results["failed_screenshots"] = results.get("failed_screenshots", [])

    return filtered_results
