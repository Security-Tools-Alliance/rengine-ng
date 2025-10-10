"""
Fuzzing tasks for directory and file discovery.

This module provides functionality for directory and file fuzzing
using tools like FFUF to discover hidden content.
"""

import base64
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    AUTO_CALIBRATION,
    CUSTOM_HEADER,
    DEFAULT_DIR_FILE_FUZZ_EXTENSIONS,
    DIR_FILE_FUZZ,
    EXTENSIONS,
    FFUF_DEFAULT_FOLLOW_REDIRECT,
    FFUF_DEFAULT_MATCH_HTTP_STATUS,
    FFUF_DEFAULT_RECURSIVE_LEVEL,
    FFUF_DEFAULT_WORDLIST_NAME,
    FFUF_DEFAULT_WORDLIST_PATH,
    FOLLOW_REDIRECT,
    MATCH_HTTP_STATUS,
    MAX_TIME,
    RATE_LIMIT,
    RECURSIVE_LEVEL,
    STOP_ON_ERROR,
    THREADS,
    TIMEOUT,
    WORDLIST,
)
from reNgine.settings import (
    CELERY_DEBUG,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_THREADS,
)
from reNgine.utilities.command import generate_header_param
from reNgine.utilities.core.network import extract_path_from_url
from reNgine.utilities.core.validation import is_valid_url
from reNgine.utilities.database import save_endpoint, save_fuzzing_file
from reNgine.utilities.distributed.command import DistributedCommandBuilder
from reNgine.utilities.distributed.utilities import get_distributed_utilities
from reNgine.utilities.endpoint import ensure_endpoints_crawled_and_execute
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.url import get_http_urls, get_subdomain_from_url
from startScan.models import DirectoryScan, Subdomain


logger = get_task_logger(__name__)


class FuzzingProcessor:
    """Fuzzing processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()

    def build_ffuf_command(
        self,
        wordlist_path: str,
        target_url: str,
        extensions: List[str] = None,
        threads: int = 10,
        timeout: int = 10,
        rate_limit: int = 0,
        max_time: int = 0,
        recursive_level: int = 0,
        match_http_status: List[int] = None,
        follow_redirect: bool = True,
        auto_calibration: bool = True,
        stop_on_error: bool = False,
        custom_header: str = None,
        proxy: str = None,
    ) -> str:
        """Build ffuf command using distributed command builder"""
        if extensions is None:
            extensions = DEFAULT_DIR_FILE_FUZZ_EXTENSIONS

        if match_http_status is None:
            match_http_status = FFUF_DEFAULT_MATCH_HTTP_STATUS

        command_builder = DistributedCommandBuilder("ffuf")

        # Add wordlist
        command_builder.add_option("-w", wordlist_path)

        # Add extensions
        if extensions:
            extensions_str = ",".join([ext if ext.startswith(".") else f".{ext}" for ext in extensions])
            command_builder.add_option("-e", extensions_str)

        # Add threads
        if threads and threads > 0:
            command_builder.add_option("-t", threads)

        # Add timeout
        if timeout and timeout > 0:
            command_builder.add_option("-timeout", timeout)

        # Add rate limit (delay)
        if rate_limit > 0:
            delay = rate_limit / (threads * 100)  # calculate request pause delay from rate_limit and number of threads
            if delay > 0:
                command_builder.add_option("-p", delay)

        # Add max time
        if max_time > 0:
            command_builder.add_option("-maxtime", max_time)

        # Add recursion
        if recursive_level > 0:
            command_builder.add_flag("-recursion")
            command_builder.add_option("-recursion-depth", recursive_level)

        # Add match HTTP status
        if match_http_status:
            mc = ",".join([str(c) for c in match_http_status])
            command_builder.add_option("-mc", mc)

        # Add flags
        if not follow_redirect:
            command_builder.add_flag("-fr")

        if auto_calibration:
            command_builder.add_flag("-ac")

        if stop_on_error:
            command_builder.add_flag("-se")

        # Add custom header
        if custom_header:
            command_builder.add_argument(custom_header)

        # Add proxy
        if proxy:
            command_builder.add_option("-x", proxy)

        # Add target URL
        command_builder.add_option("-u", target_url)

        # Add output format
        command_builder.add_flag("-s")
        command_builder.add_flag("-json")

        return command_builder.build()

    def execute_ffuf_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute ffuf command using distributed command processor"""
        try:
            result = self.command_processor.execute_commands_batch([command], "ffuf_fuzzing", timeout=600, **kwargs)

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
            logger.error(f"FFUF command execution failed: {e}")
            return {"success": False, "command": command, "error": str(e), "execution_time": 0}

    def stream_ffuf_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Stream ffuf command output using distributed command processor"""
        try:
            result = self.command_processor.execute_commands_batch(
                [command], "ffuf_streaming", timeout=600, stream=True, **kwargs
            )

            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "stream_output": result.data.get("stream_output", ""),
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
            logger.error(f"FFUF streaming failed: {e}")
            return {"success": False, "command": command, "error": str(e), "execution_time": 0}

    def process_ffuf_results(
        self, results: List[Dict[str, Any]], ctx: Dict[str, Any], scan_history=None, subscan=None
    ) -> List[Dict[str, Any]]:
        """Process FFUF results and save to database using distributed database processor"""
        processed_results = []

        for line in results:
            if not isinstance(line, dict):
                continue

            try:
                # Extract FFUF output data
                url = line.get("url", "")
                length = line.get("length", 0)
                status = line.get("status", 0)
                words = line.get("words", 0)
                lines = line.get("lines", 0)
                content_type = line.get("content-type", "")
                duration = line.get("duration", 0)

                # Extract path and convert to base64
                name = base64.b64encode(extract_path_from_url(url).encode()).decode()

                if not name:
                    logger.error(f'FUZZ not found for "{url}"')
                    continue

                # Get or create endpoint from URL
                endpoint, created = save_endpoint(url, ctx=ctx)

                if endpoint is None:
                    continue

                # Update endpoint data from FFUF output
                endpoint.http_status = status
                endpoint.content_length = length
                endpoint.response_time = duration / 1000000000
                endpoint.content_type = content_type
                endpoint.save()

                # Save directory file output from FFUF
                try:
                    dfile, created = save_fuzzing_file(
                        name=name,
                        url=url,
                        http_status=status,
                        length=length,
                        words=words,
                        lines=lines,
                        content_type=content_type,
                    )
                except Exception as e:
                    logger.error(f"Failed to save DirectoryFile for {url}: {e}")
                    continue

                # Log newly created file or directory if debug activated
                if created and CELERY_DEBUG:
                    logger.warning(f"Found new directory or file {url}")

                processed_results.append(
                    {
                        "url": url,
                        "status": status,
                        "length": length,
                        "words": words,
                        "lines": lines,
                        "content_type": content_type,
                        "duration": duration,
                        "created": created,
                    }
                )

            except Exception as e:
                logger.error(f"Error processing FFUF result: {e}")
                continue

        return processed_results


# Celery tasks


@app.task(name="dir_file_fuzz", queue="io_queue", base=RengineTask, bind=True)
def dir_file_fuzz(self, ctx=None, description=None):
    """Perform directory scan, and currently uses `ffuf` as a default tool.

    Args:
        ctx (dict, optional): Context dictionary with scan information.
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of URLs discovered.
    """

    # Initialize ctx if None to avoid mutable default argument issues
    if ctx is None:
        ctx = {}

    def _execute_dir_file_fuzz(ctx, description):
        # Config
        config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
        custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
        if custom_header:
            custom_header = generate_header_param(custom_header, "common")
        auto_calibration = config.get(AUTO_CALIBRATION, True)
        rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
        extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
        # prepend . on extensions
        extensions = [ext if ext.startswith(".") else f".{ext}" for ext in extensions]
        follow_redirect = config.get(FOLLOW_REDIRECT, FFUF_DEFAULT_FOLLOW_REDIRECT)
        max_time = config.get(MAX_TIME, 0)
        match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
        recursive_level = config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
        stop_on_error = config.get(STOP_ON_ERROR, False)
        timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
        threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
        wordlist_name = config.get(WORDLIST, FFUF_DEFAULT_WORDLIST_NAME)
        input_path = str(Path(self.results_dir) / "input_dir_file_fuzz.txt")

        # Get wordlist
        wordlist_name = FFUF_DEFAULT_WORDLIST_NAME if wordlist_name == "default" else wordlist_name
        wordlist_path = str(Path(FFUF_DEFAULT_WORDLIST_PATH) / f"{wordlist_name}.txt")

        # Get URLs to fuzz
        urls = get_http_urls(
            is_alive=True, ignore_files=False, write_filepath=input_path, get_only_default_urls=True, ctx=ctx
        )

        if not urls:
            logger.error("No alive URLs found for directory fuzzing. Skipping.")
            return

        logger.warning(urls)

        # Use distributed fuzzing processor
        processor = FuzzingProcessor()

        # Loop through URLs and run command
        results = []
        for url in urls:
            """
                Above while fetching urls, we are not ignoring files, because some
                default urls may redirect to https://example.com/login.php
                so, ignore_files is set to False
                but, during fuzzing, we will only need part of the path, in above example
                it is still a good idea to ffuf base url https://example.com
                so files from base url
            """
            url_parse = urlparse(url)
            target_url = f"{url_parse.scheme}://{url_parse.netloc}"
            target_url += "/FUZZ"  # TODO: fuzz not only URL but also POST / PUT / headers
            proxy = get_random_proxy()

            # Build ffuf command
            command = processor.build_ffuf_command(
                wordlist_path=wordlist_path,
                target_url=target_url,
                extensions=extensions,
                threads=threads,
                timeout=timeout,
                rate_limit=rate_limit,
                max_time=max_time,
                recursive_level=recursive_level,
                match_http_status=match_http_status,
                follow_redirect=follow_redirect,
                auto_calibration=auto_calibration,
                stop_on_error=stop_on_error,
                custom_header=custom_header,
                proxy=proxy,
            )

            # Initialize DirectoryScan object
            dirscan = DirectoryScan()
            dirscan.scanned_date = timezone.now()
            dirscan.command_line = command
            dirscan.save()

            # Stream command output and process results
            stream_result = processor.stream_ffuf_command(
                command, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id
            )

            if stream_result["success"]:
                # Parse stream output as JSON lines
                stream_output = stream_result.get("stream_output", "")
                ffuf_results = []

                for line in stream_output.split("\n"):
                    if line.strip():
                        try:
                            import json

                            ffuf_line = json.loads(line)
                            ffuf_results.append(ffuf_line)
                        except json.JSONDecodeError:
                            continue

                # Process FFUF results
                processed_results = processor.process_ffuf_results(ffuf_results, ctx, self.scan, self.subscan)

                # Add results to directory scan
                for result in processed_results:
                    results.append(result)

                    # Get the directory file object
                    try:
                        name = base64.b64encode(extract_path_from_url(result["url"]).encode()).decode()
                        dfile = save_fuzzing_file(
                            name=name,
                            url=result["url"],
                            http_status=result["status"],
                            length=result["length"],
                            words=result["words"],
                            lines=result["lines"],
                            content_type=result["content_type"],
                        )[0]

                        # Add file to current dirscan
                        dirscan.directory_files.add(dfile)

                        # Add subscan relation to dirscan if exists
                        if self.subscan:
                            dirscan.dir_subscan_ids.add(self.subscan)

                        # Save dirscan data
                        dirscan.save()

                        # Get subdomain and add dirscan
                        if ctx.get("subdomain_id") and ctx["subdomain_id"] > 0:
                            subdomain = Subdomain.objects.get(id=ctx["subdomain_id"])
                        else:
                            subdomain_name = get_subdomain_from_url(result["url"])
                            subdomain = Subdomain.objects.get(name=subdomain_name, scan_history=self.scan)
                        subdomain.directories.add(dirscan)
                        subdomain.save()

                    except Exception as e:
                        logger.error(f"Error processing directory file result: {e}")
                        continue
            else:
                logger.error(f"FFUF command failed: {stream_result.get('error', 'Unknown error')}")

        return results

    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_dir_file_fuzz, ctx, description)


# Utility functions for easy access


def fuzz_directories_distributed(
    urls: List[str], wordlist_path: str, extensions: List[str] = None, threads: int = 10, **kwargs
) -> Dict[str, Any]:
    """
    Fuzz directories using distributed processing.
    """
    processor = FuzzingProcessor()

    results = []
    for url in urls:
        # Build command
        command = processor.build_ffuf_command(
            wordlist_path=wordlist_path, target_url=url, extensions=extensions, threads=threads, **kwargs
        )

        # Execute command
        result = processor.execute_ffuf_command(command)
        if result["success"]:
            results.append(result)

    return {"success": True, "total_urls": len(urls), "successful_fuzzes": len(results), "results": results}


def build_ffuf_command_distributed(wordlist_path: str, target_url: str, **kwargs) -> str:
    """
    Build FFUF command using distributed command builder.
    """
    processor = FuzzingProcessor()
    return processor.build_ffuf_command(wordlist_path=wordlist_path, target_url=target_url, **kwargs)


def parse_ffuf_output(output: str) -> List[Dict[str, Any]]:
    """
    Parse FFUF JSON output.

    Args:
        output: FFUF JSON output

    Returns:
        List of parsed results
    """
    results = []

    for line in output.split("\n"):
        if line.strip():
            try:
                import json

                result = json.loads(line)
                results.append(result)
            except json.JSONDecodeError:
                continue

    return results


def validate_fuzzing_input(urls: List[str], wordlist_path: str) -> Dict[str, Any]:
    """
    Validate fuzzing input parameters.

    Args:
        urls: List of URLs to fuzz
        wordlist_path: Path to wordlist file

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

    # Validate wordlist
    if not wordlist_path:
        validation_result["valid"] = False
        validation_result["errors"].append("No wordlist path provided")
    else:
        from pathlib import Path

        if not Path(wordlist_path).exists():
            validation_result["valid"] = False
            validation_result["errors"].append(f"Wordlist file not found: {wordlist_path}")

    return validation_result


def get_fuzzing_statistics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics from fuzzing results.

    Args:
        results: List of fuzzing results

    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "status_codes": {},
            "content_types": {},
            "average_response_time": 0,
        }

    total_requests = len(results)
    successful_requests = sum(1 for r in results if r.get("status", 0) < 400)
    failed_requests = total_requests - successful_requests

    # Count status codes
    status_codes = {}
    for result in results:
        status = result.get("status", 0)
        status_codes[status] = status_codes.get(status, 0) + 1

    # Count content types
    content_types = {}
    for result in results:
        content_type = result.get("content_type", "unknown")
        content_types[content_type] = content_types.get(content_type, 0) + 1

    # Calculate average response time
    response_times = [r.get("duration", 0) for r in results if r.get("duration")]
    average_response_time = sum(response_times) / len(response_times) if response_times else 0

    return {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "status_codes": status_codes,
        "content_types": content_types,
        "average_response_time": average_response_time,
        "success_rate": (successful_requests / total_requests * 100) if total_requests > 0 else 0,
    }
