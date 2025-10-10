"""
URL tasks for URL fetching, duplicate removal, and GF pattern matching.

This module provides functionality for fetching URLs, removing duplicates,
and applying GF patterns for content discovery.
"""

import os
from pathlib import Path
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from django.db.models import Count

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    CUSTOM_HEADER,
    DEFAULT_GF_PATTERNS,
    DEFAULT_IGNORE_FILE_EXTENSIONS,
    DUPLICATE_REMOVAL_FIELDS,
    ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS,
    ENDPOINT_SCAN_DEFAULT_TOOLS,
    EXCLUDED_SUBDOMAINS,
    FETCH_URL,
    FOLLOW_REDIRECT,
    GF_PATTERNS,
    IGNORE_FILE_EXTENSION,
    REMOVE_DUPLICATE_ENDPOINTS,
    THREADS,
    USES_TOOLS,
)
from reNgine.settings import DEFAULT_THREADS, DELETE_DUPLICATES_THRESHOLD
from reNgine.utilities.command import generate_header_param, run_command
from reNgine.utilities.core.data import is_iterable
from reNgine.utilities.core.validation import is_valid_url
from reNgine.utilities.database import save_endpoint, validate_and_save_subdomain
from reNgine.utilities.distributed.utilities import get_distributed_utilities
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.url import get_http_urls, get_subdomain_from_url, sanitize_url
from startScan.models import EndPoint


logger = get_task_logger(__name__)


class URLProcessor:
    """URL processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()
        self.endpoint_processor = self.distributed_utils.get_endpoint_processor()
        self.subdomain_processor = self.distributed_utils.get_subdomain_processor()

    def build_url_fetching_commands(
        self,
        urls: List[str],
        tools: List[str],
        threads: int = 10,
        custom_header: str = None,
        proxy: str = None,
        follow_redirect: bool = True,
    ) -> List[str]:
        """Build URL fetching commands for multiple tools"""
        commands = []

        # Initialize command map for tools
        cmd_map = {
            "gau": "gau --config " + str(Path.home() / ".config" / "gau" / "config.toml"),
            "hakrawler": "hakrawler -subs -u",
            "waybackurls": "waybackurls",
            "gospider": "gospider --js -d 2 --sitemap --robots -w -r -a",
            "katana": "katana -silent -jc -kf all -d 3 -fs rdn -td",
        }

        # Add proxy configuration
        if proxy:
            cmd_map["gau"] += f' --proxy "{proxy}"'
            cmd_map["gospider"] += f" -p {proxy}"
            cmd_map["hakrawler"] += f" -proxy {proxy}"
            cmd_map["katana"] += f" -proxy {proxy}"

        # Add thread configuration
        if threads > 0:
            cmd_map["gau"] += f" --threads {threads}"
            cmd_map["gospider"] += f" -t {threads}"
            cmd_map["hakrawler"] += f" -t {threads}"
            cmd_map["katana"] += f" -c {threads}"

        # Add custom header configuration
        if custom_header:
            cmd_map["gospider"] += generate_header_param(custom_header, "gospider")
            cmd_map["hakrawler"] += generate_header_param(custom_header, "hakrawler")
            cmd_map["katana"] += generate_header_param(custom_header, "common")

        # Add follow_redirect option to tools that support it
        if follow_redirect is False:
            cmd_map["gospider"] += " --no-redirect"
            cmd_map["hakrawler"] += " -dr"
            cmd_map["katana"] += " -dr"

        # Generate commands for each URL and tool combination
        for url in urls:
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc.split(":")[0]  # Remove port if present
            host_regex = f"'https?://{re.escape(base_domain)}(:[0-9]+)?(/.*)?$'"

            cat_input = f'echo "{url}"'

            # Generate commands for each tool for the current URL
            for tool in tools:
                if tool in cmd_map:
                    cmd = cmd_map[tool]
                    tool_cmd = f"{cat_input} | {cmd} | grep -Eo {host_regex}"
                    commands.append(tool_cmd)

        return commands

    def execute_url_fetching_commands(self, commands: List[str], output_files: List[str], **kwargs) -> Dict[str, Any]:
        """Execute URL fetching commands using distributed command processor"""
        try:
            # Create command-output file pairs
            command_output_pairs = []
            for i, (cmd, output_file) in enumerate(zip(commands, output_files)):
                full_cmd = f"{cmd} > {output_file}"
                command_output_pairs.append(full_cmd)

            result = self.command_processor.execute_commands_batch(
                command_output_pairs, "url_fetching", timeout=1800, **kwargs
            )

            if result.is_successful:
                return {
                    "success": True,
                    "commands": command_output_pairs,
                    "output_files": output_files,
                    "execution_time": result.processing_time,
                }
            else:
                return {
                    "success": False,
                    "commands": command_output_pairs,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time,
                }

        except Exception as e:
            logger.error(f"URL fetching commands execution failed: {e}")
            return {"success": False, "commands": commands, "error": str(e), "execution_time": 0}

    def build_gf_command(self, input_file: str, pattern: str, domain_name: str, output_file: str) -> str:
        """Build GF pattern matching command"""
        host_regex = f"'https?://{re.escape(domain_name)}(:[0-9]+)?(/.*)?$'"
        return f"cat {input_file} | gf {pattern} | grep -Eo {host_regex} >> {output_file}"

    def execute_gf_commands(self, commands: List[str], **kwargs) -> Dict[str, Any]:
        """Execute GF pattern matching commands"""
        try:
            result = self.command_processor.execute_commands_batch(commands, "gf_patterns", timeout=600, **kwargs)

            if result.is_successful:
                return {"success": True, "commands": commands, "execution_time": result.processing_time}
            else:
                return {
                    "success": False,
                    "commands": commands,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time,
                }

        except Exception as e:
            logger.error(f"GF commands execution failed: {e}")
            return {"success": False, "commands": commands, "error": str(e), "execution_time": 0}

    def process_gf_results(
        self, gf_output_files: List[str], gf_patterns: List[str], ctx: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process GF pattern matching results"""
        results = []

        for gf_output_file, gf_pattern in zip(gf_output_files, gf_patterns):
            try:
                if not os.path.exists(gf_output_file):
                    logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
                    continue

                # Read output file line by line
                with open(gf_output_file, "r") as f:
                    lines = f.readlines()

                # Add endpoints / subdomains to DB
                for url in lines:
                    try:
                        http_url = sanitize_url(url)
                        subdomain_name = get_subdomain_from_url(http_url)
                        subdomain, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
                        if subdomain is None:
                            continue

                        endpoint, created = save_endpoint(http_url=http_url, subdomain=subdomain, ctx=ctx)
                        if not endpoint:
                            continue

                        earlier_pattern = None
                        if not created:
                            earlier_pattern = endpoint.matched_gf_patterns
                        pattern = f"{earlier_pattern},{gf_pattern}" if earlier_pattern else gf_pattern
                        endpoint.matched_gf_patterns = pattern
                        endpoint.save()

                        results.append({"url": http_url, "pattern": gf_pattern, "created": created})

                    except Exception as e:
                        logger.error(f"Error processing GF result URL {url}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error processing GF output file {gf_output_file}: {e}")
                continue

        return results


# Celery tasks


@app.task(name="fetch_url", queue="io_queue", base=RengineTask, bind=True)
def fetch_url(self, urls=[], ctx={}, description=None):
    """Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

    Args:
        urls (list): List of URLs to start from.
        description (str, optional): Task description shown in UI.
    """
    input_path = str(Path(self.results_dir) / "input_endpoints_fetch_url.txt")
    proxy = get_random_proxy()

    # Config
    config = self.yaml_configuration.get(FETCH_URL) or {}
    should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
    duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)

    gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
    config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
    tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    domain_request_headers = self.domain.request_headers if self.domain else None
    custom_header = config.get(CUSTOM_HEADER) or self.yaml_configuration.get(CUSTOM_HEADER)
    follow_redirect = config.get(FOLLOW_REDIRECT, False)  # Get follow redirect setting
    if domain_request_headers or custom_header:
        custom_header = domain_request_headers or custom_header
    exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

    # Initialize the URLs
    if urls and is_iterable(urls) and any(url for url in urls if url):
        logger.debug("URLs provided by user")
        with open(input_path, "w") as f:
            f.write("\n".join(urls))
    else:
        logger.debug("URLs gathered from database")
        urls = get_http_urls(
            is_alive=True,
            write_filepath=input_path,
            exclude_subdomains=exclude_subdomains,
            get_only_default_urls=True,
            ctx=ctx,
        )

    # check if urls is empty
    if not urls:
        logger.warning("No URLs found. Exiting fetch_url.")
        return

    # Log initial URLs
    logger.debug(f"Initial URLs: {urls}")

    # Use distributed URL processor
    processor = URLProcessor()

    # Build URL fetching commands
    commands = processor.build_url_fetching_commands(
        urls=urls,
        tools=tools,
        threads=threads,
        custom_header=custom_header,
        proxy=proxy,
        follow_redirect=follow_redirect,
    )

    # Create output files for each command
    output_files = []
    for i, command in enumerate(commands):
        output_file = f"{self.results_dir}/urls_command_{i}.txt"
        output_files.append(output_file)

    # Execute URL fetching commands
    fetch_result = processor.execute_url_fetching_commands(
        commands, output_files, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id
    )

    if not fetch_result["success"]:
        logger.error(f"URL fetching failed: {fetch_result.get('error', 'Unknown error')}")
        return

    # Process results and collect URLs
    all_urls = []
    tool_mapping = {}  # New dictionary to map URLs to tools

    for i, (command, output_file) in enumerate(zip(commands, output_files)):
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                discovered_urls = f.readlines()
                for url in discovered_urls:
                    url = url.strip()
                    urlpath = None
                    base_url = None
                    if "] " in url:  # found JS scraped endpoint e.g from gospider
                        split = tuple(url.split("] "))
                        if not len(split) == 2:
                            logger.warning(f'URL format not recognized for "{url}". Skipping.')
                            continue
                        base_url, urlpath = split
                        urlpath = urlpath.lstrip("- ")
                    elif " - " in url:  # found JS scraped endpoint e.g from gospider
                        base_url, urlpath = tuple(url.split(" - "))

                    if base_url and urlpath:
                        # Handle both cases: path-only and full URLs
                        if urlpath.startswith(("http://", "https://")):
                            # Full URL case - check if in scope
                            parsed_url = urlparse(urlpath)
                            if self.domain.name in parsed_url.netloc:
                                url = urlpath  # Use the full URL directly
                                logger.debug(f"Found in-scope URL: {url}")
                            else:
                                logger.debug(f"URL {urlpath} not in scope for domain {self.domain.name}. Skipping.")
                                continue
                        else:
                            # Path-only case
                            subdomain = urlparse(base_url)
                            # Remove ./ at beginning of urlpath
                            urlpath = urlpath.lstrip("./")
                            # Ensure urlpath starts with /
                            if not urlpath.startswith("/"):
                                urlpath = "/" + urlpath
                            url = f"{subdomain.scheme}://{subdomain.netloc}{urlpath}"

                    import validators

                    if not validators.url(url):
                        logger.warning(f'Invalid URL "{url}". Skipping.')
                        continue

                    if url not in tool_mapping:
                        tool_mapping[url] = set()
                    tool_mapping[url].add(tools[i % len(tools)])  # Use a set to ensure uniqueness

    all_urls = list(tool_mapping.keys())
    for url, found_tools in tool_mapping.items():
        unique_tools = ", ".join(found_tools)
        logger.info(f"URL {url} found by tools: {unique_tools}")

    # Filter out URLs if a path filter was passed
    if self.url_filter:
        all_urls = [url for url in all_urls if self.url_filter in url]

    # Write result to output path
    with open(self.output_path, "w") as f:
        f.write("\n".join(all_urls))
    logger.warning(f"Found {len(all_urls)} usable URLs")

    # -------------------#
    # GF PATTERNS MATCH #
    # -------------------#

    # Combine old gf patterns with new ones
    if gf_patterns and is_iterable(gf_patterns):
        self.scan.used_gf_patterns = ",".join(gf_patterns)
        self.scan.save()

    # Run gf patterns on saved endpoints
    gf_commands = []
    gf_output_files = []

    for gf_pattern in gf_patterns:
        # TODO: js var is causing issues, removing for now
        if gf_pattern == "jsvar":
            logger.info("Ignoring jsvar as it is causing issues.")
            continue

        # Run gf on current pattern
        logger.warning(f'Running gf on pattern "{gf_pattern}"')
        gf_output_file = str(Path(self.results_dir) / f"gf_patterns_{gf_pattern}.txt")
        gf_output_files.append(gf_output_file)

        command = processor.build_gf_command(
            input_file=self.output_path, pattern=gf_pattern, domain_name=self.domain.name, output_file=gf_output_file
        )
        gf_commands.append(command)

    # Execute GF commands
    if gf_commands:
        gf_result = processor.execute_gf_commands(
            gf_commands, history_file=self.history_file, scan_id=self.scan_id, activity_id=self.activity_id
        )

        if gf_result["success"]:
            # Process GF results
            gf_results = processor.process_gf_results(gf_output_files, gf_patterns, ctx)
            logger.info(f"Processed {len(gf_results)} GF pattern matches")
        else:
            logger.error(f"GF pattern matching failed: {gf_result.get('error', 'Unknown error')}")

    # Remove duplicate endpoints if configured
    if should_remove_duplicate_endpoints and all_urls:
        logger.info("Removing duplicate endpoints after URL discovery")
        remove_duplicate_endpoints(
            scan_history_id=self.scan_id, domain_id=self.domain_id, duplicate_removal_fields=duplicate_removal_fields
        )

    return all_urls


@app.task(name="remove_duplicate_endpoints", bind=False, queue="cpu_queue")
def remove_duplicate_endpoints(
    scan_history_id,
    domain_id,
    subdomain_id=None,
    filter_ids=[],
    # TODO Check if the status code could be set as parameters of the scan engine instead of hardcoded values
    filter_status=[200, 301, 302, 303, 307, 404, 410],  # Extended status codes
    duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS,
):
    """Remove duplicate endpoints.

    Check for implicit redirections by comparing endpoints:
    - [x] `content_length` similarities indicating redirections
    - [x] `page_title` (check for same page title)
    - [ ] Sign-in / login page (check for endpoints with the same words)

    Args:
        scan_history_id: ScanHistory id.
        domain_id (int): Domain id.
        subdomain_id (int, optional): Subdomain id.
        filter_ids (list): List of endpoint ids to filter on.
        filter_status (list): List of HTTP status codes to filter on.
        duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
    """
    logger.info(f"Removing duplicate endpoints based on {duplicate_removal_fields}")

    # Filter endpoints based on scan history and domain
    endpoints = EndPoint.objects.filter(scan_history__id=scan_history_id).filter(target_domain__id=domain_id)
    if filter_status:
        endpoints = endpoints.filter(http_status__in=filter_status)

    if subdomain_id:
        endpoints = endpoints.filter(subdomain__id=subdomain_id)

    if filter_ids:
        endpoints = endpoints.filter(id__in=filter_ids)

    # Group by all duplicate removal fields combined
    fields_combined = duplicate_removal_fields[:]
    fields_combined.append("id")  # Add ID to ensure unique identification

    cl_query = endpoints.values(*duplicate_removal_fields).annotate(mc=Count("id")).order_by("-mc")

    for field_values in cl_query:
        if field_values["mc"] > DELETE_DUPLICATES_THRESHOLD:
            filter_criteria = {field: field_values[field] for field in duplicate_removal_fields}
            eps_to_delete = endpoints.filter(**filter_criteria).order_by("discovered_date").all()[1:]
            msg = f"Deleting {len(eps_to_delete)} endpoints [reason: same {filter_criteria}]"
            for ep in eps_to_delete:
                url = urlparse(ep.http_url)
                if url.path in [
                    "",
                    "/",
                    "/login",
                ]:  # Ensure not to delete the original page that other pages redirect to
                    continue
                msg += f"\n\t {ep.http_url} [{ep.http_status}] {filter_criteria}"
                ep.delete()
            logger.warning(msg)


@app.task(name="run_gf_list", queue="run_command_queue")
def run_gf_list():
    """Run GF list command to get available patterns"""
    try:
        # Prepare GF list command
        gf_command = "gf -list"

        # Run GF list command
        return_code, output = run_command(cmd=gf_command, shell=True, remove_ansi_sequence=True)

        # Log the raw output
        logger.info(f"Raw output from GF list: {output}")

        # Check if the command was successful
        if return_code == 0:
            # Split the output into a list of patterns
            patterns = [pattern.strip() for pattern in output.split("\n") if pattern.strip()]
            return {"status": True, "output": patterns}
        else:
            logger.error(f"GF list command failed with return code: {return_code}")
            return {"status": False, "message": f"GF list command failed with return code: {return_code}"}

    except Exception as e:
        logger.error(f"Error running GF list: {e}")
        return {"status": False, "message": str(e)}


# Utility functions for easy access


def fetch_urls_distributed(urls: List[str], tools: List[str], **kwargs) -> Dict[str, Any]:
    """
    Fetch URLs using distributed processing.
    """
    processor = URLProcessor()

    # Build commands
    commands = processor.build_url_fetching_commands(urls=urls, tools=tools, **kwargs)

    # Create output files
    output_files = [f"/tmp/urls_{i}.txt" for i in range(len(commands))]

    # Execute commands
    result = processor.execute_url_fetching_commands(commands, output_files)

    if result["success"]:
        # Collect results
        all_urls = []
        for output_file in output_files:
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    urls_from_file = [line.strip() for line in f.readlines()]
                    all_urls.extend(urls_from_file)

        return {
            "success": True,
            "total_urls": len(all_urls),
            "unique_urls": len(set(all_urls)),
            "urls": list(set(all_urls)),
            "execution_time": result["execution_time"],
        }
    else:
        return {
            "success": False,
            "error": result.get("error", "Unknown error"),
            "execution_time": result["execution_time"],
        }


def apply_gf_patterns_distributed(urls: List[str], patterns: List[str], domain_name: str, **kwargs) -> Dict[str, Any]:
    """
    Apply GF patterns to URLs using distributed processing.
    """
    processor = URLProcessor()

    # Build GF commands
    gf_commands = []
    gf_output_files = []

    for pattern in patterns:
        if pattern == "jsvar":
            continue  # Skip problematic pattern

        output_file = f"/tmp/gf_{pattern}.txt"
        gf_output_files.append(output_file)

        command = processor.build_gf_command(
            input_file="/tmp/input_urls.txt", pattern=pattern, domain_name=domain_name, output_file=output_file
        )
        gf_commands.append(command)

    # Write input URLs to file
    with open("/tmp/input_urls.txt", "w") as f:
        f.write("\n".join(urls))

    # Execute GF commands
    result = processor.execute_gf_commands(gf_commands, **kwargs)

    if result["success"]:
        # Process results
        gf_results = processor.process_gf_results(gf_output_files, patterns, {})

        return {
            "success": True,
            "total_patterns": len(patterns),
            "matched_urls": len(gf_results),
            "results": gf_results,
            "execution_time": result["execution_time"],
        }
    else:
        return {
            "success": False,
            "error": result.get("error", "Unknown error"),
            "execution_time": result["execution_time"],
        }


def validate_url_input(urls: List[str], tools: List[str]) -> Dict[str, Any]:
    """
    Validate URL fetching input parameters.

    Args:
        urls: List of URLs to fetch
        tools: List of tools to use

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

    # Validate tools
    if not tools:
        validation_result["valid"] = False
        validation_result["errors"].append("No tools provided")
    else:
        available_tools = ["gau", "hakrawler", "waybackurls", "gospider", "katana"]
        valid_tools = [tool for tool in tools if tool in available_tools]

        if not valid_tools:
            validation_result["valid"] = False
            validation_result["errors"].append("No valid tools found")
        elif len(valid_tools) != len(tools):
            invalid_tools = [tool for tool in tools if tool not in available_tools]
            validation_result["warnings"].append(f"Invalid tools: {invalid_tools}")

    return validation_result


def get_url_statistics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get statistics from URL fetching results.

    Args:
        results: URL fetching results

    Returns:
        Statistics dictionary
    """
    if not results:
        return {"total_urls": 0, "unique_urls": 0, "duplicate_urls": 0, "execution_time": 0}

    total_urls = results.get("total_urls", 0)
    unique_urls = results.get("unique_urls", 0)
    duplicate_urls = total_urls - unique_urls
    execution_time = results.get("execution_time", 0)

    return {
        "total_urls": total_urls,
        "unique_urls": unique_urls,
        "duplicate_urls": duplicate_urls,
        "execution_time": execution_time,
        "duplicate_rate": (duplicate_urls / total_urls * 100) if total_urls > 0 else 0,
    }
