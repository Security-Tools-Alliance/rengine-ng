import validators

from pathlib import Path
from copy import deepcopy
from urllib.parse import urlparse

from reNgine.definitions import (
    ALL,
    SUBDOMAIN_DISCOVERY,
    SUBDOMAIN_SCAN_DEFAULT_TOOLS,
    USES_TOOLS,
)
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.subdomain_tools import build_subdomain_tool_command
from reNgine.tasks.command import run_command_line
from reNgine.tasks.http import http_crawl
from reNgine.utils.command_builder import CommandBuilder, build_piped_command
from reNgine.utils.task_config import TaskConfig

from scanEngine.models import (
    InstalledExternalTool,
    Notification,
)
from startScan.models import (
    Subdomain,
)

logger = Logger(True)


@app.task(name='subdomain_discovery', queue='io_queue', base=RengineTask, bind=True)
def subdomain_discovery(
        self,
        host=None,
        ctx=None,
        description=None):
    """Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
    subdomains associated with a domain.

    Args:
        host (str): Hostname to scan.

    Returns:
        subdomains (list): List of subdomain names.
    """
    from api.serializers import SubdomainSerializer
    from reNgine.utils.db import (
        get_random_proxy,
        get_interesting_subdomains,
        get_new_added_subdomain,
        get_removed_subdomain,
        save_endpoint,
        save_subdomain,
        save_subdomain_metadata,
    )
    if not host:
        host = self.subdomain.name if self.subdomain else self.domain.name

    if self.url_filter:
        logger.warning(f'🌍 Ignoring subdomains scan as an URL path filter was passed ({self.url_filter}).')
        return

    # Config
    config = TaskConfig(self.yaml_configuration, self.results_dir, self.scan_id, self.filename)
    subdomain_config = config.get_config(SUBDOMAIN_DISCOVERY)
    enable_http_crawl = config.get_http_crawl_enabled(SUBDOMAIN_DISCOVERY)
    threads = config.get_threads(SUBDOMAIN_DISCOVERY)
    timeout = config.get_timeout(SUBDOMAIN_DISCOVERY)
    tools = subdomain_config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
    default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
    custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
    send_subdomain_changes, send_interesting = False, False
    if notif := Notification.objects.first():
        send_subdomain_changes = notif.send_subdomain_changes_notif
        send_interesting = notif.send_interesting_notif

    # Gather tools to run for subdomain scan
    if ALL in tools:
        tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
    tools = [t.lower() for t in tools]

    default_subdomain_tools.extend(('amass-passive', 'amass-active'))
    # Run tools
    for tool in tools:
        cmd, use_shell, error_msg = build_subdomain_tool_command(
            tool, host, self.results_dir, subdomain_config, get_random_proxy(), timeout, threads, custom_subdomain_tools)

        if error_msg:
            logger.error(error_msg)
            continue

        # Run tool
        if cmd:
            try:
                run_command_line.delay(
                    cmd,
                    shell=use_shell,
                    history_file=self.history_file,
                    scan_id=self.scan_id,
                    activity_id=self.activity_id
                )
            except Exception as e:
                logger.error(f'🌍 Error running command: {cmd}, error: {e}')
                continue

    # Gather all the tools' results in one single file. Write subdomains into
    # separate files, and sort all subdomains.
    input_path = str(Path(self.results_dir) / "subdomains_*.txt")
    output_path = self.output_path

    cat_cmd = CommandBuilder('cat')
    cat_cmd.add_option(input_path)

    piped_cmd = build_piped_command(
        [cat_cmd], 
        output_file=output_path,
        append=False
    )

    run_command_line.delay(
        cmd=piped_cmd.build_string(),
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    sort_cmd = CommandBuilder('sort')
    sort_cmd.add_option('-u')
    sort_cmd.add_option(output_path)

    piped_cmd = build_piped_command(
        [sort_cmd], 
        output_file=output_path,
        append=False
    )

    run_command_line.delay(
        cmd=piped_cmd.build_string(),
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    # Check that the sorted file has been created
    if not Path(self.output_path).exists():
        logger.error('❌ Failed to create sorted subdomains file')
        return SubdomainSerializer([], many=True).data

    # Read the results file
    with open(self.output_path) as f:
        lines = f.readlines()

    # Parse the output_file file and store Subdomain and EndPoint objects found
    # in db.
    subdomain_count = 0
    subdomains = []
    urls = []
    for line in lines:
        subdomain_name = line.strip()
        valid_url = bool(validators.url(subdomain_name))
        valid_domain = (
            bool(validators.domain(subdomain_name)) or
            bool(validators.ipv4(subdomain_name)) or
            bool(validators.ipv6(subdomain_name)) or
            valid_url
        )
        if not valid_domain:
            logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
            continue

        if valid_url:
            subdomain_name = urlparse(subdomain_name).netloc

        if subdomain_name in self.out_of_scope_subdomains:
            logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
            continue

        # Add subdomain
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        if not isinstance(subdomain, Subdomain):
            logger.error(f"Invalid subdomain encountered: {subdomain}")
            continue
        subdomain_count += 1
        subdomains.append(subdomain)
        urls.append(subdomain.name)

    # Bulk crawl subdomains
    if enable_http_crawl:
        custom_ctx = deepcopy(ctx)
        custom_ctx['track'] = True
        http_crawl.delay(urls, ctx=custom_ctx, update_subdomain_metadatas=True)
    else:
        url_filter = ctx.get('url_filter')
        # Find root subdomain endpoints
        for subdomain in subdomains:
            subdomain_name = subdomain.strip()
            # Create base endpoint (for scan)
            http_url = f'{subdomain.name}{url_filter}' if url_filter else subdomain.name
            endpoint, _ = save_endpoint(
                http_url,
                ctx=ctx,
                is_default=True,
                subdomain=subdomain
            )
            save_subdomain_metadata(subdomain, endpoint)

    # Send notifications
    subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
    self.notify(fields={
        'Subdomain count': len(subdomains),
        'Subdomains': subdomains_str,
    })
    if send_subdomain_changes and self.scan_id and self.domain_id:
        added = get_new_added_subdomain(self.scan_id, self.domain_id)
        removed = get_removed_subdomain(self.scan_id, self.domain_id)

        if added:
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
            self.notify(fields={'Added subdomains': subdomains_str})

        if removed:
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
            self.notify(fields={'Removed subdomains': subdomains_str})

    if send_interesting and self.scan_id and self.domain_id:
        if interesting_subdomains := get_interesting_subdomains(
            self.scan_id, self.domain_id
        ):
            subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
            self.notify(fields={'Interesting subdomains': subdomains_str})

    return SubdomainSerializer(subdomains, many=True).data
