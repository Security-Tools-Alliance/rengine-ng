import validators
from pathlib import Path

from api.serializers import SubdomainSerializer
from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    SUBDOMAIN_DISCOVERY,
    THREADS,
    TIMEOUT,
    USES_TOOLS,
    SUBDOMAIN_SCAN_DEFAULT_TOOLS,
    ALL,
    USE_AMASS_CONFIG,
    AMASS_WORDLIST,
    AMASS_DEFAULT_WORDLIST_NAME,
    AMASS_DEFAULT_WORDLIST_PATH,
    USE_SUBFINDER_CONFIG,
)
from reNgine.settings import (
    DEFAULT_THREADS,
    DEFAULT_HTTP_TIMEOUT,
    RENGINE_TOOL_GITHUB_PATH,
)
from reNgine.tasks.command import run_command
from reNgine.utilities.database import save_subdomain, save_endpoint, save_subdomain_metadata
from reNgine.utilities.proxy import get_random_proxy
from reNgine.utilities.external import get_netlas_key
from reNgine.utilities.subdomain import get_new_added_subdomain, get_removed_subdomain, get_interesting_subdomains
from scanEngine.models import InstalledExternalTool, Notification
from startScan.models import Subdomain

logger = get_task_logger(__name__)


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
    if ctx is None:
        ctx = {}
    if not host:
        host = self.subdomain.name if self.subdomain else self.domain.name

    if self.url_filter:
        logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.url_filter}).')
        return

    # Config
    config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
    timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
    tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
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
        cmd = None
        logger.info(f'Scanning subdomains for {host} with {tool}')
        proxy = get_random_proxy()
        if tool in default_subdomain_tools:
            if tool == 'amass-passive':
                use_amass_config = config.get(USE_AMASS_CONFIG, False)
                cmd = f'amass enum -passive -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_amass.txt')
                cmd += (' -config ' + str(Path.home() / '.config' / 'amass' / 'config.ini')) if use_amass_config else ''

            elif tool == 'amass-active':
                use_amass_config = config.get(USE_AMASS_CONFIG, False)
                amass_wordlist_name = config.get(AMASS_WORDLIST, AMASS_DEFAULT_WORDLIST_NAME)
                wordlist_path = str(Path(AMASS_DEFAULT_WORDLIST_PATH) / f'{amass_wordlist_name}.txt')
                cmd = f'amass enum -active -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_amass_active.txt')
                cmd += (' -config ' + str(Path.home() / '.config' / 'amass' / 'config.ini')) if use_amass_config else ''
                cmd += f' -brute -w {wordlist_path}'

            elif tool == 'sublist3r':
                cmd = f'sublist3r -d {host} -t {threads} -o ' + str(Path(self.results_dir) / 'subdomains_sublister.txt')

            elif tool == 'subfinder':
                cmd = f'subfinder -d {host} -o ' + str(Path(self.results_dir) / 'subdomains_subfinder.txt')
                use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
                cmd += (' -config ' + str(Path.home() / '.config' / 'subfinder' / 'config.yaml')) if use_subfinder_config else ''
                cmd += f' -proxy {proxy}' if proxy else ''
                cmd += f' -timeout {timeout}' if timeout else ''
                cmd += f' -t {threads}' if threads else ''
                cmd += ' -silent'

            elif tool == 'oneforall':
                cmd = f'oneforall --target {host} run'
                cmd_extract = 'cut -d\',\' -f6 ' + str(Path(RENGINE_TOOL_GITHUB_PATH) / 'OneForAll' / 'results' / f'{host}.csv') + ' | tail -n +2 > ' + str(Path(self.results_dir) / 'subdomains_oneforall.txt')
                cmd_rm = 'rm -rf ' + str(Path(RENGINE_TOOL_GITHUB_PATH) / 'OneForAll' / 'results'/ f'{host}.csv')
                cmd += f' && {cmd_extract} && {cmd_rm}'

            elif tool == 'ctfr':
                results_file = str(Path(self.results_dir) / 'subdomains_ctfr.txt')
                cmd = f'ctfr -d {host} -o {results_file}'
                cmd_extract = f"cat {results_file} | sed 's/\*.//g' | tail -n +12 | uniq | sort > {results_file}"
                cmd += f' && {cmd_extract}'

            elif tool == 'tlsx':
                results_file = str(Path(self.results_dir) / 'subdomains_tlsx.txt')
                cmd = f'tlsx -san -cn -silent -ro -host {host}'
                cmd += f" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
                cmd += f' > {results_file}'

            elif tool == 'netlas':
                results_file = str(Path(self.results_dir) / 'subdomains_netlas.txt')
                cmd = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
                netlas_key = get_netlas_key()
                cmd += f' -a {netlas_key}' if netlas_key else ''
                cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
                cmd += f' | {cmd_extract} > {results_file}'

        elif tool in custom_subdomain_tools:
            tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
            if not tool_query.exists():
                logger.error(f'{tool} configuration does not exists. Skipping.')
                continue
            custom_tool = tool_query.first()
            cmd = custom_tool.subdomain_gathering_command
            if '{TARGET}' not in cmd:
                logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
                continue
            if '{OUTPUT}' not in cmd:
                logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
                continue


            cmd = cmd.replace('{TARGET}', host)
            cmd = cmd.replace('{OUTPUT}', str(Path(self.results_dir) / f'subdomains_{tool}.txt'))
            cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
        else:
            logger.warning(
                f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.')
            continue

        # Run tool
        try:
            run_command(
                cmd,
                shell=True,
                history_file=self.history_file,
                scan_id=self.scan_id,
                activity_id=self.activity_id)
        except Exception as e:
            logger.error(
                f'Subdomain discovery tool "{tool}" raised an exception')
            logger.exception(e)

    # Gather all the tools' results in one single file. Write subdomains into
    # separate files, and sort all subdomains.
    run_command(
        'cat ' + str(Path(self.results_dir) / 'subdomains_*.txt') + f' > {self.output_path}',
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)
    run_command(
        f'sort -u {self.output_path} -o {self.output_path}',
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)

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
            from urllib.parse import urlparse
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

    url_filter = ctx.get('url_filter')
    # Find root subdomain endpoints
    for subdomain in subdomains:
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