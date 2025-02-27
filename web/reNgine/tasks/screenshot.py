import csv
import os

from pathlib import Path

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
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.logger import Logger
from reNgine.utils.utils import extract_columns
from reNgine.utils.formatters import get_output_file_name
from reNgine.utils.utils import remove_file_or_pattern
from scanEngine.models import Notification
from startScan.models import Subdomain
from reNgine.tasks.command import run_command_line
from reNgine.tasks.notification import send_file_to_discord
logger = Logger(True)

@app.task(name='screenshot', queue='screenshot_queue', base=RengineTask, bind=True)
def screenshot(self, ctx=None, description=None):
    """Uses EyeWitness to gather screenshot of a domain and/or url.

    Args:
        description (str, optional): Task description shown in UI.
    """
    from reNgine.utils.db import get_http_urls
 
    if ctx is None:
        ctx = {}
    # Config
    screenshots_path = str(Path(self.results_dir) / 'screenshots')
    output_path = str(Path(self.results_dir) / 'screenshots' / self.filename)
    alive_endpoints_file = str(Path(self.results_dir) / 'endpoints_alive.txt')
    config = self.yaml_configuration.get(SCREENSHOT) or {}
    intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
    timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
    threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

    # If intensity is normal, grab only the root endpoints of each subdomain
    strict = intensity == 'normal'

    # Get URLs to take screenshot of
    urls = get_http_urls(
        is_alive=True,
        strict=strict,
        write_filepath=alive_endpoints_file,
        get_only_default_urls=True,
        ctx=ctx
    )
    if not urls:
        logger.error('No URLs to take screenshot of. Skipping.')
        return

    # Send start notif
    notification = Notification.objects.first()
    send_output_file = notification.send_scan_output_file if notification else False

    # Run cmd
    cmd = f'EyeWitness -f {alive_endpoints_file} -d {screenshots_path} --no-prompt'
    cmd += f' --timeout {timeout}' if timeout > 0 else ''
    cmd += f' --threads {threads}' if threads > 0 else ''
    run_command_line.delay(
        cmd,
        shell=False,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id)
    if not os.path.isfile(output_path):
        logger.error(f'Could not load EyeWitness results at {output_path} for {self.domain.name}.')
        return

    # Loop through results and save objects in DB
    screenshot_paths = []
    with open(output_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # Skip header row
        indices = [header.index(col) for col in ["Protocol", "Port", "Domain", "Request Status", "Screenshot Path", " Source Path"]]
        for row in reader:
            protocol, port, subdomain_name, status, screenshot_path, source_path = extract_columns(row, indices)
            subdomain_query = Subdomain.objects.filter(name=subdomain_name)
            if self.scan:
                subdomain_query = subdomain_query.filter(scan_history=self.scan)
            if status == 'Successful' and subdomain_query.exists():
                subdomain = subdomain_query.first()
                screenshot_paths.append(screenshot_path)
                subdomain.screenshot_path = screenshot_path.replace(RENGINE_RESULTS, '')
                subdomain.save()
                logger.warning(f'Added screenshot for {protocol}://{subdomain.name}:{port} to DB')


    # Remove all db, html extra files in screenshot results
    patterns = ['*.csv', '*.db', '*.js', '*.html', '*.css']
    for pattern in patterns:
        remove_file_or_pattern(
            screenshots_path,
            pattern=pattern,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id
        )

    # Delete source folder
    remove_file_or_pattern(
        str(Path(screenshots_path) / 'source'),
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    # Send finish notifs
    screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
    self.notify(fields={'Screenshots': screenshots_str})
    if send_output_file:
        for path in screenshot_paths:
            title = get_output_file_name(
                self.scan_id,
                self.subscan_id,
                self.filename)
            send_file_to_discord.delay(path, title)
