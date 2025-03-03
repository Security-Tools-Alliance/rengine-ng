import json
import os
import re
import shutil
from urllib.parse import urlparse

from pathlib import Path

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import WAF_DETECTION
from reNgine.settings import RENGINE_TOOL_PATH
from reNgine.tasks.command import run_command_line
from reNgine.utils.command_builder import CommandBuilder, build_cmsseek_cmd, build_wafw00f_cmd
from reNgine.utils.logger import Logger
from reNgine.utils.http import get_subdomain_from_url, prepare_urls_with_fallback
from reNgine.utils.task_config import TaskConfig

from startScan.models import Waf, Subdomain

"""
Celery tasks.
"""

logger = Logger(is_task_logger=True)  # Use task logger for Celery tasks


@app.task(name='waf_detection', queue='io_queue', base=RengineTask, bind=True)
def waf_detection(self, ctx=None, description=None):
    """
    Uses wafw00f to check for the presence of a WAF.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of startScan.models.Waf objects.
    """
    if ctx is None:
        ctx = {}

    config = TaskConfig(ctx, WAF_DETECTION)
    task_config = config.get_task_config()

    # Get alive endpoints from DB
    urls = prepare_urls_with_fallback(
        is_alive=True,
        write_filepath=task_config['input_path'],
        get_only_default_urls=True,
        ctx=ctx
    )
    if not urls:
        logger.error('🛡️  No URLs to check for WAF. Skipping.')
        return

    run_command_line.delay(
        build_wafw00f_cmd(config),
        shell=False,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    if not os.path.isfile(self.output_path):
        logger.error(f'🛡️  Could not find {self.output_path}')
        return

    with open(self.output_path) as file:
        wafs = json.load(file)

    for waf_data in wafs:
        if not waf_data.get('detected') or not waf_data.get('firewall'):
            continue

        # Add waf to db
        waf, _ = Waf.objects.get_or_create(
            name=waf_data['firewall'],
            manufacturer=waf_data.get('manufacturer', '')
        )

        # Add waf info to Subdomain in DB
        subdomain_name = get_subdomain_from_url(waf_data['url'])
        logger.info(f'🛡️  Wafw00f Subdomain : {subdomain_name}')

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
            logger.warning(f'🛡️  Subdomain {subdomain_name} was not found in the db, skipping waf detection.')

    return wafs

@app.task(name='run_cmseek', queue='run_command_queue')
def run_cmseek(url):
    try:
        # Run CMSeeK
        _, output = run_command_line(build_cmsseek_cmd(url), remove_ansi_sequence=True)

        # Parse CMSeeK output
        base_path = f"{RENGINE_TOOL_PATH}/.github/CMSeeK/Result"
        domain_name = urlparse(url).netloc
        json_path = os.path.join(base_path, domain_name, "cms.json")

        if not Path(json_path).exists():
            logger.error(f'📁 CMSeeK file missing : {json_path}')
            return {'status': False, 'message': 'CMS result file missing'}

        with open(json_path, 'r') as f:
            cms_data = json.load(f)

        if cms_data.get('cms_name'):
            # CMS detected
            result = {'status': True}
            result |= cms_data

        # Clean up CMSeeK results
        try:
            shutil.rmtree(os.path.dirname(json_path))
        except Exception as e:
            logger.error(f"Error cleaning up CMSeeK results: {e}")

        return result

    except Exception as e:
        logger.error(f"Error running CMSeeK: {e}")
        return {'status': False, 'message': str(e)}

@app.task(name='run_wafw00f', bind=False, queue='run_command_queue')
def run_wafw00f(url):
    try:
        logger.info(f"Starting WAF detection for URL: {url}")
        # wafw00f command builder
        wafw_builder = CommandBuilder('wafw00f')
        wafw_builder.add_option(url)
        return_code, output = run_command_line(
            wafw_builder.build_list(),
            shell=False,
        )

        logger.info(f"Raw output from wafw00f: {output}")

        if match := re.search(r"behind (.+)", output):
            result = match[1]
            logger.info(f"WAF detected: {result}")
            return result
        else:
            logger.info("No WAF detected")
            return "No WAF detected"
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"Unexpected error: {str(e)}"
