import json
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.settings import RENGINE_TOOL_PATH
from reNgine.tasks.command import run_command
from reNgine.utilities.url import get_subdomain_from_url
from reNgine.utilities.endpoint import get_http_urls, ensure_endpoints_crawled_and_execute
from startScan.models import Subdomain, Waf

logger = get_task_logger(__name__)


@app.task(name='waf_detection', queue='io_queue', base=RengineTask, bind=True)
def waf_detection(self, ctx={}, description=None):
    """
    Uses wafw00f to check for the presence of a WAF.

    Args:
        description (str, optional): Task description shown in UI.

    Returns:
        list: List of startScan.models.Waf objects.
    """
    
    def _execute_waf_detection(ctx, description):
        input_path = str(Path(self.results_dir) / 'input_endpoints_waf_detection.txt')
        config = self.yaml_configuration.get('waf_detection') or {}

        # Get alive endpoints from DB
        urls = get_http_urls(
            is_alive=True,
            write_filepath=input_path,
            get_only_default_urls=True,
            ctx=ctx
        )
        if not urls:
            logger.error('No alive URLs found for WAF detection. Skipping.')
            return

        cmd = f'wafw00f -i {input_path} -o {self.output_path} -f json'
        run_command(
            cmd,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id)
            
        if not os.path.isfile(self.output_path):
            logger.error(f'Could not find {self.output_path}')
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
            logger.info(f'Wafw00f Subdomain : {subdomain_name}')

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
                logger.warning(f'Subdomain {subdomain_name} was not found in the db, skipping waf detection.')

        return wafs
    
    # Use the smart crawl-then-execute pattern
    return ensure_endpoints_crawled_and_execute(_execute_waf_detection, ctx, description)


@app.task(name='run_wafw00f', bind=False, queue='run_command_queue')
def run_wafw00f(url):
    try:
        logger.info(f"Starting WAF detection for URL: {url}")
        wafw00f_command = f'wafw00f {url}'
        return_code, output = run_command(
            cmd=wafw00f_command,
            shell=True,
            remove_ansi_sequence=True
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


@app.task(name='run_cmseek', queue='run_command_queue')
def run_cmseek(url):
    try:
        # Prepare CMSeeK command
        cms_detector_command = f'cmseek --random-agent --batch --follow-redirect -u {url}'

        # Run CMSeeK
        _, output = run_command(cms_detector_command, remove_ansi_sequence=True)

        # Parse CMSeeK output
        base_path = f"{RENGINE_TOOL_PATH}/.github/CMSeeK/Result"
        domain_name = urlparse(url).netloc
        json_path = os.path.join(base_path, domain_name, "cms.json")

        if os.path.isfile(json_path):
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

        # CMS not detected
        return {'status': False, 'message': 'Could not detect CMS!'}

    except Exception as e:
        logger.error(f"Error running CMSeeK: {e}")
        return {'status': False, 'message': str(e)} 