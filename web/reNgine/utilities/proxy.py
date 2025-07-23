import json
import os
import random
import re
import shutil
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from scanEngine.models import Proxy

logger = get_task_logger(__name__)


#-------#
# Utils #
#-------#

def get_random_proxy():
    """Get a random proxy from the list of proxies input by user in the UI.

    Returns:
        str: Proxy name or '' if no proxy defined in db or use_proxy is False.
    """
    if not Proxy.objects.all().exists():
        return ''
    proxy = Proxy.objects.first()
    if not proxy.use_proxy:
        return ''
    proxy_name = random.choice(proxy.proxies.splitlines())
    logger.warning(f'Using proxy: {proxy_name}')
    # os.environ['HTTP_PROXY'] = proxy_name
    # os.environ['HTTPS_PROXY'] = proxy_name
    return proxy_name


def remove_ansi_escape_sequences(text):
    return re.sub(r'\x1b\[.*?m', '', text)


def get_cms_details(url):
    """Get CMS details using cmseek.py.

    Args:
        url (str): HTTP URL.

    Returns:
        dict: Response.
    """
    cms_detector_command = f'python3 /home/rengine/tools/.github/CMSeeK/cmseek.py --random-agent --batch --follow-redirect -u {url}'
    os.system(cms_detector_command)

    response = {'status': False, 'message': 'Could not detect CMS!'}
    parsed_url = urlparse(url)

    domain_name = parsed_url.hostname
    find_dir = domain_name

    if port := parsed_url.port:
        find_dir += f'_{port}'

    # subdomain may also have port number, and is stored in dir as _port

    cms_dir_path =  f'/home/rengine/tools/.github/CMSeeK/Result/{find_dir}'
    cms_json_path = f'{cms_dir_path}/cms.json'

    if os.path.isfile(cms_json_path):
        with open(cms_json_path, 'r') as file:
            cms_file_content = json.loads(file.read())
        if not cms_file_content.get('cms_id'):
            return response
        response = cms_file_content
        response['status'] = True
        # remove cms dir path
        try:
            shutil.rmtree(cms_dir_path)
        except Exception as e:
            print(e)

    return response 