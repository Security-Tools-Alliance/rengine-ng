import random
import re

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
    proxy = Proxy.objects.filter(use_proxy=True).order_by('?').first()
    if not proxy:
        return ''
    proxy_name = random.choice(proxy.proxies.splitlines())
    logger.warning(f'Using proxy: {proxy_name}')
    # os.environ['HTTP_PROXY'] = proxy_name
    # os.environ['HTTPS_PROXY'] = proxy_name
    return proxy_name


def remove_ansi_escape_sequences(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)
