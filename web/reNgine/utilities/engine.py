import os
import re
import uuid
import yaml
from celery.utils.log import get_task_logger
from scanEngine.models import EngineType
from reNgine.settings import RENGINE_HOME
from reNgine.definitions import (
    COMMON_WEB_PORTS,
    HTTP_CRAWL,
    HTTP_FOLLOW_REDIRECT,
    HTTP_PRE_CRAWL_ALL_PORTS,
    HTTP_PRE_CRAWL_BATCH_SIZE,
    HTTP_PRE_CRAWL_UNCOMMON_PORTS,
    HTTP_THREADS,
)

logger = get_task_logger(__name__)


#------------------#
# EngineType utils #
#------------------#

def sanitize_filename(name):
    """Sanitize a string to be safe for use as a filename.
    
    Args:
        name (str): Original name.
        
    Returns:
        str: Sanitized filename-safe string.
    """
    # Replace invalid filename characters with underscores


    sanitized = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(' .')
    if not sanitized:
        unique_suffix = uuid.uuid4().hex[:8]
        sanitized = f"untitled_{unique_suffix}"
        logger.warning("Sanitized filename was empty. Defaulted to '%s'.", sanitized)
    return sanitized

def dump_custom_scan_engines(results_dir):
    """Dump custom scan engines to YAML files.

    Args:
        results_dir (str): Results directory (will be created if non-existent).
    """
    custom_engines = EngineType.objects.filter(default_engine=False)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    for engine in custom_engines:
        safe_name = sanitize_filename(engine.engine_name)
        with open(f'{results_dir}/{safe_name}.yaml', 'w') as f:
            f.write(engine.yaml_configuration)


def load_custom_scan_engines(results_dir):
    """Load custom scan engines from YAML files. The filename without .yaml will
    be used as the engine name.

    Args:
        results_dir (str): Results directory containing engines configs.
    """
    config_paths = [
        f for f in os.listdir(results_dir)
        if os.path.isfile(os.path.join(results_dir, f)) and f.endswith('.yaml')
    ]
    for path in config_paths:
        engine_name = os.path.splitext(os.path.basename(path))[0]
        full_path = os.path.join(results_dir, path)
        with open(full_path, 'r') as f:
            yaml_configuration = f.read()

        engine, _ = EngineType.objects.get_or_create(engine_name=engine_name)
        engine.yaml_configuration = yaml_configuration
        engine.save()


def load_default_yaml_config():
    """Load the default YAML configuration
    
    Returns:
        dict: Default configuration.
    """
    return {
        'threads': HTTP_THREADS,
        'follow_redirect': HTTP_FOLLOW_REDIRECT,
        'precrawl_ports': COMMON_WEB_PORTS,
        'precrawl_uncommon_ports': HTTP_PRE_CRAWL_UNCOMMON_PORTS,
        'precrawl_all_ports': HTTP_PRE_CRAWL_ALL_PORTS,
        'precrawl_batch_size': HTTP_PRE_CRAWL_BATCH_SIZE
    }


def get_http_crawl_config_with_defaults(user_yaml_config):
    """Get HTTP crawl configuration with defaults merged in.
    
    Args:
        user_yaml_config (dict): User's YAML configuration.
        
    Returns:
        dict: HTTP crawl configuration with defaults applied.
    """
    # Get user's http_crawl configuration
    user_http_crawl = user_yaml_config.get(HTTP_CRAWL, {})

    # Define reasonable defaults for HTTP crawl if not in default config
    default_config = load_default_yaml_config()

    # Merge in this order: default_config -> user_config
    merged_config = {}
    merged_config |= default_config
    merged_config.update(user_http_crawl)

    logger.debug(f'HTTP crawl config merged: {len(merged_config)} parameters configured')
    return merged_config


def get_crawl_config_safe(task_instance, config_key=HTTP_CRAWL):
    """Safely get crawl configuration from task with fallback to defaults.
    
    Args:
        task_instance: Celery task instance with yaml_configuration attribute.
        config_key (str): Configuration key to retrieve (default: 'http_crawl').
        
    Returns:
        dict: Configuration with defaults applied.
    """
    try:
        # Handle case where yaml_configuration might be a string instead of dict
        yaml_config = task_instance.yaml_configuration
        if isinstance(yaml_config, str):
            try:
                yaml_config = yaml.safe_load(yaml_config)
            except Exception as e:
                logger.warning(f'Failed to parse YAML configuration: {e}')
                yaml_config = {}

        if not isinstance(yaml_config, dict):
            logger.warning(f'Invalid yaml_configuration type: {type(yaml_config)}, using empty dict')
            yaml_config = {}

        # Get crawl-specific configuration
        if config_key == HTTP_CRAWL:
            return get_http_crawl_config_with_defaults(yaml_config)
        else:
            # For other config keys, just return user config with empty dict fallback
            return yaml_config.get(config_key, {})

    except Exception as e:
        logger.error(f'Error getting crawl config: {e}')
        # Return reasonable defaults for http_crawl
        return load_default_yaml_config() if config_key == HTTP_CRAWL else {} 