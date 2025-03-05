import json
import os
from redis import Redis

from reNgine.settings import RENGINE_CACHE_ENABLED
from reNgine.utils.formatters import get_task_cache_key, format_json_output
from reNgine.utils.logger import default_logger as logger

# Initialize cache connection
cache = None
if 'CELERY_BROKER' in os.environ:
    cache = Redis.from_url(os.environ['CELERY_BROKER'])

def check_task_cache(task_name, *args, **kwargs):
    """Check if a task result exists in cache.
    
    This function is used by both individual tasks and grouped tasks
    to avoid code duplication and ensure consistent caching behavior.
    
    Args:
        task_name: Name of the task
        *args: Task args
        **kwargs: Task kwargs
        
    Returns:
        tuple: (cached_result, cache_key) - both None if cache disabled or miss
    """
    if not RENGINE_CACHE_ENABLED or not cache:
        return None, None
        
    cache_key = get_task_cache_key(task_name, *args, **kwargs)
    result = cache.get(cache_key)
    
    if result and result != b'null':
        try:
            return json.loads(result), cache_key
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in cache for key {cache_key}")
            
    return None, cache_key

def set_to_cache(cache_key, result, expire_time=600):
    """Store task result in cache.
    
    Args:
        cache_key: Key to store result under
        result: Result data to store (will be JSON-serialized)
        expire_time: Cache expiration time in seconds (default: 10 minutes)
        
    Returns:
        bool: True if successfully stored, False otherwise
    """
    if not RENGINE_CACHE_ENABLED or not cache or not cache_key:
        return False
        
    try:
        serialized_result = format_json_output(result)
        cache.set(cache_key, serialized_result)
        cache.expire(cache_key, expire_time)
        return True
    except Exception as e:
        logger.warning(f"Error storing result in cache: {str(e)}")
        return False 