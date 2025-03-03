from pathlib import Path

from reNgine.definitions import HTTP_CRAWL
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_builder import build_httpx_cmd
from reNgine.utils.command_executor import stream_command
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.http import get_subdomain_from_url, prepare_urls_for_http_scan
from reNgine.utils.parsers import parse_httpx_result
from reNgine.utils.task_config import TaskConfig
from reNgine.utils.utils import remove_file_or_pattern
from reNgine.tasks.url import remove_duplicate_endpoints

from startScan.models import Subdomain


@app.task(name='http_crawl', queue='io_queue', base=RengineTask, bind=True)
def http_crawl(self, urls=None, method=None, recrawl=False, ctx=None, track=True, 
               description=None, update_subdomain_metadatas=False, 
               should_remove_duplicate_endpoints=True, duplicate_removal_fields=None):
    """Use httpx to query HTTP URLs for important info like page titles, http status, etc.
    
    Args:
        urls (list, optional): URLs to check
        method (str): HTTP method to use
        recrawl (bool, optional): If False, filter out URLs already crawled
        should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
        duplicate_removal_fields (list): Fields to check for duplicates
    """
    # Initialize context, config, and defaults
    result = initialize_http_crawl(self, urls, ctx, duplicate_removal_fields, recrawl)
    if not result:
        return []
    
    config, task_config, input_path, urls, update_subdomain_metadatas = result
    
    # Build and execute the command
    cmd = build_httpx_cmd(config, urls, method, task_config.get('threads', 10))
    
    # Process the results
    results = process_http_results(
        self, cmd, input_path, config.get_task_config()['follow_redirect'], 
        update_subdomain_metadatas, ctx
    )
    
    # Clean up and post-processing
    if should_remove_duplicate_endpoints and results:
        remove_duplicate_endpoints(
            self.scan_id, self.domain_id, self.subdomain_id,
            filter_ids=[r.get('endpoint_id') for r in results if 'endpoint_id' in r]
        )
    
    remove_file_or_pattern(input_path, history_file=self.history_file,
                          scan_id=self.scan_id, activity_id=self.activity_id)
    
    return results

def initialize_http_crawl(self, urls, ctx, duplicate_removal_fields, recrawl):
    """Initialize HTTP crawl parameters and prepare URLs
    
    Returns:
        tuple: (config, task_config, input_path, urls, update_subdomain_metadatas)
        or None if no URLs found
    """
    if ctx is None:
        ctx = {}
    if duplicate_removal_fields is None:
        duplicate_removal_fields = []
        
    logger.info('🌐 Initiating HTTP Crawl')
    
    config = TaskConfig(ctx, HTTP_CRAWL)
    task_config = config.get_task_config()
    
    urls, input_path, subdomain_metadata_update = prepare_urls_for_http_scan(
        urls, self.url_filter, self.results_dir, ctx, recrawl
    )
    
    if not urls:
        logger.warning('🌐 No URLs to crawl. Skipping.')
        return None
        
    return config, task_config, input_path, urls, subdomain_metadata_update

def process_http_results(self, cmd, input_path, follow_redirect, update_subdomain_metadatas, ctx):
    """Process HTTP crawl results
    
    Returns:
        list: Processed results
    """
    results = []
    endpoint_ids = []

    if not Path(input_path).exists():
        logger.error(f'📁 HTTP input file missing: {input_path}')
        return []

    for line in stream_command(cmd, history_file=self.history_file,
                              scan_id=self.scan_id, activity_id=self.activity_id):
        # Skip invalid lines
        if not line or not isinstance(line, dict) or line.get('failed', False):
            continue

        # Check for errors
        if 'error' in line:
            logger.error(line)
            continue

        if endpoint_data := process_http_line(
            self, line, cmd, follow_redirect, update_subdomain_metadatas, ctx
        ):
            results.append(endpoint_data['result'])
            endpoint_ids.append(endpoint_data['endpoint_id'])

    return results

def process_http_line(self, line, cmd, follow_redirect, update_subdomain_metadatas, ctx):
    """Process a single HTTP result line
    
    Returns:
        dict: Processed endpoint data or None if invalid
    """
    from reNgine.utils.db import save_subdomain
    
    # Get subdomain from URL
    subdomain_name = get_subdomain_from_url(line.get('url', ''))
    subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
    
    if not isinstance(subdomain, Subdomain):
        logger.error(f"🌐 Invalid subdomain encountered: {subdomain}")
        return None
        
    # Process the line and get results
    endpoint, endpoint_str, result_data = parse_httpx_result(
        line, subdomain, ctx, follow_redirect, 
        update_subdomain_metadatas, self.subscan
    )
    
    if not endpoint:
        return None
        
    # Log and notify about the endpoint
    logger.info(f'🌐 {endpoint_str}')
    
    notify_findings(self, endpoint, endpoint_str, result_data)
    
    # Add the results
    line['_cmd'] = cmd
    line['endpoint_id'] = endpoint.id
    line.update(result_data)
    
    return {
        'result': line,
        'endpoint_id': endpoint.id
    }

def notify_findings(self, endpoint, endpoint_str, result_data):
    """Send notification for alive endpoint
    
    Args:
        self: Task instance with notify method
        endpoint_str (str): Endpoint string
    """
    if endpoint.is_alive:
        send_notification(
            self, 
            'Alive endpoint', 
            endpoint_str
        )

    # Notification for technologies
    if result_data['techs']:
        send_notification(
            self,
            'Technologies',
            result_data['techs'],
            format_as_code=True,
            use_bullet_points=False
        )

    # Notification for IPs (A records)
    if result_data['a_records']:
        send_notification(
            self,
            'IPs',
            result_data['a_records'],
            format_as_code=True
        )

    # Notification for host IP
    if result_data['host']:
        send_notification(
            self,
            'IPs',
            result_data['host'],
            format_as_code=True
        )

def send_notification(self, field_name, data, add_meta_info=False, format_as_code=False, use_bullet_points=True):
    """Send formatted notification with consistent styling
    
    Args:
        self: Task instance with notify method
        field_name (str): Name of the field to display in notification
        data: Data to display (str, list, or dict)
        add_meta_info (bool): Whether to add metadata to notification
        format_as_code (bool): Whether to format values as code with backticks
        use_bullet_points (bool): Whether to format list items with bullet points
        
    Returns:
        None
    """
    if not hasattr(self, 'notify') or not data:
        return

    # Format the data based on its type
    if isinstance(data, list):
        # Format list of items
        items = [f'`{item}`' for item in data] if format_as_code else data
        if use_bullet_points:
            formatted_data = (
                f'• {items[0]}'
                if len(items) == 1
                else '• ' + '\n• '.join(items)
            )
        else:
            formatted_data = ', '.join(items)
    elif isinstance(data, dict):
        # Format dictionary values
        formatted_data = ', '.join([f'{k}: {v}' for k, v in data.items()])
    elif format_as_code:
        formatted_data = f'`{data}`'
    else:
        formatted_data = f'• {data}' if use_bullet_points else str(data)
    # Send the notification
    self.notify(
        fields={field_name: formatted_data},
        add_meta_info=add_meta_info
    )
