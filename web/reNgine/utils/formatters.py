import re
import traceback
import humanize
from pathlib import Path
from typing import List, Union
from django.utils import timezone
from reNgine.utils.logger import Logger
from reNgine.settings import DOMAIN_NAME, RENGINE_TASK_IGNORE_CACHE_KWARGS

logger = Logger(__name__)

class SafePath:
    """Utility class for safe path handling and directory creation."""
    
    @staticmethod
    def sanitize_component(component: str) -> str:
        """Sanitize a path component to prevent directory traversal.
        
        Args:
            component (str): Path component to sanitize
            
        Returns:
            str: Sanitized path component
        """
        # Remove any non-alphanumeric chars except safe ones
        return re.sub(r'[^a-zA-Z0-9\-\_\.]', '_', component)

    @classmethod
    def create_safe_path(
        cls,
        base_dir: Union[str, Path],
        components: List[str],
        create_dir: bool = True,
        mode: int = 0o755
    ) -> str:
        """Create a safe path within the base directory.
        
        Args:
            base_dir (str|Path): Base directory
            components (list): List of path components
            create_dir (bool): Whether to create the directory
            mode (int): Directory permissions if created
            
        Returns:
            str: Safe path object
            
        Raises:
            ValueError: If path would be outside base directory
            OSError: If directory creation fails
        """
        try:
            # Convert to Path objects
            base_path = Path(base_dir).resolve()
            
            # Sanitize all components
            safe_components = [cls.sanitize_component(c) for c in components]
            
            # Build full path
            full_path = base_path.joinpath(*safe_components)
            
            # Resolve to absolute path
            abs_path = full_path.resolve()
            
            # Check if path is within base directory
            if not str(abs_path).startswith(str(base_path)):
                raise ValueError(
                    f"Invalid path: {abs_path} is outside base directory {base_path}"
                )
            
            # Create directory if requested
            if create_dir:
                abs_path.mkdir(parents=True, mode=mode, exist_ok=True)
                logger.debug(f"Created directory: {abs_path}")
                
            return str(abs_path)
            
        except Exception as e:
            logger.error(f"Error creating safe path: {str(e)}")
            raise

    @classmethod
    def is_safe_path(cls, base_dir: Union[str, Path], path: Union[str, Path], follow_symlinks: bool = True) -> bool:
        """Enhanced version of is_safe_path that uses pathlib.
        Maintains compatibility with existing code while adding more security."""
        try:
            base_path = Path(base_dir).resolve()
            check_path = Path(path)

            check_path = check_path.resolve() if follow_symlinks else check_path.absolute()
            return str(check_path).startswith(str(base_path))
        except Exception:
            return False

def get_scan_url(scan_id=None, subscan_id=None):
    return f'https://{DOMAIN_NAME}/scan/detail/{scan_id}' if scan_id else None

def get_scan_title(scan_id, subscan_id=None, task_name=None):
    return f'Subscan #{subscan_id} summary' if subscan_id else f'Scan #{scan_id} summary'

def get_scan_fields(engine, scan, subscan=None, status='RUNNING', tasks=None):
    if tasks is None:
        tasks = []
    scan_obj = subscan or scan
    if subscan:
        tasks_h = f'`{subscan.type}`'
        host = subscan.subdomain.name
        scan_obj = subscan
    else:
        tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''
        host = scan.domain.name
        scan_obj = scan

    # Find scan elapsed time
    duration = None
    if scan_obj:
        if status in ['ABORTED', 'FAILED', 'SUCCESS']:
            td = scan_obj.stop_scan_date - scan_obj.start_scan_date
        else:
            td = timezone.now() - scan_obj.start_scan_date
        duration = humanize.naturaldelta(td)
    # Build fields
    url = get_scan_url(scan.id)
    fields = {
        'Status': f'**{status}**',
        'Engine': engine.engine_name,
        'Scan ID': f'[#{scan.id}]({url})'
    }

    if subscan:
        url = get_scan_url(scan.id, subscan.id)
        fields['Subscan ID'] = f'[#{subscan.id}]({url})'

    if duration:
        fields['Duration'] = duration

    fields['Host'] = host
    if tasks:
        fields['Tasks'] = tasks_h

    return fields

def get_task_title(task_name, scan_id=None, subscan_id=None):
    if scan_id:
        prefix = f'#{scan_id}'
        if subscan_id:
            prefix += f'-#{subscan_id}'
        return f'`{prefix}` - `{task_name}`'
    return f'`{task_name}` [unbound]'


def get_task_header_message(name, scan_history_id, subscan_id):
    msg = f'`{name}` [#{scan_history_id}'
    if subscan_id:
        msg += f'_#{subscan_id}]'
    msg += 'status'
    return msg


def get_task_cache_key(func_name, *args, **kwargs):
    args_str = '_'.join([str(arg) for arg in args])
    kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
    return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, subscan_id, filename):
    title = f'{scan_history_id}'
    if subscan_id:
        title += f'-{subscan_id}'
    title += f'_{filename}'
    return title


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
    path = results_dir
    if scan_history_id:
        path += f'/#{scan_history_id}'
        if subscan_id:
            path += f'-#{subscan_id}'
    path += f'-{task_name}.txt'
    return path

def fmt_traceback(exc):
    return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))
