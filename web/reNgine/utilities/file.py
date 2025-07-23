import glob
import os
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


#------------------#
# File Operations  #
#------------------#

def remove_file_or_pattern(path, pattern=None, shell=True, history_file=None, scan_id=None, activity_id=None):
    """
    Safely removes a file/directory or pattern matching files
    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")
        shell: Whether to use shell=True in run_command
        history_file: History file for logging
        scan_id: Scan ID for logging
        activity_id: Activity ID for logging
    Returns:
        bool: True if successful, False if error occurred
    """
    from reNgine.tasks.command import run_command
    
    try:
        if pattern:
            # Check for files matching the pattern
            match_count = len(glob.glob(os.path.join(path, pattern)))
            if match_count == 0:
                logger.warning(f"No files matching pattern '{pattern}' in {path}")
                return True
            full_path = os.path.join(path, pattern)
        else:
            if not os.path.exists(path):
                logger.warning(f"Path {path} does not exist")
                return True
            full_path = path

        # Execute secure command
        run_command(
            f'rm -rf {full_path}',
            shell=shell,
            history_file=history_file,
            scan_id=scan_id,
            activity_id=activity_id
        )
        return True
    except Exception as e:
        logger.error(f"Failed to delete {full_path}: {str(e)}")
        return False 