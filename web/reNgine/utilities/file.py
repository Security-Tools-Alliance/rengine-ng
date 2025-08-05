import glob
import os
import shutil
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
        shell: Whether to use shell=True in run_command (deprecated)
        history_file: History file for logging (deprecated)
        scan_id: Scan ID for logging (deprecated)
        activity_id: Activity ID for logging (deprecated)
    Returns:
        bool: True if successful, False if error occurred
    """
    try:
        if pattern:
            # Find and remove files matching the pattern
            matched_files = glob.glob(os.path.join(path, pattern))
            if not matched_files:
                logger.warning(f"No files matching pattern '{pattern}' in {path}")
                return True
            
            all_deleted = True
            for file_path in matched_files:
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except OSError as e:
                    logger.error(f"Failed to delete '{file_path}': {e}")
                    all_deleted = False
            return all_deleted
        else:
            if not os.path.exists(path):
                logger.warning(f"Path {path} does not exist")
                return True
            
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
            return True
        
    except OSError as e:
        logger.error(f"Failed to delete {path}: {str(e)}")
        return False

def is_nuclei_config_valid(config_path):
    """
    Check if the Nuclei configuration file is not empty (has at least one non-commented line).
    
    Args:
        config_path (str): Path to the Nuclei configuration file
        
    Returns:
        bool: True if the config file has valid content, False otherwise
    """
    try:
        if not os.path.exists(config_path):
            return False
            
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Check if line is not empty and not a comment
                if line and not line.startswith('#'):
                    return True
        return False
    except Exception as e:
        logger.warning(f'Could not read Nuclei config file {config_path}: {e}')
        return False
