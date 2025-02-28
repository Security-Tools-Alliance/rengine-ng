import os
import glob
from reNgine.utils.logger import Logger
import shutil

logger = Logger(True)

def is_safe_path(basedir, path, follow_symlinks=True):
    # Source: https://security.openstack.org/guidelines/dg_using-file-paths.html
    # resolves symbolic links
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


# Source: https://stackoverflow.com/a/10408992
def remove_lead_and_trail_slash(s):
    if s.startswith('/'):
        s = s[1:]
    if s.endswith('/'):
        s = s[:-1]
    return s


def get_time_taken(latest, earlier):
    duration = latest - earlier
    days, seconds = duration.days, duration.seconds
    hours = days * 24 + seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    if not hours and not minutes:
        return f'{seconds} seconds'
    elif not hours:
        return f'{minutes} minutes'
    elif not minutes:
        return f'{hours} hours'
    return f'{hours} hours {minutes} minutes'

# Check if value is a simple string, a string with commas, a list [], a tuple (), a set {} and return an iterable
def return_iterable(string):
    if not isinstance(string, (list, tuple)):
        string = [string]

    return string

def replace_nulls(obj):
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    elif isinstance(obj, list):
        return [replace_nulls(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: replace_nulls(value) for key, value in obj.items()}
    else:
        return obj



def get_gpt_vuln_input_description(title, path):
    vulnerability_description = ''
    vulnerability_description += f'Vulnerability Title: {title}'
    # gpt gives concise vulnerability description when a vulnerable URL is provided
    vulnerability_description += f'\nVulnerable URL: {path}'

    return vulnerability_description

def remove_file_or_pattern(path, pattern=None, history_file=None, scan_id=None, activity_id=None):
    """
    Safely removes a file/directory or pattern matching files
    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")
        history_file: History file for logging
        scan_id: Scan ID for logging
        activity_id: Activity ID for logging
    Returns:
        bool: True if successful, False if error occurred
    """
    try:
        if pattern:
            # Check for files matching the pattern
            matching_files = glob.glob(os.path.join(path, pattern))
            if not matching_files:
                logger.warning(f"📁 No files matching pattern '{pattern}' in {path}")
                return True
                
            # Remove each matching file individually
            for file_path in matching_files:
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
        else:
            if not os.path.exists(path):
                logger.warning(f"📁 Path {path} does not exist")
                return True
                
            # Remove file or directory
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
                
        return True
    except Exception as e:
        full_path = os.path.join(path, pattern) if pattern else path
        logger.error(f"📁 Failed to delete {full_path}: {str(e)}")
        return False

def check_process_status(pid):
    try:
        os.kill(pid, 0)  # Check if process exists
        with open(f"/proc/{pid}/status") as f:
            status = f.read()
            return 'running' if 'R (running)' in status else 'sleeping'
    except (ProcessLookupError, FileNotFoundError):
        return 'dead'

def is_iterable(variable):
    try:
        iter(variable)
        return True
    except TypeError:
        return False

def safe_int_cast(value, default=None):
    """
    Convert a value to an integer if possible, otherwise return a default value.

    Args:
        value: The value or the array of values to convert to an integer.
        default: The default value to return if conversion fails.

    Returns:
        int or default: The integer value if conversion is successful, otherwise the default value.
    """
    if isinstance(value, list):
        return [safe_int_cast(item) for item in value]
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def extract_columns(row, columns):
    """
    Extract specific columns from a row based on column indices.
    
    Args:
        row (list): The CSV row as a list of values.
        columns (list): List of column indices to extract.
    
    Returns:
        list: Extracted values from the specified columns.
    """
    return [row[i] for i in columns]

def extract_between(text, pattern):
    match = pattern.search(text)
    return match.group(1).strip() if match else ""
