import os
import traceback
from pathlib import Path
from celery.utils.log import get_task_logger
from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT

logger = get_task_logger(__name__)


#-----------------#
# Misc Functions  #
#-----------------#

def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.info(
                f"\n⚡ Debugger started on port {str(CELERY_REMOTE_DEBUG_PORT)}"
                + ", task is waiting IDE (VSCode ...) to be attached to continue ⚡\n"
            )
            os.environ['GEVENT_SUPPORT'] = 'True'
            import debugpy
            debugpy.listen(('0.0.0.0',CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client()
    except Exception as e:
        logger.error(e)


def fmt_traceback(exc):
    return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
    path = results_dir
    if scan_history_id:
        path += f'/#{scan_history_id}'
        if subscan_id:
            path += f'-#{subscan_id}'
    path += f'-{task_name}.txt'
    return path

def get_and_save_emails(scan_history, activity_id, results_dir):
    """Get and save emails from Google, Bing and Baidu.

    Args:
        scan_history (startScan.ScanHistory): Scan history object.
        activity_id: ScanActivity Object
        results_dir (str): Results directory.

    Returns:
        list: List of emails found.
    """
    from reNgine.tasks.command import run_command
    from reNgine.utilities.database import save_email

    emails = []

    # Proxy settings
    # get_random_proxy()

    # Gather emails from Google, Bing and Baidu
    output_file = str(Path(results_dir) / 'emails_tmp.txt')
    history_file = str(Path(results_dir) / 'commands.txt')
    command = f'infoga --domain {scan_history.domain.name} --source all --report {output_file}'
    try:
        run_command(
            command,
            shell=False,
            history_file=history_file,
            scan_id=scan_history.id,
            activity_id=activity_id)

        if not os.path.isfile(output_file):
            logger.info('No Email results')
            return []

        with open(output_file) as f:
            for line in f:
                if 'Email' in line:
                    split_email = line.split(' ')[2]
                    emails.append(split_email)

        output_path = str(Path(results_dir) / 'emails.txt')
        with open(output_path, 'w') as output_file:
            for email_address in emails:
                save_email(email_address, scan_history)
                output_file.write(f'{email_address}\n')

    except Exception as e:
        logger.exception(e)
    return emails 