from pathlib import Path

from reNgine.definitions import SCREENSHOT
from reNgine.settings import RENGINE_RESULTS
from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.utils.command_builder import build_eyewitness_cmd
from reNgine.utils.formatters import get_output_file_name
from reNgine.utils.http import prepare_urls_with_fallback
from reNgine.utils.logger import Logger
from reNgine.utils.task_config import TaskConfig
from reNgine.utils.utils import extract_columns, remove_file_or_pattern
from scanEngine.models import Notification
from startScan.models import Subdomain
from reNgine.tasks.command import run_command_line
from reNgine.tasks.notification import send_file_to_discord

logger = Logger(True)

@app.task(name='screenshot', queue='io_queue', base=RengineTask, bind=True)
def screenshot(self, ctx=None, description=None):
    """Uses EyeWitness to gather screenshot of a domain and/or url.

    Args:
        description (str, optional): Task description shown in UI.
    """
 
    if ctx is None:
        ctx = {}
    # Config
    config = TaskConfig(ctx, SCREENSHOT)
    task_config = config.get_task_config()

    # If intensity is normal, grab only the root endpoints of each subdomain
    strict = task_config['intensity'] == 'normal'

    # Get URLs to take screenshot of
    urls = prepare_urls_with_fallback(
        is_alive=True,
        strict=strict,
        write_filepath=task_config['alive_endpoints_file'],
        get_only_default_urls=True,
        ctx=ctx
    )
    if not urls:
        logger.error('📸 No URLs to take screenshot of. Skipping.')
        return

    # Send start notif
    notification = Notification.objects.first()
    send_output_file = notification.send_scan_output_file if notification else False

    # Run cmd
    cmd = build_eyewitness_cmd(config)

    run_command_line.delay(
        cmd,
        shell=False,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )
    if not Path(csv := config.get_working_dir(filename=self.filename)).exists():
        logger.error(f'📸 EyeWitness output file missing : {csv}')
        return

    # Loop through results and save objects in DB
    screenshot_paths = []
    with open(csv, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)  # Skip header row
        indices = [header.index(col) for col in ["Protocol", "Port", "Domain", "Request Status", "Screenshot Path", " Source Path"]]
        for row in reader:
            protocol, port, subdomain_name, status, screenshot_path, source_path = extract_columns(row, indices)
            subdomain_query = Subdomain.objects.filter(name=subdomain_name)
            if self.scan:
                subdomain_query = subdomain_query.filter(scan_history=self.scan)
            if status == 'Successful' and subdomain_query.exists():
                subdomain = subdomain_query.first()
                screenshot_paths.append(screenshot_path)
                subdomain.screenshot_path = screenshot_path.replace(RENGINE_RESULTS, '')
                subdomain.save()
                logger.warning(f'📸 Added screenshot for {protocol}://{subdomain.name}:{port} to DB')


    # Remove all db, html extra files in screenshot results
    patterns = ['*.csv', '*.db', '*.js', '*.html', '*.css']
    for pattern in patterns:
        remove_file_or_pattern(
            task_config['screenshots_path'],
            pattern=pattern,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id
        )

    # Delete source folder
    remove_file_or_pattern(
        str(Path(task_config['screenshots_path']) / 'source'),
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id
    )

    # Send finish notifs
    screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
    self.notify(fields={'Screenshots': screenshots_str})
    if send_output_file:
        for path in screenshot_paths:
            title = get_output_file_name(
                self.scan_id,
                self.subscan_id,
                self.filename)
            send_file_to_discord.delay(path, title)
