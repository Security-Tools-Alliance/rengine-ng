from reNgine.celery import app
from reNgine.utils.command_executor import run_command
from reNgine.utils.logger import Logger

logger = Logger(True)

@app.task(name='run_command_line', bind=False, queue='run_command_queue')
def run_command_line(cmd, **kwargs):
    if not cmd:
        logger.error('🚫 Empty command received')
        return
    return run_command(cmd, **kwargs)
