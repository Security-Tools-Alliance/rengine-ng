from reNgine.celery import app
from reNgine.utils.command_executor import run_command


@app.task(name='run_command_line', bind=False, queue='run_command_queue')
def run_command_line(cmd, **kwargs):
    return run_command(cmd, **kwargs)
