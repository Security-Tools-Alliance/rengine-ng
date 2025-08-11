from celery.utils.log import ColorFormatter
from celery._state import get_current_task


#--------------#
# Logging utils #
#--------------#

class RengineTaskFormatter(ColorFormatter):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.get_current_task = get_current_task
        except ImportError:
            self.get_current_task = lambda: None

    def format(self, record):
        task = self.get_current_task()
        if task and task.request:
            task_name = '/'.join(task.name.replace('tasks.', '').split('.'))
            record.__dict__.update(task_id=task.request.id,
                                   task_name=task_name)
        else:
            record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
            record.__dict__.setdefault('task_id', '')
        return super().format(record) 