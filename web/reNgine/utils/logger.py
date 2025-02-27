import logging
from celery.utils.log import get_task_logger
from celery import current_task

class Logger:
    def __init__(self, is_task_logger=False):
        self.is_task_logger = is_task_logger
        if is_task_logger:
            self.logger = get_task_logger(__name__)
        else:
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(level=logging.INFO)

    def info(self, message):
        """Log an info message."""
        self._log(message, 'INFO')

    def warning(self, message):
        """Log a warning message."""
        self._log(message, 'WARNING')

    def error(self, message):
        """Log an error message."""
        self._log(message, 'ERROR')

    def debug(self, message):
        self._log(message, 'DEBUG')

    def exception(self, message):
        """Log an exception message."""
        self._log(message, 'ERROR')

    def _log(self, message, level):
        task_name = current_task.name if self.is_task_logger else ''
        formatted_message = f"{task_name:<35} | {level:<8} | {message}"
        print(formatted_message, flush=True)
