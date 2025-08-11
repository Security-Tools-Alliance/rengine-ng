from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


#-----------#
# Time utils #
#-----------#

def get_time_taken(latest, earlier):
    duration = latest - earlier
    days, seconds = duration.days, duration.seconds
    hours = days * 24 + seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    if hours and minutes:
        return f'{hours} hours {minutes} minutes'
    elif hours:
        return f'{hours} hours'
    elif minutes:
        return f'{minutes} minutes'
    return f'{seconds} seconds'