from reNgine.utils.logger import Logger
import debugpy
from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT

logger = Logger(True)

def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.info(
                f"\n⚡ Debugger started on port {str(CELERY_REMOTE_DEBUG_PORT)}"
                + ", task is waiting IDE (VSCode ...) to be attached to continue ⚡\n"
            )
            # os.environ['GEVENT_SUPPORT'] = 'True'
            if not debugpy.is_client_connected():
                debugpy.listen(('0.0.0.0',CELERY_REMOTE_DEBUG_PORT))
            debugpy.wait_for_client(timeout=30)
    except Exception as e:
        logger.error(e)