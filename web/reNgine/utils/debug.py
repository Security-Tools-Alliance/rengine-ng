import os
import threading
import debugpy
from reNgine.utils.logger import Logger
from reNgine.settings import CELERY_REMOTE_DEBUG, CELERY_REMOTE_DEBUG_PORT

logger = Logger(True)

def debug():
    try:
        # Activate remote debug for scan worker
        if CELERY_REMOTE_DEBUG:
            logger.info(
                f"\n⚡ Debugger started on port {str(CELERY_REMOTE_DEBUG_PORT)}"
                + ", task is waiting 10 seconds for IDE (VSCode ...) to be attached to continue ⚡\n"
            )
            os.environ['GEVENT_SUPPORT'] = 'True'
            if not debugpy.is_client_connected():
                debugpy.listen(('0.0.0.0', CELERY_REMOTE_DEBUG_PORT))
                def wait_for_client_with_timeout():
                    debugpy.wait_for_client()
                attach_thread = threading.Thread(target=wait_for_client_with_timeout, daemon=True)
                attach_thread.start()
                attach_thread.join(timeout=10)  # Wait up to 10 seconds for the debugger client to attach
                if not debugpy.is_client_connected():
                    logger.warning("No debugger client attached within timeout. Continuing execution without debugger.")


    except Exception as e:
        logger.error(e)