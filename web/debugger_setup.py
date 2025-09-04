import os
import socket

from reNgine.settings import UI_REMOTE_DEBUG_PORT


def is_port_in_use(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def setup_debugger(wait=False, gevent="False"):
    import debugpy

    if UI_REMOTE_DEBUG_PORT > 0:
        # Prevent to set breakpoitn in VSCode - https://stackoverflow.com/a/66714620
        # But seems to be needed while debugging workers
        os.environ["GEVENT_SUPPORT"] = gevent
        if not is_port_in_use(UI_REMOTE_DEBUG_PORT):
            try:
                debugpy.listen(("0.0.0.0", UI_REMOTE_DEBUG_PORT))
                print("\n⚡ Debugger started on port " + str(UI_REMOTE_DEBUG_PORT) + " ⚡\n")
                if wait:
                    debugpy.wait_for_client()
            except Exception as e:
                print(f"Failed to start debugger: {e}")
        else:
            print("\n⚠️  Debugger already started on port " + str(UI_REMOTE_DEBUG_PORT) + " ⚠️\n")
