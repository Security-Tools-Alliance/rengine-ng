"""
Remote debugger setup (debugpy) for reNgine-ng.

The debugger binds to a configurable host/port. By default it listens on 127.0.0.1
(localhost only) for security. Previously the default was 0.0.0.0 (all interfaces).

Environment:
- RENGINE_DEBUG_HOST: Host to bind the debugger to. Default: 127.0.0.1.
  Set to 0.0.0.0 to allow remote debugging (attach from another machine).
  Existing remote setups that assumed binding on all interfaces must set
  RENGINE_DEBUG_HOST=0.0.0.0 explicitly.
- UI_REMOTE_DEBUG_PORT (from settings): Port number, e.g. 5678.
"""

import os
import socket

from reNgine.settings import UI_REMOTE_DEBUG_PORT


DEFAULT_DEBUG_HOST = "127.0.0.1"


def is_port_in_use(port, host=None):
    if host is None:
        host = DEFAULT_DEBUG_HOST
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
        debug_host = os.environ.get("RENGINE_DEBUG_HOST", DEFAULT_DEBUG_HOST)
        if not is_port_in_use(UI_REMOTE_DEBUG_PORT, debug_host):
            try:
                debugpy.listen((debug_host, UI_REMOTE_DEBUG_PORT))
                print("\n⚡ Debugger started on " + debug_host + ":" + str(UI_REMOTE_DEBUG_PORT) + " ⚡\n")
                if wait:
                    debugpy.wait_for_client()
            except Exception as e:
                print(f"Failed to start debugger: {e}")
        else:
            print("\n⚠️  Debugger already started on " + debug_host + ":" + str(UI_REMOTE_DEBUG_PORT) + " ⚠️\n")
