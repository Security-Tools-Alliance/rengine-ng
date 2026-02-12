"""
Worker WebSocket channel group names. Single source for producers and consumers.
No Django or app imports so this module can be loaded before settings are configured (e.g. ASGI bootstrap).
"""


def worker_deploy_group(worker_id: int) -> str:
    """Channel group name for worker deploy log stream."""
    return f"worker-deploy-{worker_id}"


def worker_refresh_group(worker_id: int) -> str:
    """Channel group name for worker refresh log stream."""
    return f"worker-refresh-{worker_id}"
