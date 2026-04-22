from __future__ import annotations

from django import template

from scanEngine.models import SecatorWorker


register = template.Library()


@register.filter(name="worker_is_pull_only")
def worker_is_pull_only(worker: object) -> bool:
    """True if worker is HTTPS classic + pull-agent (SSH actions disabled)."""
    uses = getattr(worker, "uses_https_pull_agent", None)
    if callable(uses):
        return bool(uses())
    https_pull_agent = bool(getattr(worker, "https_pull_agent", False))
    api_access_type = getattr(worker, "api_access_type", None)
    return api_access_type == SecatorWorker.API_ACCESS_CLASSIC and https_pull_agent
