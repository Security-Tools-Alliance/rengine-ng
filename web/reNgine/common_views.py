import logging

from django.conf import settings
from django.shortcuts import render
from django.template import RequestContext
from django.utils.module_loading import import_string


logger = logging.getLogger(__name__)


def bad_request(request, exception=None):
    """
    Custom 400 error handler
    """
    if exception is not None:
        logger.warning(f"Bad request from {request.META.get('REMOTE_ADDR', 'Unknown')}: {exception}")
    else:
        logger.warning(f"Bad request from {request.META.get('REMOTE_ADDR', 'Unknown')}")

    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/bad_request.html", context.flatten(), status=400)


def permission_denied(request, exception=None):
    if exception is not None:
        logger.warning(f"Permission denied for user {request.user}: {exception}")
    else:
        logger.warning(f"Permission denied for user {request.user}")

    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/permission_denied.html", context.flatten(), status=403)


def page_not_found(request, exception=None):
    if exception is not None:
        logger.warning(f"Page not found: {request.path} - {exception}")
    else:
        logger.warning(f"Page not found: {request.path}")

    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/page_not_found.html", context.flatten(), status=404)


def server_error(request):
    """
    Custom 500 error handler that logs basic error information
    Note: Detailed error logging is now handled by CustomErrorMiddleware
    """
    # Return standard 500 error page
    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/server_error.html", context.flatten(), status=500)
