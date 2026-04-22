from django.conf import settings
from django.shortcuts import render
from django.template import RequestContext
from django.utils.module_loading import import_string

from reNgine.utilities.logger import get_module_logger


PREFIX_COMMON_VIEWS = "[COMMON_VIEWS]"
logger = get_module_logger(__name__)


def bad_request(request, exception=None):
    """
    Custom 400 error handler
    """
    if exception is not None:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "BAD_REQUEST",
            "Bad request from %s: %s" % (request.META.get("REMOTE_ADDR", "Unknown"), exception),
            level="warning",
        )
    else:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "BAD_REQUEST",
            "Bad request from %s" % (request.META.get("REMOTE_ADDR", "Unknown"),),
            level="warning",
        )

    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/bad_request.html", context.flatten(), status=400)


def permission_denied(request, exception=None):
    if exception is not None:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "PERMISSION_DENIED",
            "Permission denied for user %s: %s" % (request.user, exception),
            level="warning",
        )
    else:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "PERMISSION_DENIED",
            "Permission denied for user %s" % (request.user,),
            level="warning",
        )

    context = RequestContext(request)

    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]["OPTIONS"]["context_processors"]:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))

    return render(request, "common/permission_denied.html", context.flatten(), status=403)


def page_not_found(request, exception=None):
    if exception is not None:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "PAGE_NOT_FOUND",
            "Page not found: %s - %s" % (request.path, exception),
            level="warning",
        )
    else:
        logger.log_line(
            PREFIX_COMMON_VIEWS,
            "PAGE_NOT_FOUND",
            "Page not found: %s" % (request.path,),
            level="warning",
        )

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
