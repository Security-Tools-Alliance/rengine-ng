import logging
import traceback

from django.http import HttpResponseServerError
from django.template.loader import render_to_string

from reNgine.settings import DEBUG, UI_ERROR_LOGGING


logger = logging.getLogger(__name__)


class CustomErrorMiddleware:
    """
    Custom middleware to handle 500 errors and display custom error page
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        """
        Process exceptions and return custom 500 error page
        """

        # In debug mode, let Django handle the exception with its debug page
        if DEBUG:
            return None

        # Log detailed error information if UI_ERROR_LOGGING is enabled
        if UI_ERROR_LOGGING:
            try:
                # Safely extract error information
                error_type = type(exception).__name__ if exception else "UnknownError"
                error_message = str(exception) if exception else "Unknown error occurred"

                # Safely get traceback
                try:
                    error_traceback = "".join(
                        traceback.format_exception(type(exception), exception, exception.__traceback__)
                    )
                except (AttributeError, TypeError):
                    error_traceback = "Traceback not available"

                # Safely get request information
                try:
                    user_info = str(request.user) if hasattr(request, "user") and request.user else "Anonymous"
                except (AttributeError, TypeError):
                    user_info = "Anonymous"

                try:
                    ip_address = request.META.get("REMOTE_ADDR", "Unknown")
                except (AttributeError, TypeError):
                    ip_address = "Unknown"

                try:
                    request_path = request.path if hasattr(request, "path") else "Unknown"
                    request_method = request.method if hasattr(request, "method") else "Unknown"
                except (AttributeError, TypeError):
                    request_path = "Unknown"
                    request_method = "Unknown"

                error_details = {
                    "type": error_type,
                    "message": error_message,
                    "traceback": error_traceback,
                    "path": request_path,
                    "method": request_method,
                    "user": user_info,
                    "ip": ip_address,
                }

                # Log detailed error information
                logger.error(f"500 Error Details: {error_details}")

                # Also print to console for immediate visibility
                print(f"\n{'=' * 80}")
                print("500 INTERNAL SERVER ERROR")
                print(f"{'=' * 80}")
                print(f"Path: {error_details['path']}")
                print(f"Method: {error_details['method']}")
                print(f"User: {error_details['user']}")
                print(f"IP: {error_details['ip']}")
                print(f"Error Type: {error_details['type']}")
                print(f"Error Message: {error_details['message']}")
                print("Traceback:")
                print(error_details["traceback"])
                print(f"{'=' * 80}\n")

            except Exception as logging_error:
                # If logging fails, at least log the basic error
                logger.error(f"Failed to log detailed error information: {logging_error}")
                logger.error(f"Original exception: {exception}")

        # Try to render custom error page
        try:
            # Create a minimal context for the error page
            context = {
                "request": request,
                "exception": exception,
                "error_type": type(exception).__name__ if exception else "UnknownError",
                "error_message": str(exception) if exception else "Unknown error occurred",
            }

            # Try to render the custom error template
            html_content = render_to_string("common/server_error.html", context)
            return HttpResponseServerError(html_content)

        except Exception as template_error:
            # If custom template fails, fall back to simple error page
            logger.error(f"Failed to render custom error template: {template_error}")

            # Return a simple HTML error page
            simple_html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Error - reNgine</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                    .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .error-header { color: #dc3545; border-bottom: 2px solid #dc3545; padding-bottom: 10px; margin-bottom: 20px; }
                    .error-message { color: #6c757d; margin-bottom: 20px; }
                    .actions { margin-top: 20px; }
                    .btn { display: inline-block; padding: 10px 20px; margin: 5px; text-decoration: none; border-radius: 4px; }
                    .btn-primary { background-color: #007bff; color: white; }
                    .btn-secondary { background-color: #6c757d; color: white; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error-header">500 - Internal Server Error</h1>
                    <p class="error-message">
                        We're sorry, but something went wrong on our end.
                        Our team has been notified and is working to fix the issue.
                    </p>
                    <div class="actions">
                        <a href="/" class="btn btn-primary">Go to Dashboard</a>
                        <a href="javascript:history.back()" class="btn btn-secondary">Go Back</a>
                    </div>
                </div>
            </body>
            </html>
            """
            return HttpResponseServerError(simple_html)
