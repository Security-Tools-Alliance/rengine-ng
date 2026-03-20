import mimetypes
import os
from pathlib import Path
import sys

import environ

from reNgine.core.db import resolve_db_host_port
from reNgine.init import first_run


env = environ.FileAwareEnv()

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Root env vars
RENGINE_HOME = env("RENGINE_HOME", default=str(Path.home() / "rengine"))
RENGINE_RESULTS = env("RENGINE_RESULTS", default=str(Path.home() / "scan_results"))
SECATOR_RESULTS = env("SECATOR_RESULTS", default=str(Path.home() / ".secator" / "reports"))
# Prefix to strip from Secator report paths when storing (path_utils.strip_secator_reports_prefix).
# Must match the path prefix used by Secator workers when they emit screenshot_path / stored_response_path.
# Default aligned with SECATOR_RESULTS so unconfigured setups behave consistently. In Docker/worker setups
# where workers use a different report root (e.g. /home/secator/.secator/reports), set SECATOR_REPORTS_PREFIX
# to that value so stored paths stay relative and ServeScanFile can resolve them under RENGINE_RESULTS.
SECATOR_REPORTS_PREFIX = env(
    "SECATOR_REPORTS_PREFIX",
    default=str(Path.home() / ".secator" / "reports"),
)
RENGINE_CUSTOM_ENGINES = env("RENGINE_CUSTOM_ENGINES", default=str(Path.home() / "custom_engines"))
RENGINE_WORDLISTS = env("RENGINE_WORDLISTS", default=str(Path.home() / "wordlists"))
RENGINE_GF_PATTERNS_DIR = env("RENGINE_GF_PATTERNS_DIR", default=str(Path.home() / ".gf"))
RENGINE_NUCLEI_TEMPLATES_DIR = env("RENGINE_NUCLEI_TEMPLATES_DIR", default=str(Path.home() / "nuclei-templates"))
RENGINE_TOOL_PATH = env("RENGINE_TOOL_PATH", default=str(Path.home() / "tools"))
RENGINE_TOOL_GITHUB_PATH = env("RENGINE_TOOL_GITHUB_PATH", default=str(Path(RENGINE_TOOL_PATH) / ".github"))
# Default SSH key path for worker connections (generated at container startup in ~/.ssh/id_ed25519)
RENGINE_SSH_DEFAULT_KEY_PATH = env(
    "RENGINE_SSH_DEFAULT_KEY_PATH",
    default=str(Path.home() / ".ssh" / "id_ed25519"),
)

RENGINE_CACHE_ENABLED = env.bool("RENGINE_CACHE_ENABLED", default=False)
RENGINE_RECORD_ENABLED = env.bool("RENGINE_RECORD_ENABLED", default=True)
RENGINE_RAISE_ON_ERROR = env.bool("RENGINE_RAISE_ON_ERROR", default=False)

with open(Path(RENGINE_HOME) / "reNgine" / "version.txt", "r", encoding="utf-8") as f:
    RENGINE_CURRENT_VERSION = f.read().strip()

# Debug env vars
UI_DEBUG = bool(int(os.environ.get("UI_DEBUG", "0")))
UI_ERROR_LOGGING = bool(int(os.environ.get("UI_ERROR_LOGGING", "0")))
UI_REMOTE_DEBUG = bool(int(os.environ.get("UI_REMOTE_DEBUG", "0")))
UI_REMOTE_DEBUG_PORT = int(os.environ.get("UI_REMOTE_DEBUG_PORT", 5678))
SECATOR_API_DEBUG = bool(int(os.environ.get("SECATOR_API_DEBUG", "0")))

# Common env vars
DEBUG = env.bool("UI_DEBUG", default=False)
DOMAIN_NAME = env("DOMAIN_NAME", default="localhost:8000")
TEMPLATE_DEBUG = env.bool("TEMPLATE_DEBUG", default=UI_DEBUG)
DISABLE_TEMPLATE_CACHE = env.bool("DISABLE_TEMPLATE_CACHE", default=UI_DEBUG)
SECRET_FILE = os.path.join(RENGINE_HOME, "secret")
DEFAULT_RATE_LIMIT = env.int("DEFAULT_RATE_LIMIT", default=150)  # requests / second
DEFAULT_HTTP_TIMEOUT = env.int("DEFAULT_HTTP_TIMEOUT", default=5)  # seconds
DEFAULT_RETRIES = env.int("DEFAULT_RETRIES", default=1)
DEFAULT_THREADS = env.int("DEFAULT_THREADS", default=30)
DEFAULT_DELAY = env.float("DEFAULT_DELAY", default=0)  # seconds between requests
DEFAULT_FOLLOW_REDIRECT = env.bool("DEFAULT_FOLLOW_REDIRECT", default=False)
DEFAULT_DEPTH: int | None = None  # no depth limit by default
DEFAULT_GET_LLM_REPORT = env.bool("DEFAULT_GET_LLM_REPORT", default=True)

# Globals
ALLOWED_HOSTS = ["*"]
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# CSRF Configuration for Django 5.2 compatibility
# Fix for "Origin checking failed" errors after Django upgrade
CSRF_TRUSTED_ORIGINS = [
    f"http://{DOMAIN_NAME}",
    f"https://{DOMAIN_NAME}",
    "https://localhost",
    "https://127.0.0.1",
    "http://localhost:8000",
    "https://localhost:8000",
    "http://127.0.0.1:8000",
    "https://127.0.0.1:8000",
]

# Additional CSRF settings for better security
CSRF_COOKIE_SECURE = not DEBUG  # Use secure cookies in production
CSRF_COOKIE_HTTPONLY = True  # Prevent JavaScript access to CSRF cookie for better security
CSRF_COOKIE_SAMESITE = "Lax"  # CSRF protection while allowing some cross-site requests
CSRF_USE_SESSIONS = True  # Use sessions for CSRF tokens when HTTPONLY is True (more secure)
CSRF_COOKIE_AGE = 31449600  # 1 year in seconds

# Session security settings
SESSION_COOKIE_SECURE = not DEBUG  # Use secure cookies in production
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
SESSION_COOKIE_SAMESITE = "Lax"  # Session protection while allowing some cross-site requests

# Databases
USE_PGBOUNCER = env.bool("USE_PGBOUNCER", default=True)
RENGINE_DB_PROBE_AT_STARTUP = env.bool("RENGINE_DB_PROBE_AT_STARTUP", default=False)


_db_host, _db_port = resolve_db_host_port(env, USE_PGBOUNCER, RENGINE_DB_PROBE_AT_STARTUP, sys.argv)

# DISABLE_SERVER_SIDE_CURSORS must be at top level; in OPTIONS it would be passed to psycopg2.connect() and cause an error.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB"),
        "USER": env("POSTGRES_USER"),
        "PASSWORD": env("POSTGRES_PASSWORD"),
        "HOST": _db_host,
        "PORT": _db_port,
        "CONN_HEALTH_CHECKS": USE_PGBOUNCER,
        "DISABLE_SERVER_SIDE_CURSORS": USE_PGBOUNCER,
    }
}

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "django.contrib.sites",
    "rest_framework",
    "rest_framework_api_key",
    "rest_framework_datatables",
    "dashboard.apps.DashboardConfig",
    "targetApp.apps.TargetappConfig",
    "scanEngine.apps.ScanengineConfig",
    "startScan.apps.StartscanConfig",
    "recon_note.apps.ReconNoteConfig",
    "commonFilters.apps.CommonfiltersConfig",
    "django_ace",
    "django_extensions",
    "mathfilters",
    "drf_yasg",
    "rolepermissions",
    "channels",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.github",
    "allauth.socialaccount.providers.microsoft",
    "allauth.socialaccount.providers.gitlab",
    "allauth.socialaccount.providers.openid_connect",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "api.middleware.APIKeyAuthenticationMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "login_required.middleware.LoginRequiredMiddleware",
    "dashboard.middleware.SlugMiddleware",
    "dashboard.middleware.ProjectAccessMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "reNgine.middleware.CustomErrorMiddleware",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [(os.path.join(BASE_DIR, "templates"))],
        "APP_DIRS": False,  # Must be False when loaders is defined
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "reNgine.context_processors.version",
                "reNgine.context_processors.oauth_providers",
                "reNgine.context_processors.misc",
                "reNgine.context_processors.user_preferences",
                "reNgine.context_processors.dompurify_sanitize_config",
                "dashboard.context_processors.project_context",
            ],
            # Disable template caching in development
            "loaders": [
                "django.template.loaders.filesystem.Loader",
                "django.template.loaders.app_directories.Loader",
            ]
            if DISABLE_TEMPLATE_CACHE
            else [
                (
                    "django.template.loaders.cached.Loader",
                    [
                        "django.template.loaders.filesystem.Loader",
                        "django.template.loaders.app_directories.Loader",
                    ],
                )
            ],
        },
    }
]
ROOT_URLCONF = "reNgine.urls"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "api.permissions.HasAPIKeyOrIsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        "rest_framework_datatables.renderers.DatatablesRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": ("rest_framework_datatables.filters.DatatablesFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": ("rest_framework_datatables.pagination.DatatablesPageNumberPagination"),
    "PAGE_SIZE": 500,
}
WSGI_APPLICATION = "reNgine.wsgi.application"

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation." + "UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation." + "NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

MEDIA_URL = "/media/"
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = "/staticfiles/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    "login",
    "socialaccount_login",
    "socialaccount_signup",
    # Pull-agent endpoints use X-Rengine-Worker-Pull-Token only (no session)
    "api:secator_worker_pull_claim",
    "api:secator_worker_pull_complete",
    "api:secator_worker_pull_checkin",
    "secator_worker_pull_claim",
    "secator_worker_pull_complete",
    "secator_worker_pull_checkin",
]

LOGIN_REQUIRED_IGNORE_PATHS = [
    # Only exempt the specific allauth routes needed for OAuth login/callback flow.
    # Do NOT use a broad r"/accounts/" pattern — that would expose account-management
    # views (email, password, etc.) to anonymous users.
    r"/accounts/\w+/login/$",
    r"/accounts/\w+/login/callback/$",
    r"/accounts/signup/$",
    r"/accounts/social/signup/$",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "login"

# IP service timeout in seconds
IP_SERVICE_TIMEOUT = env.int("IP_SERVICE_TIMEOUT", default=5)

# Django allauth configuration
SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# Allauth settings
ACCOUNT_AUTHENTICATION_METHOD = "username_email"
ACCOUNT_EMAIL_REQUIRED = False
ACCOUNT_EMAIL_VERIFICATION = "optional"
ACCOUNT_USERNAME_REQUIRED = True
ACCOUNT_UNIQUE_EMAIL = True  # Prevent duplicate emails across OAuth/local accounts
ACCOUNT_PREVENT_ENUMERATION = True  # Don't reveal if username/email exists
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_VERIFICATION = "optional"
SOCIALACCOUNT_STORE_TOKENS = False  # Don't store OAuth tokens (security)
# Whether to skip the intermediate confirmation page and redirect directly to the OAuth provider.
# Set SOCIALACCOUNT_LOGIN_ON_GET=0 in .env to restore the confirmation page.
SOCIALACCOUNT_LOGIN_ON_GET = env.bool("SOCIALACCOUNT_LOGIN_ON_GET", default=True)

# Custom adapter for OAuth user creation with minimal permissions
SOCIALACCOUNT_ADAPTER = "dashboard.adapters.OAuthAccountAdapter"
ACCOUNT_ADAPTER = "dashboard.adapters.AccountAdapter"

# Trust proxy headers for HTTPS detection.
# Only enable when running behind a trusted reverse proxy (e.g. nginx, traefik)
# that correctly sets X-Forwarded-Proto/Host/Port headers.
# Set TRUST_PROXY_HEADERS=True in .env to enable.
if env.bool("TRUST_PROXY_HEADERS", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True

# OAuth Provider Settings
# Note: OpenID Connect providers are configured via Django admin
# after creating SocialApp entries with provider_id='openid_connect'
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "SCOPE": [
            "profile",
            "email",
        ],
        "AUTH_PARAMS": {
            "access_type": "online",
        },
        "APP": {
            "client_id": env("GOOGLE_OAUTH_CLIENT_ID", default=""),
            "secret": env("GOOGLE_OAUTH_CLIENT_SECRET", default=""),
            "key": "",
        },
    },
    "github": {
        "SCOPE": [
            "user",
            "email",
        ],
        "APP": {
            "client_id": env("GITHUB_OAUTH_CLIENT_ID", default=""),
            "secret": env("GITHUB_OAUTH_CLIENT_SECRET", default=""),
        },
    },
    "microsoft": {
        "SCOPE": [
            "User.Read",
        ],
        "APP": {
            "client_id": env("MICROSOFT_OAUTH_CLIENT_ID", default=""),
            "secret": env("MICROSOFT_OAUTH_CLIENT_SECRET", default=""),
        },
    },
    "gitlab": {
        "GITLAB_URL": env("GITLAB_URL", default="https://gitlab.com"),
        "SCOPE": ["read_user"],
        "APP": {
            "client_id": env("GITLAB_OAUTH_CLIENT_ID", default=""),
            "secret": env("GITLAB_OAUTH_CLIENT_SECRET", default=""),
        },
    },
    "openid_connect": {"APPS": []},
}

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

"""
SECATOR settings
"""
SECATOR_CELERY_BROKER_URL = env("SECATOR_CELERY_BROKER_URL", default="redis://redis:6379/0")
SECATOR_CELERY_RESULT_BACKEND = env("SECATOR_CELERY_RESULT_BACKEND", default="redis://redis:6379/0")
# Used when deploying remote workers (worker .env generation)
SECATOR_ADDONS_API_URL = env(
    "SECATOR_ADDONS_API_URL",
    default=f"https://{DOMAIN_NAME}/api/secator",
)
SECATOR_ADDONS_API_HEADER_NAME = env("SECATOR_ADDONS_API_HEADER_NAME", default="Api-Key")
SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT = env("SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT", default="")
SECATOR_ADDONS_API_KEY = env("SECATOR_ADDONS_API_KEY", default="")
SECATOR_ADDONS_API_FORCE_SSL = env.bool("SECATOR_ADDONS_API_FORCE_SSL", default=False)

# When False, run runner/ScanHistory sync in the request (inline, e.g. for tests). When True, run in a bounded
# background thread pool. Set to False in production if you observe concurrency/connection issues.
SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND = bool(int(os.environ.get("SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND", "1")))

# Max workers for the thread pool used when SECATOR_RUNNER_UPDATE_SYNC_BACKGROUND is True.
# Limits concurrent sync tasks to avoid unbounded thread growth and DB connection pressure.
SECATOR_RUNNER_UPDATE_SYNC_MAX_WORKERS = env.int("SECATOR_RUNNER_UPDATE_SYNC_MAX_WORKERS", default=8)

# Python executable used inside the remote worker container to run the Secator job script.
# Set this when Secator is installed via pipx in the container (e.g. /root/.local/share/pipx/venvs/secator/bin/python).
SECATOR_WORKER_CONTAINER_PYTHON = env(
    "SECATOR_WORKER_CONTAINER_PYTHON", default="/home/secator/.local/share/pipx/venvs/secator/bin/python"
)

# Base path for scripts inside the worker container (where run_secator_job.py is run).
# Set this when the container sees a different path than deploy_path (e.g. container user is secator:
# deploy_path may be /home/rengine/secator-worker on the host, container has /home/secator/secator-worker).
# If unset, deploy_path is used for both SFTP upload and the container command.
SECATOR_WORKER_CONTAINER_SCRIPT_BASE = env("SECATOR_WORKER_CONTAINER_SCRIPT_BASE", default="/home/secator")

# SSH reverse tunnel (worker api_access_type=tunnel): bind and target for ssh -R on the worker host.
# Bind: where the worker host listens; default Docker bridge gateway so only the Secator container
# can reach it via host.docker.internal. Use 127.0.0.1 for localhost-only, 0.0.0.0 for all interfaces.
RENGINE_TUNNEL_BIND_ADDRESS = env("RENGINE_TUNNEL_BIND_ADDRESS", default="172.17.0.1")

# Target: host/port the tunnel forwards to (where nginx/API listens). In Docker use "proxy", bare metal "localhost".
RENGINE_TUNNEL_TARGET_HOST = env("RENGINE_TUNNEL_TARGET_HOST", default="proxy")
RENGINE_TUNNEL_TARGET_PORT = env.int("RENGINE_TUNNEL_TARGET_PORT", default=443)

"""
Redis settings for distributed locking
"""
REDIS_HOST = env("REDIS_HOST", default="redis")
REDIS_PORT = env("REDIS_PORT", default=6379)
REDIS_DB = env("REDIS_DB", default=0)
REDIS_PASSWORD = env("REDIS_PASSWORD", default=None)
"""
ROLES and PERMISSIONS
"""
ROLEPERMISSIONS_MODULE = "reNgine.roles"
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

"""
Cache settings
"""
RENGINE_TASK_IGNORE_CACHE_KWARGS = ["ctx"]

# Django Cache Configuration
# In development, disable caching to ensure templates and views reload properly
if DEBUG:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.dummy.DummyCache",
        }
    }
else:
    # Production cache using Redis
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": SECATOR_CELERY_BROKER_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            },
            "KEY_PREFIX": "rengine_cache",
            "TIMEOUT": 300,  # 5 minutes default timeout
        }
    }


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

"""
LOGGING settings
"""
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {
        "file": {
            "level": "ERROR",
            "class": "logging.FileHandler",
            "filename": "errors.log",
        },
        "null": {"class": "logging.NullHandler"},
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "brief": {"class": "logging.StreamHandler", "formatter": "brief"},
        "console": {"class": "logging.StreamHandler", "formatter": "brief"},
        "db": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "brief",
            "filename": str(Path.home() / "db.log"),
            "maxBytes": 1024,
            "backupCount": 3,
        },
        "error_console": {
            "class": "logging.StreamHandler",
            "formatter": "brief",
            "stream": "ext://sys.stderr",
        },
    },
    "formatters": {
        "default": {"format": "%(message)s"},
        "brief": {"format": "%(name)-10s | %(message)s"},
        "simple": {
            "format": "%(levelname)s %(message)s",
            "datefmt": "%y %b %d, %H:%M:%S",
        },
        "migration": {"format": "%(asctime)s [%(levelname)s] %(app)s: %(message)s (Migrations: %(migration_count)s)"},
    },
    "loggers": {
        "django": {
            "handlers": ["file", "error_console"] if UI_ERROR_LOGGING else ["file"],
            "level": "ERROR" if (UI_DEBUG or UI_ERROR_LOGGING) else "CRITICAL",
            "propagate": False,
        },
        "django.server": {"handlers": ["console"], "propagate": False},
        "django.db.backends": {"handlers": ["db"], "level": "INFO", "propagate": False},
        "reNgine": {
            "handlers": ["default"],
            "level": "DEBUG" if UI_DEBUG else "INFO",
            "propagate": False,
        },
        "api": {
            "handlers": ["default"],
            "level": "DEBUG" if (UI_DEBUG or SECATOR_API_DEBUG) else "INFO",
            "propagate": False,
        },
        "websocket": {
            "handlers": ["default"],
            "level": "DEBUG" if (UI_DEBUG) else "INFO",
            "propagate": False,
        },
        "migrations": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if UI_DEBUG else "INFO",
            "formatter": "migration",
            "propagate": False,
        },
        "reNgine.utilities.logger.api_logger": {
            "handlers": ["default"],
            "level": "DEBUG" if (SECATOR_API_DEBUG) else "INFO",
            "propagate": False,  # Don't propagate to avoid duplicate logs
        },
        "reNgine.utilities.logger.runner_logger": {
            "handlers": ["default"],
            "level": "DEBUG" if (SECATOR_API_DEBUG) else "INFO",
            "propagate": False,  # Don't propagate to avoid duplicate logs
        },
        "startScan.secator": {
            "handlers": ["default"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG" if UI_DEBUG else "INFO",
    },
}


# debug
def show_toolbar(request):
    return bool(UI_DEBUG)


if UI_DEBUG:
    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": "reNgine.settings.show_toolbar",
    }

    INSTALLED_APPS.append("debug_toolbar")
    MIDDLEWARE.append("debug_toolbar.middleware.DebugToolbarMiddleware")

# Channels configuration
ASGI_APPLICATION = "reNgine.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("redis", 6379)],
            "capacity": 1500,
            "expiry": 10,
        },
    },
}

# WebSocket settings
WEBSOCKET_ACCEPT_ALL = True  # For development, change in production
WEBSOCKET_SCAN_STATUS_THROTTLE_SECONDS = 2
WEBSOCKET_SCAN_STATUS_FULL_INTERVAL_SECONDS = 15
