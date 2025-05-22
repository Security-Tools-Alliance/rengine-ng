import environ
import mimetypes
import os
from pathlib import Path
import logging

from reNgine.init import first_run

from celery.utils.log import ColorFormatter
from celery._state import get_current_task

env = environ.FileAwareEnv()

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Root env vars
RENGINE_HOME = env('RENGINE_HOME', default=str(Path.home() / 'rengine'))
RENGINE_RESULTS = env('RENGINE_RESULTS', default=str(Path.home() / 'scan_results'))
RENGINE_CUSTOM_ENGINES = env('RENGINE_CUSTOM_ENGINES', default=str(Path.home() / 'custom_engines'))
RENGINE_WORDLISTS = env('RENGINE_WORDLISTS', default=str(Path.home() / 'wordlists'))
RENGINE_TOOL_PATH = env('RENGINE_TOOL_PATH', default=str(Path.home() / 'tools'))
RENGINE_TOOL_GITHUB_PATH = env('RENGINE_TOOL_GITHUB_PATH', default=str(Path(RENGINE_TOOL_PATH) / '.github'))

RENGINE_CACHE_ENABLED = env.bool('RENGINE_CACHE_ENABLED', default=False)
RENGINE_RECORD_ENABLED = env.bool('RENGINE_RECORD_ENABLED', default=True)
RENGINE_RAISE_ON_ERROR = env.bool('RENGINE_RAISE_ON_ERROR', default=False)

with open(Path(RENGINE_HOME) / 'reNgine' / 'version.txt', 'r', encoding="utf-8") as f:
    RENGINE_CURRENT_VERSION = f.read().strip()

# Debug env vars
UI_DEBUG = bool(int(os.environ.get('UI_DEBUG', '0')))
UI_REMOTE_DEBUG = bool(int(os.environ.get('UI_REMOTE_DEBUG', '0')))
UI_REMOTE_DEBUG_PORT = int(os.environ.get('UI_REMOTE_DEBUG_PORT', 5678))
CELERY_DEBUG = bool(int(os.environ.get('CELERY_DEBUG', '0')))
CELERY_REMOTE_DEBUG = bool(int(os.environ.get('CELERY_REMOTE_DEBUG', '0')))
CELERY_REMOTE_DEBUG_PORT = int(os.environ.get('CELERY_REMOTE_DEBUG_PORT', 5679))
COMMAND_EXECUTOR_DRY_RUN = bool(int(os.environ.get('COMMAND_EXECUTOR_DRY_RUN', '0')))

# Common env vars
DEBUG = env.bool('UI_DEBUG', default=False)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(RENGINE_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=False)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=150) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=30)
DEFAULT_GET_LLM_REPORT = env.bool('DEFAULT_GET_LLM_REPORT', default=True)

# Cache settings
YAML_CACHE_TIMEOUT = env.int('YAML_CACHE_TIMEOUT', default=300)  # 5 minutes

# Globals
ALLOWED_HOSTS = ['*']
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)


# Secure configuration for API Key
NETLAS_API_KEY = os.environ.get('NETLAS_API_KEY', '')

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'recon_note.apps.ReconNoteConfig',
    'commonFilters.apps.CommonfiltersConfig',
    'django_ace',
    'django_celery_beat',
    'django_extensions',
    'mathfilters',
    'drf_yasg',
    'rolepermissions',
    'channels',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'dashboard.middleware.SlugMiddleware',
    'dashboard.middleware.ProjectAccessMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [(os.path.join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'reNgine.context_processors.version',
                'reNgine.context_processors.misc',
                'dashboard.context_processors.project_context', 
            ],
    },
}]
ROOT_URLCONF = 'reNgine.urls'
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':(
        'rest_framework_datatables.pagination.DatatablesPageNumberPagination'
    ),
    'PAGE_SIZE': 500,
}
WSGI_APPLICATION = 'reNgine.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

MEDIA_URL = '/media/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'onboarding'
LOGOUT_REDIRECT_URL = 'login'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

'''
CELERY settings
'''
CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'reNgine.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
RENGINE_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
class SensitiveDataFilter(logging.Filter):
    """Security filter to mask sensitive data in logs"""
    
    def filter(self, record):
        sensitive_keys = [
            NETLAS_API_KEY,
            os.environ.get('AWS_ACCESS_KEY_ID'),
            os.environ.get('AWS_SECRET_ACCESS_KEY')
        ]
        
        for key in filter(None, sensitive_keys):
            if hasattr(record, 'msg'):
                if isinstance(record.msg, str):
                    record.msg = record.msg.replace(key, '[REDACTED]')
                elif isinstance(record.msg, dict):
                    for k, v in record.msg.items():
                        if key in str(v):
                            record.msg[k] = '[REDACTED]'
        return True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'sensitive_data': {
            '()': 'reNgine.settings.SensitiveDataFilter'
        }
    },
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': 'errors.log',
        },
        'null': {
            'class': 'logging.NullHandler'
        },
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'brief': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'filters': ['sensitive_data'],  # Applique le filtre
            'formatter': 'brief'
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task'
        },
        'db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': str(Path.home() / 'db.log'),
            'maxBytes': 1024,
            'backupCount': 3
        },
        'celery_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': 'celery.log',
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
        },
        'celery_beat': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': 'celery_beat.log',
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
            'backupCount': 5,
        },
    },
    'formatters': {
        'default': {
            'format': '%(message)s'
        },
        'brief': {
            'format': '%(name)-10s | %(message)s'
        },
        'task': {
            '()': lambda : RengineTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s')
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
            'datefmt': '%y %b %d, %H:%M:%S',
        },
        'migration': {
            'format': '%(asctime)s [%(levelname)s] %(app)s: %(message)s (Migrations: %(migration_count)s)'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR' if UI_DEBUG else 'CRITICAL',
            'propagate': True,
        },
        'celery.app.trace': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['task'],
            'propagate': False
        },
        'celery.worker': {
            'handlers': ['null'],
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db'],
            'level': 'INFO',
            'propagate': False
        },
        'reNgine': {
            'handlers': ['task'],
            'level': 'DEBUG' if CELERY_DEBUG else 'INFO',
            'propagate': False
        },
        'kombu.pidbox': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.pool': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.bootsteps': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.utils.functional': {
            'handlers': ['null'],
            'propagate': False,
        },
        'py.warnings': {
            'handlers': ['null'],
            'propagate': False,
        },
        'django_celery_beat': {
            'handlers': ['celery_beat', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'migrations': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if CELERY_DEBUG else 'INFO',
            'formatter': 'migration',
            'propagate': False,
        },
        'celery': {
            'handlers': ['celery_file'],
            'level': 'DEBUG' if CELERY_DEBUG else 'INFO',
            'propagate': False
        },       
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG' if CELERY_DEBUG else 'INFO',
        'filters': ['sensitive_data']  # Filtre global
    }
}

# debug
def show_toolbar(request):
    return bool(UI_DEBUG)

if UI_DEBUG:
    DEBUG_TOOLBAR_CONFIG = {
        'SHOW_TOOLBAR_CALLBACK': 'reNgine.settings.show_toolbar',
    }

    INSTALLED_APPS.append('debug_toolbar')
    MIDDLEWARE.append('debug_toolbar.middleware.DebugToolbarMiddleware')

class RengineTaskFormatter(ColorFormatter):

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		try:
			self.get_current_task = get_current_task
		except ImportError:
			self.get_current_task = lambda: None

	def format(self, record):
		task = self.get_current_task()
		if task and task.request:
			task_name = '/'.join(task.name.replace('tasks.', '').split('.'))
			record.__dict__.update(task_id=task.request.id,
								   task_name=task_name)
		else:
			record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
			record.__dict__.setdefault('task_id', '')
		return super().format(record)

# Channels configuration
ASGI_APPLICATION = 'reNgine.routing.application'

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('redis', 6379)],
        },
    },
}

# WebSocket settings
WEBSOCKET_ACCEPT_ALL = True  # For development, change in production
