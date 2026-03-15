# Suppress urllib3 InsecureRequestWarning when connecting to reNgine-ng API with self-signed cert.
# Loaded by site module at interpreter startup. We use warnings.filterwarnings only (no urllib3 import)
# to avoid early import of urllib3/ssl that can cause RecursionError in ssl.minimum_version.
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
