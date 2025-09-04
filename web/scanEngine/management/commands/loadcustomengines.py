from django.core.management.base import BaseCommand
from reNgine.settings import RENGINE_CUSTOM_ENGINES
from reNgine.utilities.engine import load_custom_scan_engines


class Command(BaseCommand):
    help = "Loads custom engines from YAMLs in custom_engines/ folder into database"

    def handle(self, *args, **kwargs):
        return load_custom_scan_engines(RENGINE_CUSTOM_ENGINES)
