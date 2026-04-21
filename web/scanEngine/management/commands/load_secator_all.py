"""
Django management command to load all Secator components (tasks, profiles, workflows, scans).
"""

from django.core.management import call_command

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load all Secator components (tasks, profiles, workflows, scans)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--tasks-only",
            action="store_true",
            help="Load only tasks",
        )
        parser.add_argument(
            "--profiles-only",
            action="store_true",
            help="Load only profiles",
        )
        parser.add_argument(
            "--workflows-only",
            action="store_true",
            help="Load only workflows",
        )
        parser.add_argument(
            "--scans-only",
            action="store_true",
            help="Load only scans",
        )

    def handle(self, *args, **options):
        tasks_only = options["tasks_only"]
        profiles_only = options["profiles_only"]
        workflows_only = options["workflows_only"]
        scans_only = options["scans_only"]

        self.stdout.write("Loading all Secator components...")

        no_filter = not (tasks_only or profiles_only or workflows_only or scans_only)
        load_tasks = tasks_only or no_filter
        load_profiles = profiles_only or no_filter
        load_workflows = workflows_only or no_filter
        load_scans = scans_only or no_filter

        if load_tasks:
            self.stdout.write("Loading tasks...")
            call_command("load_tasks")
            self.stdout.write("")

        if load_profiles:
            self.stdout.write("Loading profiles...")
            call_command("load_profiles")
            self.stdout.write("")

        if load_workflows:
            self.stdout.write("Loading workflows...")
            call_command("load_workflows")
            self.stdout.write("")

        if load_scans:
            self.stdout.write("Loading scans...")
            call_command("load_scans")
            self.stdout.write("")

        self.stdout.write(self.style.SUCCESS("All Secator components loaded successfully!"))
