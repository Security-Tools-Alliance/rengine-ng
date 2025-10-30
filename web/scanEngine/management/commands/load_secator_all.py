"""
Django management command to load all Secator components (tasks, workflows, scans).
"""

from django.core.management import call_command

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load all Secator components (tasks, workflows, scans)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force reload even if components already exist",
        )
        parser.add_argument(
            "--tasks-only",
            action="store_true",
            help="Load only tasks",
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
        force = options["force"]
        tasks_only = options["tasks_only"]
        workflows_only = options["workflows_only"]
        scans_only = options["scans_only"]

        self.stdout.write("Loading all Secator components...")

        # Determine which components to load
        load_tasks = tasks_only or (not workflows_only and not scans_only)
        load_workflows = workflows_only or (not tasks_only and not scans_only)
        load_scans = scans_only or (not tasks_only and not workflows_only)

        if load_tasks:
            self.stdout.write("Loading tasks...")
            call_command("load_tasks", force=force)
            self.stdout.write("")

        if load_workflows:
            self.stdout.write("Loading workflows...")
            call_command("load_workflows", force=force)
            self.stdout.write("")

        if load_scans:
            self.stdout.write("Loading scans...")
            call_command("load_scans", force=force)
            self.stdout.write("")

        self.stdout.write(self.style.SUCCESS("All Secator components loaded successfully!"))
