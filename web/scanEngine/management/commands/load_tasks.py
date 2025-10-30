"""
Django management command to load Secator tasks into the database.
"""

from scanEngine.models import SecatorTask

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator tasks into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force reload even if tasks already exist",
        )
        parser.add_argument(
            "--builtin-only",
            action="store_true",
            help="Load only built-in tasks (default behavior)",
        )

    def handle(self, *args, **options):
        force = options["force"]
        builtin_only = options["builtin_only"]

        self.stdout.write("Loading Secator tasks...")

        if not builtin_only:
            self.load_builtin_tasks(force)

        self.stdout.write(self.style.SUCCESS("Task loading completed successfully!"))

    def load_builtin_tasks(self, force):
        """Load built-in Secator tasks"""
        self.stdout.write("Loading built-in Secator tasks...")

        created_count = 0
        failed_count = 0

        # Get tasks list from secator
        tasks_output = self._get_secator_tasks_list()

        if not tasks_output:
            self.stdout.write(self.style.ERROR("Failed to get tasks list from secator"))
            return

        # Parse tasks from output
        tasks_data = self._parse_tasks_output(tasks_output)

        if not tasks_data:
            self.stdout.write(self.style.WARNING("No tasks found in secator output"))
            return

        for task_data in tasks_data:
            try:
                # Create or update task
                task, created = SecatorTask.objects.get_or_create(
                    name=task_data["name"],
                    defaults=task_data,
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"Created task: {task.name}")
                elif force:
                    # Update existing task
                    task.task_type = task_data["task_type"]
                    task.category = task_data["category"]
                    task.description = task_data["description"]
                    task.is_builtin = task_data["is_builtin"]
                    task.is_active = task_data["is_active"]
                    task.save(bypass_builtin_constraints=True)
                    self.stdout.write(f"Updated task: {task.name}")
                else:
                    self.stdout.write(f"Task already exists: {task.name} (skipped)")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error processing task {task_data.get('name', 'unknown')}: {e}"))
                failed_count += 1

        self.stdout.write(f"Loaded {created_count} built-in tasks")
        if failed_count > 0:
            self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} tasks"))
