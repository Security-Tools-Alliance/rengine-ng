"""
Django management command to load Secator tasks into the database.
"""

from secator.loader import get_configs_by_type

from scanEngine.models import SecatorTask

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator tasks into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--builtin-only",
            action="store_true",
            help="Load only built-in tasks (default behavior)",
        )

    def handle(self, *args, **options):
        builtin_only = options["builtin_only"]

        self.stdout.write("Loading Secator tasks...")

        if not builtin_only:
            self.load_builtin_tasks()

        self.stdout.write(self.style.SUCCESS("Task loading completed successfully!"))

    def load_builtin_tasks(self):
        """Load built-in Secator tasks"""
        self.stdout.write("Loading built-in Secator tasks...")

        created_count = 0
        updated_count = 0
        failed_count = 0

        try:
            # Get tasks directly from secator library
            tasks = get_configs_by_type("task")

            if not tasks:
                self.stdout.write(self.style.WARNING("No tasks found in secator"))
                return

            for task_loader in tasks:
                try:
                    # Extract task information from TemplateLoader
                    # Ensure task_name is a string, not an object
                    if not hasattr(task_loader, "name"):
                        self.stdout.write(self.style.WARNING("Task loader has no name attribute, skipping"))
                        failed_count += 1
                        continue

                    task_name = task_loader.name
                    # Ensure task_name is a string
                    if not isinstance(task_name, str):
                        task_name = str(task_name)
                    if not task_name:
                        self.stdout.write(self.style.WARNING("Task loader has empty name, skipping"))
                        failed_count += 1
                        continue

                    task_description = getattr(task_loader, "description", "") or ""
                    task_category = getattr(task_loader, "category", None)
                    # Ensure category is a string or None, not an object
                    if task_category is not None and not isinstance(task_category, str):
                        task_category = str(task_category) if task_category else None

                    # Always update existing tasks to stay in sync with Secator
                    task, created = SecatorTask.objects.get_or_create(
                        name=task_name,
                        defaults={
                            "task_type": task_name,
                            "category": task_category,
                            "description": task_description,
                            "is_builtin": True,
                            "is_active": True,
                        },
                    )

                    if created:
                        # For built-in tasks, use bypass_builtin_constraints to allow save
                        task.save(bypass_builtin_constraints=True)
                        created_count += 1
                        self.stdout.write(f"Created task: {task.name}")
                    else:
                        # Update existing task using update() to bypass save() constraints
                        SecatorTask.objects.filter(pk=task.pk).update(
                            task_type=task_name,
                            category=task_category,
                            description=task_description,
                            is_builtin=True,
                            is_active=True,
                        )
                        updated_count += 1
                        self.stdout.write(f"Updated task: {task.name}")

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Error processing task {getattr(task_loader, 'name', 'unknown')}: {e}")
                    )
                    failed_count += 1

            self.stdout.write(f"Loaded {created_count} new tasks, updated {updated_count} existing tasks")
            if failed_count > 0:
                self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} tasks"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get tasks from secator: {e}"))
