"""
Django management command to load Secator tasks into the database.
"""

from secator.loader import discover_tasks, get_configs_by_type

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

    def _tags_by_task_name(self):
        """Build mapping task class name -> list of tag strings from Secator."""
        tags_by_name = {}
        for cls in discover_tasks():
            raw = getattr(cls, "tags", None)
            if raw is None:
                tags_by_name[cls.__name__] = []
            elif isinstance(raw, (list, tuple)):
                tags_by_name[cls.__name__] = [str(t).strip() for t in raw if t]
            else:
                tags_by_name[cls.__name__] = [str(raw).strip()]
        return tags_by_name

    def load_builtin_tasks(self):
        """Load built-in Secator tasks."""
        self.stdout.write("Loading built-in Secator tasks...")

        created_count = 0
        updated_count = 0
        failed_count = 0

        try:
            tasks = get_configs_by_type("task")
            if not tasks:
                self.stdout.write(self.style.WARNING("No tasks found in secator"))
                return

            tags_by_name = self._tags_by_task_name()

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
                    task_tags = list(tags_by_name.get(task_name, []))

                    task, created = SecatorTask.objects.get_or_create(
                        name=task_name,
                        defaults={
                            "task_type": task_name,
                            "tags": task_tags,
                            "description": task_description,
                            "is_builtin": True,
                            "is_active": True,
                        },
                    )

                    if created:
                        task.save(bypass_builtin_constraints=True)
                        created_count += 1
                        self.stdout.write(f"Created task: {task.name}")
                    elif task.is_builtin:
                        SecatorTask.objects.filter(pk=task.pk).update(
                            task_type=task_name,
                            tags=task_tags,
                            description=task_description,
                            is_builtin=True,
                            is_active=True,
                        )
                        updated_count += 1
                        self.stdout.write(f"Updated task: {task.name}")
                    else:
                        self.stdout.write(
                            self.style.WARNING(
                                f"Name collision: custom task '{task.name}' (id={task.pk}) "
                                "shares name with Secator task; skipping update to preserve custom task."
                            )
                        )

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
