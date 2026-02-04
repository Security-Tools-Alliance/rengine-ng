"""
Management command to run due scheduled scans (CRON replacement for django_celery_beat).

Run periodically via CRON (e.g. every minute):
  * * * * * cd /path && python manage.py run_scheduled_scans
"""

import traceback
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from reNgine.secator.service import run_per_task_secator_scans, start_secator_scan
from reNgine.utilities.logger import get_module_logger
from startScan.models import ScanSchedule

logger = get_module_logger(__name__)


def _error_message_from_secator_result(result: dict, default: str = "Scheduled Secator scan failed") -> str:
    """Build a single error message from a Secator result dict (validation_errors or error key)."""
    if isinstance(result, dict) and "validation_errors" in result:
        return str(result.get("validation_errors", default))
    return result.get("error", default)


def _run_secator_with_secator_kwargs(
    schedule: ScanSchedule,
    user_id: int,
    imported: list,
    out_of_scope: list,
) -> None:
    """
    Run a scheduled scan that uses secator_kwargs (workflow/tasks/scan from UI).
    Raises RuntimeError on failure.
    """
    kwargs_copy = dict(schedule.secator_kwargs)
    url_filter = kwargs_copy.pop("url_filter", "") or ""
    selected_targets_per_task = kwargs_copy.pop("selected_targets_per_task", None)
    kwargs_copy.pop("scan_history_id", None)
    use_per_task = bool(
        selected_targets_per_task and kwargs_copy.get("execution_mode") == "tasks"
    )

    if use_per_task:
        result = run_per_task_secator_scans(
            domain_id=schedule.domain_id,
            user_id=user_id,
            selected_targets_per_task=selected_targets_per_task,
            imported_subdomains=imported,
            out_of_scope_subdomains=out_of_scope,
            url_filter=url_filter,
            secator_config=kwargs_copy.get("secator_config") or {},
        )
        success = result.get("success_count", 0) >= 1
    else:
        result = start_secator_scan(
            domain_id=schedule.domain_id,
            user_id=user_id,
            imported_subdomains=imported,
            out_of_scope_subdomains=out_of_scope,
            url_filter=url_filter,
            **kwargs_copy,
        )
        success = result.get("status", False)

    if not success:
        raise RuntimeError(_error_message_from_secator_result(result))


def _run_secator_with_scan_type(
    schedule: ScanSchedule,
    user_id: int,
    imported: list,
    out_of_scope: list,
) -> None:
    """
    Run a scheduled scan that uses scan_type (organization scan: engine-based).
    Raises RuntimeError on failure.
    """
    if not schedule.scan_type_id:
        raise RuntimeError("Schedule has no scan_type and no secator_kwargs")
    result = start_secator_scan(
        domain_id=schedule.domain_id,
        user_id=user_id,
        execution_mode="scan",
        secator_scan_type=schedule.scan_type.engine_name,
        imported_subdomains=imported,
        out_of_scope_subdomains=out_of_scope,
    )
    if not result.get("status"):
        raise RuntimeError(
            result.get("error", "start_secator_scan failed")
        )


def _run_secator_for_schedule(
    schedule: ScanSchedule,
    user_id: int,
    imported: list,
    out_of_scope: list,
) -> None:
    """
    Run the appropriate Secator scan for this schedule (secator_kwargs or scan_type path).
    Raises RuntimeError on failure.
    """
    if schedule.secator_kwargs:
        _run_secator_with_secator_kwargs(schedule, user_id, imported, out_of_scope)
    else:
        _run_secator_with_scan_type(schedule, user_id, imported, out_of_scope)


class Command(BaseCommand):
    help = "Run scheduled scans that are due (call from CRON e.g. every minute)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only list due schedules, do not run scans.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        due = ScanSchedule.objects.filter(enabled=True, next_run__lte=now).order_by("next_run")
        dry_run = options["dry_run"]

        if dry_run:
            for schedule in due:
                self.stdout.write(
                    f"Would run: id={schedule.id} name={schedule.name} next_run={schedule.next_run}"
                )
            self.stdout.write(self.style.SUCCESS(f"Dry run: {due.count()} schedule(s) due."))
            return

        run_count = 0
        for schedule in due:
            try:
                self._run_schedule(schedule)
                run_count += 1
            except Exception as e:
                schedule_id = getattr(schedule, "id", "?")
                schedule_name = getattr(schedule, "name", "unknown")
                logger.exception(
                    "run_scheduled_scans failed for schedule id=%s name=%r: %s",
                    schedule_id,
                    schedule_name,
                    e,
                )
                tb = traceback.format_exc()
                self.stderr.write(
                    self.style.ERROR(
                        f"Schedule id={schedule_id} name={schedule_name!r}: {e}\n{tb}"
                    )
                )

        if run_count:
            self.stdout.write(self.style.SUCCESS(f"Started {run_count} scheduled scan(s)."))

    def _run_schedule(self, schedule: ScanSchedule) -> None:
        if schedule.initiated_by_id is None:
            raise RuntimeError(
                f"Schedule id={schedule.id} has no initiated_by; cannot run for audit trail. "
                "Set initiated_by on the schedule or delete it."
            )
        user_id = schedule.initiated_by_id
        imported = list(schedule.imported_subdomains or [])
        out_of_scope = list(schedule.out_of_scope_subdomains or [])

        _run_secator_for_schedule(schedule, user_id, imported, out_of_scope)

        if schedule.one_off:
            schedule.delete()
            return

        now = timezone.now()
        schedule.last_run_at = now
        schedule.total_run_count = (schedule.total_run_count or 0) + 1
        if schedule.schedule_mode == ScanSchedule.SCHEDULE_MODE_PERIODIC and schedule.frequency_value:
            schedule.next_run = ScanSchedule.compute_next_run_from_frequency(
                now, schedule.frequency_value, schedule.frequency_type
            )
        else:
            schedule.next_run = now + timedelta(days=1)

        schedule.save(validate=False)
