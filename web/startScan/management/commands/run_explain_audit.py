"""
Full EXPLAIN (ANALYZE, BUFFERS) audit for critical query patterns.

Runs EXPLAIN on representative queries from api, dashboard, datatable, recon_note,
scanEngine, startScan and targetApp; flags Seq Scan and reports index usage.
Usage:
  python manage.py run_explain_audit
  python manage.py run_explain_audit --verbose
"""

import re
from typing import Any, List, Tuple

from django.core.management.base import BaseCommand
from django.db import connection

from startScan.query_audit import build_audit_samples, get_audit_queries


def _run_explain(cursor, sql: str, params: List[Any]) -> str:
    """Run EXPLAIN (ANALYZE, BUFFERS) and return plan text."""
    cursor.execute(f"EXPLAIN (ANALYZE, BUFFERS) {sql}", params)
    return "\n".join(row[0] for row in cursor.fetchall())


def _classify_plan(plan_text: str) -> Tuple[str, str]:
    """
    Classify plan as OK (index used) or WARNING (seq scan on main table).
    Returns (status, detail).
    """
    seq_scan_matches = list(re.finditer(r"Seq Scan on ([\w\"]+)", plan_text, re.IGNORECASE))
    index_scan_matches = list(
        re.finditer(r"Index (?:Only )?Scan (?:Backward )?using (\S+) on ([\w\"]+)", plan_text, re.IGNORECASE)
    )
    bitmap_heap = "Bitmap Heap Scan" in plan_text

    if seq_scan_matches:
        tables = [m.group(1).strip('"') for m in seq_scan_matches]
        return "SEQ_SCAN", f"Seq Scan on: {', '.join(tables)}"
    if index_scan_matches:
        indexes = [m.group(1).strip('"') for m in index_scan_matches]
        return "OK", f"Index(es): {', '.join(indexes)}"
    if bitmap_heap:
        return "OK", "Bitmap Heap Scan (index-backed)"
    return "OK", "Other (nested loop, etc.)"


class Command(BaseCommand):
    help = "Run full EXPLAIN (ANALYZE, BUFFERS) audit on critical query patterns."

    def add_arguments(self, parser):
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Print full EXPLAIN output for each query",
        )
        parser.add_argument(
            "--app",
            type=str,
            default=None,
            help="Run only queries for this app (api, dashboard, datatable, recon_note, scanEngine, startScan, targetApp)",
        )

    def handle(self, *args, **options):
        verbose = options["verbose"]
        app_filter = options.get("app")
        self.stdout.write("Building audit samples...")
        samples = build_audit_samples()
        queries = get_audit_queries(samples, app_filter=app_filter)
        self.stdout.write(f"Running EXPLAIN on {len(queries)} queries\n")

        results: List[Tuple[str, str, str, str]] = []
        with connection.cursor() as cursor:
            for name, sql, params in queries:
                try:
                    plan = _run_explain(cursor, sql, params)
                except Exception as e:
                    results.append((name, "ERROR", str(e), ""))
                    if verbose:
                        self.stdout.write(self.style.ERROR(f"  {name}: {e}\n"))
                    continue
                status, detail = _classify_plan(plan)
                results.append((name, status, detail, plan))
                if verbose:
                    self.stdout.write(f"\n--- {name} ---\n{plan}\n")

        self.stdout.write("\n" + "=" * 80)
        self.stdout.write("AUDIT SUMMARY")
        self.stdout.write("=" * 80)
        for name, status, detail, _ in results:
            if status == "SEQ_SCAN":
                self.stdout.write(self.style.WARNING(f"  SEQ_SCAN  {name}"))
                self.stdout.write(self.style.WARNING(f"           {detail}"))
            elif status == "ERROR":
                self.stdout.write(self.style.ERROR(f"  ERROR     {name}: {detail}"))
            else:
                self.stdout.write(self.style.SUCCESS(f"  OK        {name}"))
                self.stdout.write(f"           {detail}")
        seq_count = sum(1 for r in results if r[1] == "SEQ_SCAN")
        err_count = sum(1 for r in results if r[1] == "ERROR")
        self.stdout.write("=" * 80)
        self.stdout.write(
            f"Total: {len(results)}  |  OK: {len(results) - seq_count - err_count}  |  Seq Scan: {seq_count}  |  Error: {err_count}"
        )
        self.stdout.write("=" * 80)
        if seq_count or err_count:
            self.stdout.write(
                self.style.WARNING("Review SEQ_SCAN and ERROR lines; consider adding indexes or fixing queries.")
            )
        else:
            self.stdout.write(self.style.SUCCESS("Done. No Seq Scan on audited queries."))
