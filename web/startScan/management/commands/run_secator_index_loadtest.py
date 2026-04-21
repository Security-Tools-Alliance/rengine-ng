"""
Load test for indexed DB queries across project apps (dashboard, recon_note,
scanEngine, startScan, targetApp).

Runs PK lookups on every table of each app plus custom indexed queries
(Secator sync). Reports min/avg/max/p95 and QPS per query.
Usage:
  python manage.py run_secator_index_loadtest
  python manage.py run_secator_index_loadtest --iterations 5000 --warmup 100
  python manage.py run_secator_index_loadtest --apps startScan scanEngine
"""

import statistics
import time
from typing import Any, Dict, List

from django.core.management.base import BaseCommand
from django.db import connection

from startScan.query_audit import build_loadtest_samples, get_loadtest_queries


def _run_timed(cursor, sql: str, params: List[Any], iterations: int) -> List[float]:
    """Execute sql `iterations` times; return list of durations in seconds."""
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        cursor.execute(sql, params or [])
        cursor.fetchall()
        times.append(time.perf_counter() - t0)
    return times


def _compute_stats(times_ms: List[float]) -> Dict[str, float]:
    """Return min, max, avg, p95 (ms)."""
    if not times_ms:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "p95": 0.0}
    sorted_ms = sorted(times_ms)
    p95_idx = max(0, int(len(sorted_ms) * 0.95) - 1)
    return {
        "min": min(times_ms),
        "max": max(times_ms),
        "avg": statistics.mean(times_ms),
        "p95": sorted_ms[p95_idx],
    }


class Command(BaseCommand):
    help = "Load test indexed queries for dashboard, recon_note, scanEngine, startScan and targetApp."

    def add_arguments(self, parser):
        parser.add_argument(
            "--iterations",
            type=int,
            default=2000,
            help="Iterations per query (default: 2000)",
        )
        parser.add_argument(
            "--warmup",
            type=int,
            default=50,
            help="Warmup iterations before timing (default: 50)",
        )
        parser.add_argument(
            "--apps",
            nargs="+",
            default=["dashboard", "recon_note", "scanEngine", "startScan", "targetApp"],
            help="App labels to include (default: dashboard recon_note scanEngine startScan targetApp)",
        )

    def handle(self, *args, **options):
        iterations = options["iterations"]
        warmup = options["warmup"]
        app_labels = options["apps"]

        self.stdout.write(f"Building sample PKs for apps: {app_labels}")
        samples = build_loadtest_samples(app_labels)
        queries = get_loadtest_queries(app_labels, samples)
        self.stdout.write(f"Running {len(queries)} queries: iterations={iterations}, warmup={warmup}\n")

        with connection.cursor() as cursor:
            for name, sql, params in queries:
                _run_timed(cursor, sql, params, warmup)
                times_sec = _run_timed(cursor, sql, params, iterations)
                times_ms = [t * 1000 for t in times_sec]
                s = _compute_stats(times_ms)
                total_ms = sum(times_ms)
                qps = iterations / (total_ms / 1000) if total_ms else 0
                self.stdout.write(
                    f"  {name}\n"
                    f"    min={s['min']:.3f} ms  avg={s['avg']:.3f} ms  "
                    f"max={s['max']:.3f} ms  p95={s['p95']:.3f} ms  "
                    f"total={total_ms:.1f} ms  qps={qps:.0f}"
                )

        self.stdout.write(self.style.SUCCESS("Done."))
