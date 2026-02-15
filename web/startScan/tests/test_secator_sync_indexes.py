"""
Tests that Secator runner sync performance indexes exist in the database.

Ensures the composite indexes added for _sync_runner_with_scan_history and
_is_all_runners_completed (and related queries) are present to avoid regressions.
Assertions use both indexname and tablename (model._meta.db_table) to avoid
false positives if similarly named indexes exist on other tables.
"""

from django.db import connection

from startScan.models import Command, ScanActivity, SecatorRunner, SubScan
from utils.test_base import BaseTestCase


# Index name -> expected db table (from migrations 0096 and 0097_secatorrunner_covering_index)
EXPECTED_INDEX_TO_TABLE = {
    "startScan_c_scan_hi_3a5c4a_idx": Command._meta.db_table,
    "startScan_s_scan_of_3c4d7a_idx": ScanActivity._meta.db_table,
    "startScan_s_scan_of_c9bdd4_idx": ScanActivity._meta.db_table,
    "startScan_s_scan_hi_a578c6_idx": SecatorRunner._meta.db_table,
    "startScan_s_scan_hi_5c36dc_idx": SubScan._meta.db_table,
    "ss_runner_scan_type_created": SecatorRunner._meta.db_table,
    "ss_runner_scan_created_cov": SecatorRunner._meta.db_table,
}


class SecatorSyncIndexesTestCase(BaseTestCase):
    """Verify that Secator sync-related composite indexes exist in the database."""

    def test_secator_sync_indexes_exist(self):
        """All composite indexes for runner sync queries must exist on the expected tables."""
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT indexname, tablename
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND tablename IN (%s, %s, %s, %s)
                """,
                [
                    Command._meta.db_table,
                    ScanActivity._meta.db_table,
                    SecatorRunner._meta.db_table,
                    SubScan._meta.db_table,
                ],
            )
            existing_by_index = {row[0]: row[1] for row in cursor.fetchall()}

        missing = set(EXPECTED_INDEX_TO_TABLE) - set(existing_by_index)
        self.assertFalse(
            missing,
            "Missing Secator sync indexes in database: %s. Run migrations: manage.py migrate startScan." % (missing,),
        )
        for indexname, expected_table in EXPECTED_INDEX_TO_TABLE.items():
            actual_table = existing_by_index.get(indexname)
            self.assertEqual(
                actual_table,
                expected_table,
                "Index %s should be on table %s, found on %s" % (indexname, expected_table, actual_table),
            )
