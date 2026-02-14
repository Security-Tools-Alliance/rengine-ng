"""
Tests that scanEngine audit indexes exist in the database.

Ensures the indexes added for EXPLAIN-audited query patterns (EngineType,
SecatorWorkflow, SecatorProfile) are present to avoid regressions.
Assertions use both indexname and tablename (model._meta.db_table) to avoid
false positives if similarly named indexes exist on other tables.
"""

from django.db import connection

from scanEngine.models import EngineType, SecatorProfile, SecatorWorkflow
from utils.test_base import BaseTestCase


# Index name -> expected db table (from migration 0027_add_scanengine_audit_indexes)
EXPECTED_INDEX_TO_TABLE = {
    "se_enginetype_default_idx": EngineType._meta.db_table,
    "se_secatorprofile_nametype_idx": SecatorProfile._meta.db_table,
    "se_secatorworkflow_active_idx": SecatorWorkflow._meta.db_table,
}


class ScanEngineAuditIndexesTestCase(BaseTestCase):
    """Verify that scanEngine audit-related indexes exist in the database."""

    def test_scanengine_audit_indexes_exist(self):
        """All audit indexes for EngineType, SecatorWorkflow, SecatorProfile must exist on expected tables."""
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT indexname, tablename
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND indexname = ANY(%s)
                """,
                [list(EXPECTED_INDEX_TO_TABLE)],
            )
            existing_by_index = {row[0]: row[1] for row in cursor.fetchall()}

        missing = set(EXPECTED_INDEX_TO_TABLE) - set(existing_by_index)
        self.assertFalse(
            missing,
            "Missing scanEngine audit indexes in database: %s. "
            "Run migrations: manage.py migrate scanEngine." % (missing,),
        )
        for indexname, expected_table in EXPECTED_INDEX_TO_TABLE.items():
            actual_table = existing_by_index.get(indexname)
            self.assertEqual(
                actual_table,
                expected_table,
                "Index %s should be on table %s, found on %s" % (indexname, expected_table, actual_table),
            )
