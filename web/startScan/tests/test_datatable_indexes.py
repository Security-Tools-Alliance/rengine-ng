"""
Tests that DataTable sort/filter performance indexes exist in the database.

Ensures the indexes added for Subdomain, EndPoint and Vulnerability
DataTable ordering (subdomains.html, detail_scan.html, endpoints) are present.
Assertions use both indexname and tablename (model._meta.db_table) to avoid
false positives if similarly named indexes exist on other tables.
"""

from django.db import connection

from startScan.models import EndPoint, Subdomain, Vulnerability
from utils.test_base import BaseTestCase


# Index name -> expected db table (from migration 0096_add_secator_sync_indexes)
EXPECTED_DATATABLE_INDEX_TO_TABLE = {
    "ss_sub_scan_content_len": Subdomain._meta.db_table,
    "ss_ep_scan_content_len": EndPoint._meta.db_table,
    "ss_vuln_scan_cvss_idx": Vulnerability._meta.db_table,
    "ss_vuln_scan_severity_idx": Vulnerability._meta.db_table,
}


class DatatableIndexesTestCase(BaseTestCase):
    """Verify that DataTable-related indexes exist in the database."""

    def test_datatable_indexes_exist(self):
        """All DataTable sort indexes must exist on the expected tables."""
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT indexname, tablename
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND indexname = ANY(%s)
                """,
                [list(EXPECTED_DATATABLE_INDEX_TO_TABLE)],
            )
            existing_by_index = {row[0]: row[1] for row in cursor.fetchall()}

        missing = set(EXPECTED_DATATABLE_INDEX_TO_TABLE) - set(existing_by_index)
        self.assertFalse(
            missing,
            "Missing DataTable indexes in database: %s. Run migrations: manage.py migrate startScan." % (missing,),
        )
        for indexname, expected_table in EXPECTED_DATATABLE_INDEX_TO_TABLE.items():
            actual_table = existing_by_index.get(indexname)
            self.assertEqual(
                actual_table,
                expected_table,
                "Index %s should be on table %s, found on %s" % (indexname, expected_table, actual_table),
            )
