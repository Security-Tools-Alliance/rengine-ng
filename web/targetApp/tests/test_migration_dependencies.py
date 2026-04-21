"""Guards migration graph invariants for targetApp / startScan domain move."""

from django.db import connection
from django.db.migrations.loader import MigrationLoader

from utils.test_base import BaseTestCase


class DomainMoveMigrationDependencyTestCase(BaseTestCase):
    """Ensure FK state referencing targetApp.domain is applied before Domain is removed from targetApp state."""

    def test_move_domain_tables_depends_on_startscan_0099(self) -> None:
        loader = MigrationLoader(connection, ignore_no_migrations=True)
        key = ("targetApp", "0051_move_domain_tables_to_startscan")
        migration = loader.graph.nodes[key]
        self.assertIn(
            ("startScan", "0099_add_scan_history_target_fk"),
            migration.dependencies,
        )
