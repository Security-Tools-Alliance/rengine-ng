"""
Unit tests for reNgine.core.db.resolve_db_host_port.
"""

import sys
import unittest
from unittest import mock

from reNgine.core.db import resolve_db_host_port


def _make_environ(
    host="pgbouncer",
    port="6432",
    direct_host="db",
    direct_port="5432",
    **kwargs,
):
    defaults = {
        "POSTGRES_HOST": host,
        "POSTGRES_PORT": port,
        "POSTGRES_DIRECT_HOST": direct_host,
        "POSTGRES_DIRECT_PORT": direct_port,
        "POSTGRES_DB": "rengine",
        "POSTGRES_USER": "rengine",
        "POSTGRES_PASSWORD": "secret",
    }
    defaults.update(kwargs)

    def environ(key, default=None):
        return defaults.get(key, default)

    return environ


class ResolveDbHostPortTestCase(unittest.TestCase):
    """Tests for resolve_db_host_port."""

    def test_test_mode_uses_direct_when_use_pgbouncer(self):
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "test"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_createsuperuser_uses_direct_when_use_pgbouncer(self):
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "createsuperuser"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_makemigrations_uses_direct_when_use_pgbouncer(self):
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "makemigrations"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_makemigrations_uses_direct_when_argv_is_python_manage_py_cmd(self):
        """Invocation as python3 manage.py makemigrations (e.g. from entrypoint) uses direct DB."""
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["python3", "manage.py", "makemigrations"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_entrypoint_setup_uses_direct_when_use_pgbouncer(self):
        """entrypoint_setup (and its sub-calls) use direct DB to avoid PgBouncer SCRAM issues."""
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "entrypoint_setup"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_run_scheduled_scans_uses_direct_when_use_pgbouncer(self):
        """run_scheduled_scans (background loop in container) uses direct DB to avoid PgBouncer."""
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "run_scheduled_scans"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")

    def test_test_mode_without_pgbouncer_uses_primary(self):
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, False, False, ["manage.py", "test"])
        self.assertEqual(host, "pgbouncer")
        self.assertEqual(port, "6432")

    def test_no_probe_returns_primary(self):
        environ = _make_environ()
        host, port = resolve_db_host_port(environ, True, False, ["manage.py", "runserver"])
        self.assertEqual(host, "pgbouncer")
        self.assertEqual(port, "6432")

    def test_probe_success_returns_primary(self):
        environ = _make_environ()
        m_conn = mock.MagicMock()
        m_psycopg2 = mock.MagicMock()
        m_psycopg2.connect.return_value = m_conn
        m_psycopg2.Error = Exception
        with mock.patch.dict(sys.modules, {"psycopg2": m_psycopg2}):
            host, port = resolve_db_host_port(environ, True, True, ["manage.py", "runserver"])
        self.assertEqual(host, "pgbouncer")
        self.assertEqual(port, "6432")
        m_conn.close.assert_called_once()

    def test_probe_connection_error_returns_direct(self):
        environ = _make_environ()
        m_psycopg2 = mock.MagicMock()
        m_psycopg2.Error = type("Error", (Exception,), {})
        m_psycopg2.connect.side_effect = m_psycopg2.Error("connection refused")
        with mock.patch.dict(sys.modules, {"psycopg2": m_psycopg2}):
            host, port = resolve_db_host_port(environ, True, True, ["manage.py", "runserver"])
        self.assertEqual(host, "db")
        self.assertEqual(port, "5432")
