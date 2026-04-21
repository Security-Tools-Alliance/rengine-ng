"""Optional Node-based unit tests for ``rengine_datatable_port_endpoint_pure.js``."""

from pathlib import Path
import shutil
import subprocess
import unittest

from django.test import SimpleTestCase


@unittest.skipUnless(shutil.which("node"), "node is not installed (optional in web Docker image)")
class RengineDatatablePortEndpointPureJsTests(SimpleTestCase):
    def test_pure_helpers_node_unit_tests(self) -> None:
        test_script = Path(__file__).resolve().parent / "rengine_datatable_port_endpoint_pure.test.cjs"
        web_root = Path(__file__).resolve().parents[3]
        proc = subprocess.run(
            ["node", "--test", str(test_script)],
            cwd=web_root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
