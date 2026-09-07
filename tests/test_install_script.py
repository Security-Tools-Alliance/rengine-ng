import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "install.sh"


def run_bash(script, cwd=None):
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd or ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


class InstallScriptTest(unittest.TestCase):
    def test_help_works_without_sudo_from_another_directory(self):
        result = subprocess.run(
            ["bash", str(INSTALL_SCRIPT), "--help"],
            cwd="/tmp",
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--non-interactive", result.stdout)

    def test_env_loader_preserves_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "INSTALL_TYPE=source\n"
                "GPU=0\n"
                "DJANGO_SUPERUSER_USERNAME=admin\n"
                "DJANGO_SUPERUSER_EMAIL=admin@example.com\n"
                "DJANGO_SUPERUSER_PASSWORD=p@ss&word#value\n",
                encoding="utf-8",
            )
            result = run_bash(
                f'source "{INSTALL_SCRIPT}"; '
                "load_installer_env; "
                'printf "%s|%s" "$INSTALL_TYPE" "$DJANGO_SUPERUSER_PASSWORD"',
                cwd=directory,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "source|p@ss&word#value")

    def test_gpu_values_are_updated_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "GPU=0\nGPU_TYPE=none\nDOCKER_RUNTIME=none\nGPU=0\n",
                encoding="utf-8",
            )
            result = run_bash(
                f'source "{INSTALL_SCRIPT}"; set_gpu_environment 1 nvidia',
                cwd=directory,
            )
            content = env_file.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(content.count("GPU="), 1)
        self.assertEqual(content.count("GPU_TYPE="), 1)
        self.assertEqual(content.count("DOCKER_RUNTIME="), 1)
        self.assertIn("GPU=1", content)
        self.assertIn("GPU_TYPE=nvidia", content)
        self.assertIn("DOCKER_RUNTIME=nvidia", content)

    def test_required_env_rejects_mismatched_database_users(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "POSTGRES_DB=rengine\n"
                "POSTGRES_USER=rengine\n"
                "PGUSER=other-user\n"
                "POSTGRES_PASSWORD=secret\n"
                "POSTGRES_HOST=db\n",
                encoding="utf-8",
            )
            result = run_bash(
                f'source "{INSTALL_SCRIPT}"; validate_required_env',
                cwd=directory,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("POSTGRES_USER and PGUSER", result.stdout)


if __name__ == "__main__":
    unittest.main()
