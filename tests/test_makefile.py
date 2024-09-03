"""
This module contains tests for the Makefile commands in the reNgine-ng project.
It verifies various make commands and their effects on the Docker environment.
"""

import os
import unittest
import subprocess
import time
import signal
import sys
from functools import wraps
from docker import from_env as docker_from_env
from docker.errors import NotFound

# Add these constants for colors
BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
ENDC = '\033[0m'

print("Starting test_makefile.py")
print(f"Current working directory: {os.getcwd()}")

RENGINE_PATH = "/home/rengine/rengine"

# Read version from version.txt
with open(
    f"{RENGINE_PATH}/web/reNgine/version.txt", "r", encoding="utf-8"
) as version_file:
    RENGINE_VERSION = version_file.read().strip()


class TestMakefile(unittest.TestCase):
    """
    A test suite for verifying the functionality of the Makefile commands in the reNgine-ng project.
    This class tests various make commands and their effects on the Docker environment.
    """

    expected_services = [
        "rengine-web-1",
        "rengine-db-1",
        "rengine-celery-1",
        "rengine-celery-beat-1",
        "rengine-redis-1",
        "rengine-proxy-1",
        "rengine-ollama-1",
    ]
    expected_images = [
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-celery-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-web-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-postgres-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-redis-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-ollama-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-certs-v{RENGINE_VERSION}",
        f"ghcr.io/security-tools-alliance/rengine-ng:rengine-proxy-v{RENGINE_VERSION}",
    ]

    @classmethod
    def setUpClass(cls):
        """
        Set up the test environment before running any tests.
        This method initializes the Docker client.
        """
        cls.client = docker_from_env()

        # Search for the Makefile by traversing up the parent directories
        cls.makefile_dir = cls.find_makefile_directory()
        if not cls.makefile_dir:
            raise FileNotFoundError("Makefile not found in the current directory or its parents")

        # Change the working directory to the one containing the Makefile
        os.chdir(cls.makefile_dir)
        print(f"Changed working directory to: {os.getcwd()}")

    @classmethod
    def find_makefile_directory(cls):
        """
        Search for the directory containing the Makefile by traversing up the directory tree.
        """
        current_dir = os.path.abspath(os.getcwd())
        while current_dir != '/':
            if os.path.exists(os.path.join(current_dir, 'Makefile')):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        return None

    @classmethod
    def tearDownClass(cls):
        """
        Clean up the test environment after all tests have been run.
        This method stops all services.
        """
        cls.run_make_command("down")

    @classmethod
    def run_make_command(cls, command, capture_output=False, env_vars=None):
        """
        Run a make command and optionally capture its output.
        """
        cmd = f"make {command}"
        if env_vars:
            cmd = " ".join([f"{k}={v}" for k, v in env_vars.items()]) + " " + cmd

        print(f"{YELLOW}Executing command: {cmd}{ENDC}")
        if capture_output:
            make_result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=False
            )
            if make_result.returncode != 0:
                print(f"Command failed. Stderr: {make_result.stderr}")
            return make_result.stdout, make_result.stderr, make_result.returncode
        make_result = subprocess.run(cmd, shell=True, check=False)
        if make_result.returncode != 0:
            print(f"Command failed. Returncode: {make_result.returncode}")
        return make_result.returncode

    def assert_containers_running(self):
        """
        Assert that all expected services are running.
        """
        running_containers = self.client.containers.list()
        for service in self.expected_services:
            container = next((c for c in running_containers if service in c.name), None)
            self.assertIsNotNone(container, f"Service {service} is not running")
            self.assertEqual(
                container.status,
                "running",
                f"Container {container.name} is not in 'running' state",
            )

    def clean_secrets(self):
        """
        Clean up the secrets directory.
        """
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    @staticmethod
    def with_cleanup(func):
        """
        Decorator to ensure cleanup after test execution.
        """

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            finally:
                self.clean_secrets()
        return wrapper

    def test_pull(self):
        """
        Test the `make pull` command.
        This test verifies that all required Docker images can be pulled successfully.
        """
        returncode = self.run_make_command("pull")
        self.assertEqual(returncode, 0)
        images = self.client.images.list()
        for image in self.expected_images:
            self.assertTrue(
                any(image in img.tags[0] for img in images if img.tags),
                f"Image {image} not found",
            )

    def test_images(self):
        """
        Test the `make images` command.
        This test verifies that all required Docker images are present and correctly tagged.
        """
        self.run_make_command("pull")
        stdout, _, returncode = self.run_make_command(
            "images", capture_output=True
        )
        self.assertEqual(returncode, 0)
        for image in self.expected_images:
            repo, tag = image.split(":")
            self.assertIn(repo, stdout, f"Repository {repo} not found in output")
            self.assertIn(tag, stdout, f"Tag {tag} not found in output")

    @with_cleanup
    def test_start_services_up(self):
        """
        Test the `make up` command.
        This test verifies that the application can be started successfully with the 'up' command.
        """
        print(f"{BLUE}test_start_services_up{ENDC}")
        print(f"{CYAN}Test the 'up' make command. ... {ENDC}\n")
        self._test_start_services("up", {})

    @with_cleanup
    def test_start_services_build(self):
        """
        Test the `make build` command.
        This test verifies that the application can be built and started successfully with the 'build' command.
        """
        print(f"{BLUE}test_start_services_build{ENDC}")
        print(f"{CYAN}Test the 'build' make command. ... {ENDC}\n")
        self._test_start_services("build", {})

    def _test_start_services(self, command, env_vars):
        """
        Helper method to test start services.
        This method contains the common logic for testing 'up' and 'build' commands.
        """
        self.run_make_command("down")
        self.run_make_command("certs")

        if "build" in command:
            _, stderr, returncode = self.run_make_command(
                command, capture_output=True, env_vars=env_vars
            )
            self.assertEqual(
                returncode, 0, f"Build command failed with error: {stderr}"
            )
            _, stderr, returncode = self.run_make_command(
                "up", capture_output=True, env_vars=env_vars
            )
        else:
            _, stderr, returncode = self.run_make_command(
                command, capture_output=True, env_vars=env_vars
            )

        self.assertEqual(
            returncode, 0, f"{command} command failed with error: {stderr}"
        )
        self.assert_containers_running()

    @with_cleanup
    def test_restart_services(self):
        """
        Test the `make restart` command with various configurations.
        This test verifies that services can be restarted successfully in different scenarios.
        """
        print(f"{BLUE}test_restart_services (__main__.TestMakefile.test_restart_services){ENDC}")
        print(f"{CYAN}Test the 'restart' make command with various configurations. ... {ENDC}")
        scenarios = [
            ("restart", {}, []),
            ("restart", {"DEV": "1"}, []),
            ("restart", {"COLD": "1"}, []),
            ("restart", {}, ["web"]),
            ("restart", {}, ["celery"]),
        ]

        for command, env_vars, services in scenarios:
            with self.subTest(command=command, env_vars=env_vars, services=services):
                self._test_restart_services(command, env_vars, services)

    def _test_restart_services(self, command, env_vars, services):
        """
        Helper method to test restart services.
        This method contains the common logic for testing various restart scenarios.
        """
        self.run_make_command("certs")
        self.run_make_command("up")

        restart_command = f"{command} {' '.join(services)}"
        _, stderr, returncode = self.run_make_command(
            restart_command.strip(), capture_output=True, env_vars=env_vars
        )

        self.assertEqual(returncode, 0, f"Restart command failed with error: {stderr}")
        self.assert_containers_running()

    @with_cleanup
    def test_logs(self):
        """
        Test the `make logs` command.
        This test verifies that logs can be retrieved and contain expected content.
        It ensures services are up before checking logs and limits the log collection time.
        """
        self.run_make_command("certs")
        self.run_make_command("up")

        logs_process = subprocess.Popen(
            "make logs",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        time.sleep(5)
        os.killpg(os.getpgid(logs_process.pid), signal.SIGTERM)
        stdout, _ = logs_process.communicate(timeout=1)

        expected_services = [
            "redis-1",
            "db-1",
            "web-1",
            "celery-1",
            "celery-beat-1",
            "ollama-1",
            "proxy-1",
        ]
        for service in expected_services:
            self.assertIn(service, stdout, f"Logs for {service} not found")

    @with_cleanup
    def test_superuser(self):
        """
        Test the superuser-related make commands.
        This test verifies that a superuser can be created, its password changed, and then deleted.
        """
        self.run_make_command("certs")
        self.run_make_command("up")

        create_result = subprocess.run(
            "make superuser_create isNonInteractive=true",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            create_result.returncode,
            0,
            f"Superuser creation failed with error: {create_result.stderr}",
        )
        self.assertIn("Superuser created successfully", create_result.stdout)

        changepassword_result = subprocess.run(
            "make superuser_changepassword isNonInteractive=true",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            changepassword_result.returncode,
            0,
            f"Superuser password change failed with error: {changepassword_result.stderr}",
        )

        delete_result = subprocess.run(
            "make superuser_delete",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            delete_result.returncode,
            0,
            f"Superuser deletion failed with error: {delete_result.stderr}",
        )

    @with_cleanup
    def test_migrate(self):
        """
        Test the `make migrate` command.
        This test verifies that database migrations can be applied successfully.
        """
        # First, generate certificates and start services
        self.run_make_command("certs")
        self.run_make_command("up")

        # Now run the migrate command
        stdout, _, returncode = self.run_make_command(
            "migrate", capture_output=True
        )
        self.assertEqual(returncode, 0)
        self.assertIn("Apply all migrations", stdout)

    @with_cleanup
    def test_certs(self):
        """
        Test the `make certs` command.
        This test verifies that SSL certificates can be generated successfully.
        """
        returncode = self.run_make_command("certs")
        self.assertEqual(returncode, 0)
        self.assertTrue(
            os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine_chain.pem")
        )
        self.assertTrue(
            os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine_rsa.key")
        )
        self.assertTrue(
            os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine.pem")
        )

    @with_cleanup
    def test_down(self):
        """
        Test the `make down` command.
        This test verifies that all services can be stopped successfully.
        """
        # First, generate certificates and start services
        self.run_make_command("certs")
        self.run_make_command("up")

        # Execute the 'down' command
        returncode = self.run_make_command("down")
        self.assertEqual(returncode, 0)

        # Verify that none of the expected services are running
        running_containers = self.client.containers.list()
        for service in self.expected_services:
            self.assertFalse(
                any(service in container.name for container in running_containers),
                f"Service {service} is still running after 'down' command",
            )

        # Verify that all associated containers are stopped
        all_containers = self.client.containers.list(all=True)
        for container in all_containers:
            if any(service in container.name for service in self.expected_services):
                try:
                    container_info = container.attrs
                    self.assertIn(
                        container_info["State"]["Status"],
                        ["exited", "dead"],
                        f"Container {container.name} is not stopped after 'down' command",
                    )
                except NotFound:
                    # If the container is not found, it's considered stopped
                    pass

    def test_prune(self):
        """
        Test the `make prune` command.
        This test verifies that unused Docker volumes can be removed successfully.
        """
        # Ensure all services are down before pruning
        self.run_make_command("down")

        # Run the prune command
        returncode = self.run_make_command("prune")
        self.assertEqual(returncode, 0, "Prune command failed")

        # Check for reNgine-related volumes
        volumes = self.client.volumes.list()
        rengine_volumes = [v for v in volumes if v.name.startswith("rengine_")]

        if rengine_volumes:
            volume_names = ", ".join([v.name for v in rengine_volumes])
            self.fail(f"reNgine volumes still exist after pruning: {volume_names}")

        print(f"Total volumes remaining: {len(volumes)}")
        print("Volumes not removed:")
        for volume in volumes:
            print(f"- {volume.name}")

def suite(tests_to_run=None, exclude_build=False):
    """
    Create a test suite with specified or all tests.
    
    Args:
    tests_to_run (list): List of test names to run. If None, all tests are run.
    exclude_build (bool): If True, excludes the build test from the suite.

    Returns:
    unittest.TestSuite: The test suite to run.
    """
    all_tests = [
        "test_certs",
        "test_pull",
        "test_images",
        "test_start_services_up",
        "test_superuser",
        "test_migrate",
        "test_logs",
        "test_restart_services",
        "test_start_services_build",
        "test_down",
        "test_prune",
    ]

    if exclude_build:
        all_tests.remove("test_start_services_build")

    tests_to_execute = tests_to_run if tests_to_run else all_tests

    test_suite = unittest.TestSuite()
    executed_tests = []
    skipped_tests = []

    for test in tests_to_execute:
        if test in all_tests:
            test_method = getattr(TestMakefile, test, None)
            if test_method and callable(test_method):
                test_suite.addTest(TestMakefile(test))
                executed_tests.append(test)
            else:
                skipped_tests.append(test)
                print(f"Warning: Test method '{test}' not found in TestMakefile. Skipping.")
        else:
            skipped_tests.append(test)
            print(f"Warning: Test '{test}' not in the list of available tests. Skipping.")

    # Store test information for later display
    test_info = {
        'executed': executed_tests,
        'skipped': skipped_tests
    }

    return test_suite, test_info


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run reNgine-ng Makefile tests")
    parser.add_argument("--exclude-build", action="store_true", help="Exclude build test")
    parser.add_argument("--tests", nargs="*", help="Specific tests to run")
    args = parser.parse_args()

    runner = unittest.TextTestRunner(verbosity=1)
    test_suite, test_info = suite(args.tests, args.exclude_build)
    result = runner.run(test_suite)

    # Display test summary
    print(f"\n{GREEN}Test Execution Summary:{ENDC}")
    print(f"{YELLOW}Tests executed:{ENDC}")
    for test in test_info['executed']:
        print(f"- {test}")
    if test_info['skipped']:
        print(f"\n{RED}Tests skipped:{ENDC}")
        for test in test_info['skipped']:
            print(f"- {test}")

    sys.exit(not result.wasSuccessful())
