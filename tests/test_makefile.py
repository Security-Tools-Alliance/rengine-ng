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
from docker import from_env as docker_from_env
from docker.errors import NotFound

print("Starting test_makefile.py")
print(f"Current working directory: {os.getcwd()}")

RENGINE_PATH = "/home/rengine/rengine"

# Read version from version.txt
with open(f"{RENGINE_PATH}/web/reNgine/version.txt", 'r', encoding="utf-8") as version_file:
    RENGINE_VERSION = version_file.read().strip()


class TestMakefile(unittest.TestCase):
    """
    A test suite for verifying the functionality of the Makefile commands in the reNgine-ng project.
    This class tests various make commands and their effects on the Docker environment.
    """

    expected_services = [
        'rengine-web-1',
        'rengine-db-1',
        'rengine-celery-1',
        'rengine-celery-beat-1',
        'rengine-redis-1',
        'rengine-proxy-1',
        'rengine-ollama-1'
    ]
    expected_images = [
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-celery-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-web-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-postgres-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-redis-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-ollama-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-certs-v{RENGINE_VERSION}',
        f'ghcr.io/security-tools-alliance/rengine-ng:rengine-proxy-v{RENGINE_VERSION}'
    ]

    @classmethod
    def setUpClass(cls):
        """
        Set up the test environment before running any tests.
        This method initializes the Docker client, generates certificates, and starts the services.
        """
        cls.client = docker_from_env()

    @classmethod
    def tearDownClass(cls):
        """
        Clean up the test environment after all tests have been run.
        This method stops all services.
        """
        cls.run_make_command("down")

    @classmethod
    def run_make_command(cls, command, capture_output=False):
        """
        Execute a make command and return its output.

        Args:
            command (str): The make command to run.
            capture_output (bool): Whether to capture and return stdout and stderr.

        Returns:
            int or tuple: The return code of the command, or a tuple containing stdout, stderr,
                          and the return code if capture_output is True.
        """
        if capture_output:
            result = subprocess.run(f"make {command}", shell=True, capture_output=True, text=True,
                                    check=False)
            return result.stdout, result.stderr, result.returncode
        result = subprocess.run(f"make {command}", shell=True, check=False)
        return result.returncode

    def test_pull(self):
        """
        Test the 'pull' make command.
        This test verifies that all required Docker images can be pulled successfully.
        """
        returncode = self.run_make_command("pull")
        self.assertEqual(returncode, 0)
        images = self.client.images.list()
        for image in self.expected_images:
            self.assertTrue(
                any(image in img.tags[0] for img in images if img.tags),
                f"Image {image} not found"
            )

    def test_images(self):
        """
        Test the 'images' make command.
        This test verifies that all expected Docker images are present.
        """
        # First, pull the images
        self.run_make_command("pull")

        stdout, stderr, returncode = self.run_make_command("images", capture_output=True)
        self.assertEqual(returncode, 0)
        for image in self.expected_images:
            repo, tag = image.split(':')
            self.assertIn(repo, stdout, f"Repository {repo} not found in output")
            self.assertIn(tag, stdout, f"Tag {tag} not found in output")

    def test_up(self):
        """
        Test the 'up' make command.
        This test verifies that all services can be started successfully.
        It first runs 'make certs' to ensure SSL certificates are available.
        """
        # First, generate certificates
        self.run_make_command("certs")

        # Now run 'make up'
        returncode = self.run_make_command("up")
        self.assertEqual(returncode, 0, "Failed to start services with 'make up'")

        # Verify that all services are created in 'running' state
        running_containers = self.client.containers.list()
        for service in self.expected_services:
            container = next((c for c in running_containers if service in c.name), None)
            self.assertIsNotNone(container, f"Service {service} is not running")
            self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

        # Clean up the secrets folder after the test
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_dev_up(self):
        """
        Test the 'dev_up' make command.
        This test verifies that the application can be started in development mode.
        """
        # First, remove the containers and generate certificates
        self.run_make_command("down")
        self.run_make_command("certs")

        returncode = self.run_make_command("dev_up")
        self.assertEqual(returncode, 0)

        # Verify that all services are created in 'running' state
        running_containers = self.client.containers.list()
        for service in self.expected_services:
            container = next((c for c in running_containers if service in c.name), None)
            self.assertIsNotNone(container, f"Service {service} is not running")
            self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

        # Clean up the secrets folder after the test
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_build_up(self):
        """
        Test the 'build_up' make command.
        This test verifies that the application can be built and started successfully.
        """
        # First, remove the containers and generate certificates
        self.run_make_command("down")

        stdout, stderr, returncode = self.run_make_command("build", capture_output=True)
        self.assertEqual(returncode, 0, f"Build command failed with error: {stderr}")

        stdout, stderr, returncode = self.run_make_command("certs", capture_output=True)
        self.assertEqual(returncode, 0, f"Certs command failed with error: {stderr}")

        # Now run 'make up'
        stdout, stderr, returncode = self.run_make_command("up", capture_output=True)
        self.assertEqual(returncode, 0, f"Up command failed with error: {stderr}")

        # Verify that all services are created in 'running' state
        running_containers = self.client.containers.list()
        for service in self.expected_services:
            container = next((c for c in running_containers if service in c.name), None)
            self.assertIsNotNone(container, f"Service {service} is not running")
            self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

        # Clean up the secrets folder after the test
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_restart(self):
        """
        Test the 'restart' make command.
        This test verifies that all services can be restarted successfully,
        both in normal and dev mode.
        """
        try:
            # First, generate certificates and start services
            self.run_make_command("certs")
            self.run_make_command("up")

            # Restart services in normal mode
            returncode = self.run_make_command("restart")
            self.assertEqual(returncode, 0)

            # Verify that all services are created in 'running' state
            running_containers = self.client.containers.list()
            for service in self.expected_services:
                container = next((c for c in running_containers if service in c.name), None)
                self.assertIsNotNone(container, f"Service {service} is not in the container list")
                self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

            # Restart services in dev mode
            returncode = self.run_make_command("restart DEV=1")
            self.assertEqual(returncode, 0)

            # Verify that all services are created in 'running' state
            running_containers = self.client.containers.list()
            for service in self.expected_services:
                container = next((c for c in running_containers if service in c.name), None)
                self.assertIsNotNone(container, f"Service {service} is not in the container list after dev restart")
                self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

            # Cold restart services
            returncode = self.run_make_command("restart COLD=1")
            self.assertEqual(returncode, 0)

            # Verify that all services are created in 'running' state
            running_containers = self.client.containers.list()
            for service in self.expected_services:
                container = next((c for c in running_containers if service in c.name), None)
                self.assertIsNotNone(container, f"Service {service} is not in the container list after cold restart")
                self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

            # Restart web service
            returncode = self.run_make_command("restart web")
            self.assertEqual(returncode, 0)

            # Verify that web services are created in 'running' state
            running_containers = self.client.containers.list()
            for service in ['rengine-web-1']:
                container = next((c for c in running_containers if service in c.name), None)
                self.assertIsNotNone(container, f"Service {service} is not in the container list after restart")
                self.assertEqual(container.status, 'running', f"Container {container.name} is not in 'running' state")

        finally:
            # Clean up
            secrets_path = f"{RENGINE_PATH}/docker/secrets"
            if os.path.exists(secrets_path):
                subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_logs(self):
        """
        Test the 'logs' make command.
        This test verifies that logs can be retrieved and contain expected content.
        It ensures services are up before checking logs and limits the log collection time.
        """
        try:
            # First, generate certificates and start services
            self.run_make_command("certs")
            self.run_make_command("up")

            # Run the logs command with a timeout
            logs_process = subprocess.Popen(
                "make logs",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True
            )

            # Wait for a short period to collect some logs
            time.sleep(5)  # Adjust this value as needed

            # Terminate the logs process
            os.killpg(os.getpgid(logs_process.pid), signal.SIGTERM)

            # Get the output
            stdout, stderr = logs_process.communicate(timeout=1)

            self.assertIn("redis-1", stdout)
            self.assertIn("db-1", stdout)   
            self.assertIn("web-1", stdout)
            self.assertIn("celery-1", stdout)
            self.assertIn("celery-beat-1", stdout)
            self.assertIn("ollama-1", stdout)
            self.assertIn("proxy-1", stdout)


        finally:
            # Clean up
            secrets_path = f"{RENGINE_PATH}/docker/secrets"
            if os.path.exists(secrets_path):
                subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_superuser(self):
        """
        Test the 'superuser' make command in non-interactive mode.
        This test verifies that a superuser can be created, password changed and deleted successfully.
        """
        try:
            # First, generate certificates and start services
            self.run_make_command("certs")
            self.run_make_command("up")

            # Create the superuser
            create_result = subprocess.run(
                "make superuser_create isNonInteractive=true",
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )

            self.assertEqual(create_result.returncode, 0, f"Superuser creation failed with error: {create_result.stderr}")
            self.assertIn("Superuser created successfully", create_result.stdout)

            # Change the superuser's password
            changepassword_result = subprocess.run(
                "make superuser_changepassword isNonInteractive=true",
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )

            self.assertEqual(changepassword_result.returncode, 0, f"Superuser password change failed with error: {changepassword_result.stderr}")

            # Delete the superuser
            delete_result = subprocess.run(
                "make superuser_delete",
                shell=True,
                capture_output=True,
                text=True,
                check=False
            )

            self.assertEqual(delete_result.returncode, 0, f"Superuser deletion failed with error: {delete_result.stderr}")

        finally:
            # Clean up
            secrets_path = f"{RENGINE_PATH}/docker/secrets"
            if os.path.exists(secrets_path):
                subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_migrate(self):
        """
        Test the 'migrate' make command.
        This test verifies that database migrations can be applied successfully.
        """
        # First, generate certificates and start services
        self.run_make_command("certs")
        self.run_make_command("up")

        # Now run the migrate command
        stdout, stderr, returncode = self.run_make_command("migrate", capture_output=True)
        self.assertEqual(returncode, 0)
        self.assertIn("Apply all migrations", stdout)

        # Clean up
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_certs(self):
        """
        Test the 'certs' make command.
        This test verifies that SSL certificates are generated correctly.
        """
        try:
            returncode = self.run_make_command("certs")
            self.assertEqual(returncode, 0)
            self.assertTrue(os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine_chain.pem"))
            self.assertTrue(os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine_rsa.key"))
            self.assertTrue(os.path.exists(f"{RENGINE_PATH}/docker/secrets/certs/rengine.pem"))
        finally:
            # Cleanup: remove the secrets folder after the test using sudo
            secrets_path = f"{RENGINE_PATH}/docker/secrets"
            if os.path.exists(secrets_path):
                subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_down(self):
        """
        Test the 'down' make command.
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
                f"Service {service} is still running after 'down' command"
            )

        # Verify that all associated containers are stopped
        all_containers = self.client.containers.list(all=True)
        for container in all_containers:
            if any(service in container.name for service in self.expected_services):
                try:
                    container_info = container.attrs
                    self.assertIn(
                        container_info['State']['Status'],
                        ['exited', 'dead'],
                        f"Container {container.name} is not stopped after 'down' command"
                    )
                except NotFound:
                    # If the container is not found, it's considered stopped
                    pass

        # Clean up the secrets folder after the test
        secrets_path = f"{RENGINE_PATH}/docker/secrets"
        if os.path.exists(secrets_path):
            subprocess.run(f"sudo rm -rf {secrets_path}", shell=True, check=False)

    def test_prune(self):
        """
        Test the 'prune' make command.
        This test verifies that unused Docker volumes related to reNgine can be removed successfully.
        """
        # Ensure all services are down before pruning
        self.run_make_command("down")

        # Run the prune command
        returncode = self.run_make_command("prune")
        self.assertEqual(returncode, 0, "Prune command failed")

        # Check for reNgine-related volumes
        volumes = self.client.volumes.list()
        rengine_volumes = [v for v in volumes if v.name.startswith('rengine_')]

        if rengine_volumes:
            volume_names = ', '.join([v.name for v in rengine_volumes])
            self.fail(f"reNgine volumes still exist after pruning: {volume_names}")

        print(f"Total volumes remaining: {len(volumes)}")
        print("Volumes not removed:")
        for volume in volumes:
            print(f"- {volume.name}")

def suite(tests_to_run=None):
    """
    Create a test suite that defines the order of test execution.

    Args:
        tests_to_run (list): List of test names to run. If None, run all tests.

    Returns:
        unittest.TestSuite: A test suite with ordered or specified tests.
    """
    all_tests = [
        'test_certs', 'test_pull', 'test_images', 'test_up', 'test_superuser', 'test_migrate',
        'test_logs', 'test_restart', 'test_down', 'test_dev_up', 'test_build_up', 'test_prune'
    ]

    test_suite = unittest.TestSuite()

    if tests_to_run is None:
        for test in all_tests:
            test_suite.addTest(TestMakefile(test))
    else:
        for test in tests_to_run:
            if test in all_tests:
                test_suite.addTest(TestMakefile(test))
            else:
                print(f"Warning: Test '{test}' not found. Skipping.")

    return test_suite


if __name__ == '__main__':
    tests_to_run = sys.argv[1:] if len(sys.argv) > 1 else None
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite(tests_to_run))
    sys.exit(not result.wasSuccessful())
