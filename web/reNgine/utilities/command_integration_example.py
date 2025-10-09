"""
Example of how to use the refactored distributed command system.

This example shows how to properly integrate the database interface
with the distributed command processors in the tasks layer.
"""

from reNgine.utilities.distributed.command import (
    create_distributed_command_executor,
    execute_commands_distributed,
    execute_nmap_distributed,
    execute_httpx_distributed,
    execute_subfinder_distributed
)
from reNgine.utilities.django_database_interface import DjangoDatabaseInterface
from reNgine.utilities.database_interface import create_database_context


def example_command_execution():
    """Example of how to execute commands with the new architecture"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Create a distributed command executor with the database interface
    executor = create_distributed_command_executor(
        batch_size=5,
        worker_timeout=300,
        db_interface=django_db_interface
    )
    
    # 3. Sample commands to execute
    commands = [
        "echo 'Hello World'",
        "ls -la /tmp",
        "whoami",
        "date",
        "uname -a"
    ]
    
    # 4. Execute commands using the distributed system
    result = execute_commands_distributed(
        commands=commands,
        executor=executor,
        db_interface=django_db_interface,
        scan_id=1,
        activity_id=1
    )
    
    print(f"Command execution result: {result}")
    return result


def example_nmap_execution():
    """Example of how to execute nmap commands with the new architecture"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Sample targets for nmap
    targets = [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3"
    ]
    
    # 3. Execute nmap commands using the distributed system
    result = execute_nmap_distributed(
        targets=targets,
        ports=[22, 80, 443, 8080],
        script="vuln",
        db_interface=django_db_interface,
        scan_id=1,
        activity_id=1
    )
    
    print(f"Nmap execution result: {result}")
    return result


def example_httpx_execution():
    """Example of how to execute httpx commands with the new architecture"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Sample URLs for httpx
    urls = [
        "https://example.com",
        "https://test.com",
        "https://demo.com"
    ]
    
    # 3. Execute httpx commands using the distributed system
    result = execute_httpx_distributed(
        urls=urls,
        threads=5,
        follow_redirect=True,
        db_interface=django_db_interface,
        scan_id=1,
        activity_id=1
    )
    
    print(f"Httpx execution result: {result}")
    return result


def example_subfinder_execution():
    """Example of how to execute subfinder commands with the new architecture"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Sample domains for subfinder
    domains = [
        "example.com",
        "test.com",
        "demo.com"
    ]
    
    # 3. Execute subfinder commands using the distributed system
    result = execute_subfinder_distributed(
        domains=domains,
        sources=["crtsh", "virustotal", "shodan"],
        db_interface=django_db_interface,
        scan_id=1,
        activity_id=1
    )
    
    print(f"Subfinder execution result: {result}")
    return result


def example_with_database_context():
    """Example using the database context manager"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Use the database context
    with create_database_context(django_db_interface) as db_ops:
        # 3. Create executor with the interface
        executor = create_distributed_command_executor(
            db_interface=django_db_interface
        )
        
        # 4. Execute commands
        commands = [
            "echo 'Context test'",
            "ls -la /home"
        ]
        
        result = execute_commands_distributed(
            commands=commands,
            executor=executor,
            db_interface=django_db_interface,
            scan_id=2,
            activity_id=2
        )
        
        print(f"Context command execution result: {result}")
        return result


if __name__ == "__main__":
    # Run examples
    print("Running command execution example...")
    example_command_execution()
    
    print("\nRunning nmap execution example...")
    example_nmap_execution()
    
    print("\nRunning httpx execution example...")
    example_httpx_execution()
    
    print("\nRunning subfinder execution example...")
    example_subfinder_execution()
    
    print("\nRunning database context example...")
    example_with_database_context()
