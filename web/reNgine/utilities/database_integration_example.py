"""
Example of how to use the refactored distributed database system.

This example shows how to properly integrate the database interface
with the distributed processors in the tasks layer.
"""

from reNgine.utilities.distributed.database import (
    create_distributed_endpoint_processor,
    process_endpoints_distributed
)
from reNgine.utilities.django_database_interface import DjangoDatabaseInterface
from reNgine.utilities.database_interface import create_database_context


def example_endpoint_processing():
    """Example of how to process endpoints with the new architecture"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Create a distributed processor with the database interface
    processor = create_distributed_endpoint_processor(
        batch_size=10,
        worker_timeout=300,
        db_interface=django_db_interface
    )
    
    # 3. Sample endpoint data
    endpoints_data = [
        {
            'http_url': 'https://example.com/',
            'http_status': 200,
            'page_title': 'Example Page',
            'content_length': 1024,
            'content_type': 'text/html',
            'webserver': 'nginx',
            'response_time': 0.5,
            'is_default': True,
            'technologies': ['nginx', 'php']
        },
        {
            'http_url': 'https://example.com/api/',
            'http_status': 200,
            'page_title': 'API Endpoint',
            'content_length': 512,
            'content_type': 'application/json',
            'webserver': 'nginx',
            'response_time': 0.2,
            'is_default': False,
            'technologies': ['nginx', 'nodejs']
        }
    ]
    
    # 4. Context for the processing
    ctx = {
        'scan_history_id': 1,
        'domain_id': 1
    }
    
    # 5. Process endpoints using the distributed system
    result = process_endpoints_distributed(
        endpoints_data=endpoints_data,
        processor=processor,
        ctx=ctx,
        db_interface=django_db_interface
    )
    
    print(f"Processing result: {result}")
    return result


def example_with_database_context():
    """Example using the database context manager"""
    
    # 1. Create the Django-specific database interface
    django_db_interface = DjangoDatabaseInterface()
    
    # 2. Use the database context
    with create_database_context(django_db_interface) as db_ops:
        # 3. Create processor with the interface
        processor = create_distributed_endpoint_processor(
            db_interface=django_db_interface
        )
        
        # 4. Process data
        endpoints_data = [
            {
                'http_url': 'https://test.com/',
                'http_status': 200,
                'page_title': 'Test Page',
                'content_length': 2048,
                'content_type': 'text/html',
                'webserver': 'apache',
                'response_time': 1.0,
                'is_default': True,
                'technologies': ['apache', 'php']
            }
        ]
        
        ctx = {
            'scan_history_id': 2,
            'domain_id': 2
        }
        
        result = process_endpoints_distributed(
            endpoints_data=endpoints_data,
            processor=processor,
            ctx=ctx,
            db_interface=django_db_interface
        )
        
        print(f"Context processing result: {result}")
        return result


if __name__ == "__main__":
    # Run examples
    print("Running endpoint processing example...")
    example_endpoint_processing()
    
    print("\nRunning database context example...")
    example_with_database_context()
