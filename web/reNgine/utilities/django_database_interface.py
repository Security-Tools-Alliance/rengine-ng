"""
Django database interface implementation.

This module provides the Django-specific implementation of the database interface.
It should only be imported and used in the tasks layer, not in utilities.
"""

from typing import Any, Dict, List, Optional
from reNgine.utilities.database_interface import (
    DatabaseInterface, 
    DatabaseRecord, 
    QueryFilter
)


class DjangoDatabaseInterface(DatabaseInterface):
    """Django-specific database interface implementation"""
    
    def __init__(self):
        # Import Django models only when this class is instantiated
        # This prevents circular imports during Django initialization
        self._models = None
        self._load_models()
    
    def _load_models(self):
        """Lazy load Django models"""
        if self._models is None:
            from startScan.models import (
                Command, CveId, CweId, DirectoryFile, Email, Employee, EndPoint,
                IpAddress, MetaFinderDocument, ScanActivity, ScanHistory,
                Subdomain, Technology, Vulnerability, VulnerabilityTags
            )
            from targetApp.models import Domain
            
            self._models = {
                'command': Command,
                'endpoint': EndPoint,
                'subdomain': Subdomain,
                'vulnerability': Vulnerability,
                'domain': Domain,
                'scan_history': ScanHistory,
                'ip_address': IpAddress,
                'email': Email,
                'employee': Employee,
                'cve_id': CveId,
                'cwe_id': CweId,
                'directory_file': DirectoryFile,
                'meta_finder_document': MetaFinderDocument,
                'scan_activity': ScanActivity,
                'vulnerability_tags': VulnerabilityTags,
                'technology': Technology,
            }
    
    def _get_model(self, model_name: str):
        """Get Django model by name"""
        if self._models is None:
            self._load_models()
        return self._models.get(model_name)
    
    def _convert_to_record(self, django_obj) -> DatabaseRecord:
        """Convert Django object to DatabaseRecord"""
        if django_obj is None:
            return DatabaseRecord()
        
        data = {}
        for field in django_obj._meta.fields:
            data[field.name] = getattr(django_obj, field.name)
        
        return DatabaseRecord(
            id=django_obj.pk,
            data=data
        )
    
    def _convert_from_record(self, record: DatabaseRecord, model_class):
        """Convert DatabaseRecord to Django object"""
        if record.id:
            # Update existing record
            obj = model_class.objects.get(pk=record.id)
            for key, value in record.data.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
            return obj
        else:
            # Create new record
            return model_class(**record.data)
    
    def create_record(self, model_name: str, data: Dict[str, Any]) -> DatabaseRecord:
        """Create a new record"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        obj = model_class.objects.create(**data)
        return self._convert_to_record(obj)
    
    def get_record(self, model_name: str, record_id: int) -> Optional[DatabaseRecord]:
        """Get a record by ID"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        try:
            obj = model_class.objects.get(pk=record_id)
            return self._convert_to_record(obj)
        except model_class.DoesNotExist:
            return None
    
    def filter_records(self, model_name: str, filters: List[QueryFilter]) -> List[DatabaseRecord]:
        """Filter records by criteria"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        query = model_class.objects.all()
        
        for filter_obj in filters:
            field_name = f"{filter_obj.field}__{filter_obj.operator}"
            query = query.filter(**{field_name: filter_obj.value})
        
        return [self._convert_to_record(obj) for obj in query]
    
    def update_record(self, model_name: str, record_id: int, data: Dict[str, Any]) -> bool:
        """Update a record"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        try:
            obj = model_class.objects.get(pk=record_id)
            for key, value in data.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)
            obj.save()
            return True
        except model_class.DoesNotExist:
            return False
    
    def delete_record(self, model_name: str, record_id: int) -> bool:
        """Delete a record"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        try:
            obj = model_class.objects.get(pk=record_id)
            obj.delete()
            return True
        except model_class.DoesNotExist:
            return False
    
    def bulk_create(self, model_name: str, records: List[Dict[str, Any]]) -> List[DatabaseRecord]:
        """Bulk create records"""
        model_class = self._get_model(model_name)
        if not model_class:
            raise ValueError(f"Unknown model: {model_name}")
        
        objects = [model_class(**record_data) for record_data in records]
        created_objects = model_class.objects.bulk_create(objects)
        return [self._convert_to_record(obj) for obj in created_objects]


def create_django_database_interface() -> DjangoDatabaseInterface:
    """Factory function to create Django database interface"""
    return DjangoDatabaseInterface()
