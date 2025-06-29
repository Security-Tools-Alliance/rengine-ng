import os
import yaml
from django.core.management.base import BaseCommand
from django.conf import settings
from scanEngine.models import EngineType


class Command(BaseCommand):
    help = 'Load default scan engines from config/default_scan_engines/ folder'

    def handle(self, *args, **kwargs):
        """Load default engines only if no default engines exist in database"""
        
        # Check if default engines already exist
        existing_default_engines = EngineType.objects.filter(default_engine=True).count()
        if existing_default_engines > 0:
            self.stdout.write(
                self.style.WARNING(
                    f'Default engines already exist ({existing_default_engines} found). Skipping load to preserve user modifications.'
                )
            )
            return

        # Load engines from config/default_scan_engines/
        engines_dir = os.path.join(settings.BASE_DIR, 'config', 'default_scan_engines')
        
        if not os.path.exists(engines_dir):
            self.stdout.write(
                self.style.ERROR(f'Default engines directory not found: {engines_dir}')
            )
            return

        loaded_count = 0
        yaml_files = [f for f in os.listdir(engines_dir) if f.endswith('.yaml')]
        
        for yaml_file in yaml_files:
            engine_name = os.path.splitext(yaml_file)[0]
            file_path = os.path.join(engines_dir, yaml_file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                
                # Create the engine with default_engine=True
                engine, created = EngineType.objects.get_or_create(
                    engine_name=engine_name,
                    defaults={
                        'yaml_configuration': yaml_content,
                        'default_engine': True
                    }
                )
                
                if created:
                    loaded_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Loaded engine: {engine_name}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Engine already exists: {engine_name}')
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to load {yaml_file}: {str(e)}')
                )

        self.stdout.write(
            self.style.SUCCESS(f'\nSuccessfully loaded {loaded_count} default scan engines.')
        ) 