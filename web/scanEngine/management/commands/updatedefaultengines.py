import os
import yaml
from django.core.management.base import BaseCommand
from django.conf import settings
from scanEngine.models import EngineType


class Command(BaseCommand):
    help = 'Force update default scan engines from config/default_scan_engines/ folder'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force update all default engines (overwrites existing ones)',
        )

    def handle(self, *args, **options):
        """Force update default engines from config files"""
        
        engines_dir = os.path.join(settings.BASE_DIR, 'config', 'default_scan_engines')
        
        if not os.path.exists(engines_dir):
            self.stdout.write(
                self.style.ERROR(f'Default engines directory not found: {engines_dir}')
            )
            return

        if not options['force']:
            self.stdout.write(
                self.style.WARNING(
                    'This command will update/overwrite existing default engines.\n'
                    'Use --force to confirm this action.'
                )
            )
            return

        updated_count = 0
        created_count = 0
        yaml_files = [f for f in os.listdir(engines_dir) if f.endswith('.yaml')]
        
        for yaml_file in yaml_files:
            engine_name = os.path.splitext(yaml_file)[0]
            file_path = os.path.join(engines_dir, yaml_file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                
                # Update or create the engine
                engine, created = EngineType.objects.update_or_create(
                    engine_name=engine_name,
                    defaults={
                        'yaml_configuration': yaml_content,
                        'default_engine': True
                    }
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Created engine: {engine_name}')
                    )
                else:
                    updated_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'↻ Updated engine: {engine_name}')
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to process {yaml_file}: {str(e)}')
                )

        self.stdout.write(
            self.style.SUCCESS(
                f'\nCompleted: {created_count} engines created, {updated_count} engines updated.'
            )
        ) 