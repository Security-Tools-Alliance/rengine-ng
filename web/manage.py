#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from reNgine.settings import UI_REMOTE_DEBUG

# Remote debug setup for Web GUI
if UI_REMOTE_DEBUG and sys.argv[1] == 'runserver':
    from debugger_setup import setup_debugger
    setup_debugger()

def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
    
    # List of commands that should not display the rengine artwork
    skip_art_commands = ['test', 'dumpdata']
    
    # Do not show rengine artwork if we are running tests
    if all(cmd not in sys.argv for cmd in skip_art_commands):
        # show rengine artwork
        try:
            with open('art/reNgine.txt', 'r', encoding='utf-8') as f:
                file_contents = f.read()
                print(file_contents)
        except FileNotFoundError:
            print("Failed to display reNgine artwork.")
    
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
