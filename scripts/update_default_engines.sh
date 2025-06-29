#!/bin/bash

# Script to update default scan engines
# Usage: ./scripts/update_default_engines.sh

echo "=== Default Scan Engines Update ==="
echo

# Check if engines directory exists
if [ ! -d "web/config/default_scan_engines" ]; then
    echo "❌ Error: web/config/default_scan_engines directory does not exist"
    exit 1
fi

# Count YAML files
engine_count=$(find web/config/default_scan_engines -name "*.yaml" | wc -l)
echo "📁 Engines found: $engine_count YAML files"

# List files
echo "📋 Detected files:"
find web/config/default_scan_engines -name "*.yaml" -exec basename {} \; | sort

echo
read -p "❓ Do you want to update default engines? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Updating..."
    
    # Check if running in Docker container or dev mode
    if [ -f "/.dockerenv" ] || [ -n "$CONTAINER" ]; then
        # Container mode
        echo "🐳 Container mode detected"
        python3 web/manage.py updatedefaultengines --force
    else
        # Local development mode
        echo "💻 Local development mode"
        cd web && python3 manage.py updatedefaultengines --force
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ Update completed successfully!"
    else
        echo "❌ Error during update"
        exit 1
    fi
else
    echo "❌ Update cancelled"
    exit 0
fi 