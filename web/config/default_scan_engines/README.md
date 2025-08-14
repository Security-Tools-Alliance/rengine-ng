# 📡 Default Scan Engines

This directory contains the default scan engine configurations for reNgine.

## 🔧 How it works

### Automatic loading
- On **first startup**, engines from this directory are automatically loaded
- On **subsequent startups**, they are **NOT reloaded** to preserve user modifications
- If no default engines exist, they will be loaded automatically

### File structure
- Each `.yaml` file corresponds to a scan engine
- The **filename** (without extension) becomes the **engine name**
- The file content is the YAML configuration of the engine

## 🔄 Updating engines

### Method 1: Automatic script (recommended)
```bash
./scripts/update_default_engines.sh
```

### Method 2: Django command
```bash
# Force update (overwrites existing engines)
python3 manage.py updatedefaultengines --force

# Load only if no default engines exist
python3 manage.py loaddefaultengines
```

## 📋 Available engines

The following engines are available in this directory:

- **Initial Scan - reNgine recommended**: Recommended scan for initial analysis
- **Initial Scan - Passive**: Fast passive scan
- **Initial Scan - Passive with screenshots**: Passive scan with screenshots
- **Scan - Active**: Complete active scan (resource intensive)
- **Subscan - Screenshots**: Screenshots only
- **Subscan - Port scan**: Port scan only
- **Subscan - Vulnerabilities**: Vulnerability scan only
- **Subscan - WAF Detection**: WAF detection
- **Subscan - File fuzzing**: File and directory fuzzing
- **Subscan - Fetch URLs**: URL fetching

## ⚠️ Important notes

1. **Preserve modifications**: User-modified engines will not be overwritten on startup
2. **Manual update**: To update default engines, use the commands above
3. **Backup**: Consider backing up your custom configurations before a forced update

## 🛠️ Development

To add a new default engine:
1. Create a `.yaml` file in this directory
2. Use the desired engine name as the filename
3. Add the YAML configuration of the engine
4. Run the update: `./scripts/update_default_engines.sh` 