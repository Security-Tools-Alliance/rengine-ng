#!/bin/bash
set -e

# =========================================================================
# Temporary for debug: Install Secator from local repo
# This entrypoint installs Secator from /opt/secator for local development
# =========================================================================

echo "🔧 Secator worker entrypoint starting..." >&2

# Step 1: Uninstall existing Secator if installed via pipx
echo "🔧 Step 1: Uninstalling existing Secator..." >&2
if pipx list | grep -q secator; then
    echo "   → Found Secator installed, uninstalling..." >&2
    pipx uninstall secator 2>&1 || echo "   ⚠️  Could not uninstall Secator (might not be installed)" >&2
else
    echo "   ✅ Secator not installed via pipx, skipping uninstall" >&2
fi

# Step 2: Check if Secator repo exists in /opt/secator
echo "🔧 Step 2: Checking for Secator repo in /opt/secator..." >&2
if [ ! -d "/opt/secator" ]; then
    echo "   ❌ Secator repo not found at /opt/secator" >&2
    echo "   ⚠️  Make sure to mount the Secator repo volume or copy it to /opt/secator" >&2
    echo "   📝 You can add this to docker-compose.yml:" >&2
    echo "      volumes:" >&2
    echo "        - /path/to/secator:/opt/secator:ro" >&2
    exit 1
fi

if [ ! -f "/opt/secator/pyproject.toml" ]; then
    echo "   ❌ pyproject.toml not found in /opt/secator" >&2
    exit 1
fi

echo "   ✅ Secator repo found at /opt/secator" >&2

# Step 3: Install Secator from local repo with pipx in editable mode
echo "🔧 Step 3: Installing Secator from local repo with pipx (editable mode)..." >&2
cd /opt/secator
pipx install . --editable 2>&1 | tee /tmp/pipx_install.log || {
    echo "   ❌ Failed to install Secator from local repo" >&2
    cat /tmp/pipx_install.log >&2
    exit 1
}
echo "   ✅ Secator installed successfully from local repo" >&2

# Step 4: Install Secator addons (worker and redis)
# Temporary for debug: Installing addons for local development
echo "🔧 Step 4: Installing Secator addons (worker, redis, dev)..." >&2
secator install addons worker 2>&1 | tee /tmp/addon_worker.log || {
    echo "   ⚠️  Worker addon installation returned non-zero exit code" >&2
    cat /tmp/addon_worker.log >&2
}
secator install addons redis 2>&1 | tee /tmp/addon_redis.log || {
    echo "   ⚠️  Redis addon installation returned non-zero exit code" >&2
    cat /tmp/addon_redis.log >&2
}
secator install addons dev 2>&1 | tee /tmp/addon_dev.log || {
    echo "   ⚠️  Dev addon installation returned non-zero exit code" >&2
    cat /tmp/addon_dev.log >&2
}
pipx install watchdog

# Step 5: Verify addons are installed
echo "🔧 Step 5: Verifying addons installation..." >&2
if secator config list 2>&1 | grep -qE "(worker|redis|dev)"; then
    echo "   ✅ Addons verified successfully" >&2
else
    echo "   ⚠️  Could not verify addons in config (might still work)" >&2
fi

# Step 6: Execute the worker command
echo "🚀 Step 6: Starting Secator worker..." >&2
exec secator "$@" --reload
