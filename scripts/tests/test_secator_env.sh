#!/usr/bin/env bash
#
# Unit tests for Secator API key logic in common_functions.sh.
# Mirrors the behaviour of install.sh and update.sh: is_secator_api_key_configured
# and ensure_secator_api_key_in_env. Run from repo root: bash scripts/tests/test_secator_env.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMON_FUNCTIONS="$SCRIPT_DIR/../common_functions.sh"

if [[ ! -f "$COMMON_FUNCTIONS" ]]; then
  echo "Error: common_functions.sh not found at $COMMON_FUNCTIONS" >&2
  exit 1
fi

# Override log so tput is not used (script may run in non-TTY).
log() { printf '%s\n' "$1" >&2; }
export -f log 2>/dev/null || true

# Source common_functions (defines is_secator_api_key_configured, ensure_secator_api_key_in_env, etc.)
# shellcheck source=../common_functions.sh
source "$COMMON_FUNCTIONS"

# Re-override log after source (in case sourcing redefines it).
log() { printf '%s\n' "$1" >&2; }

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

assert_configured() {
  local expected=$1
  local env_file=$2
  local label="${3:-}"
  if is_secator_api_key_configured "$env_file"; then
    local got=0
  else
    local got=1
  fi
  if [[ $got -eq $expected ]]; then
    echo "PASS: $label (expected configured=$expected)"
    ((PASS++)) || true
    return 0
  fi
  echo "FAIL: $label (expected configured=$expected, got configured=$((1 - got)))"
  ((FAIL++)) || true
  return 1
}

# --- is_secator_api_key_configured tests (mirror install/update .env states) ---
echo "=== is_secator_api_key_configured ==="

# File missing -> not configured
assert_configured 1 "/nonexistent" "file missing"

# Empty file -> not configured
touch "$TMPDIR/empty"
assert_configured 1 "$TMPDIR/empty" "empty file"

# SECATOR_ADDONS_API_KEY= (empty value) -> not configured
echo 'SECATOR_ADDONS_API_KEY=' > "$TMPDIR/empty_val"
assert_configured 1 "$TMPDIR/empty_val" "empty value"

# Placeholder from .env-dist (exact) -> not configured
echo 'SECATOR_ADDONS_API_KEY=your-generated-api-key-here' > "$TMPDIR/placeholder"
assert_configured 1 "$TMPDIR/placeholder" "placeholder exact"

# Placeholder with trailing spaces -> not configured
echo 'SECATOR_ADDONS_API_KEY=your-generated-api-key-here   ' > "$TMPDIR/placeholder_trailing"
assert_configured 1 "$TMPDIR/placeholder_trailing" "placeholder with trailing spaces"

# Placeholder with leading spaces in value (after =) -> not configured
echo 'SECATOR_ADDONS_API_KEY=  your-generated-api-key-here' > "$TMPDIR/placeholder_leading"
assert_configured 1 "$TMPDIR/placeholder_leading" "placeholder with leading spaces in value"

# Other line before; placeholder -> not configured (as in .env after merge_env_from_dist)
printf '%s\n' 'OTHER=value' 'SECATOR_ADDONS_API_KEY=your-generated-api-key-here' > "$TMPDIR/other_then_placeholder"
assert_configured 1 "$TMPDIR/other_then_placeholder" "other var then placeholder"

# Real key (as after successful install/update) -> configured
echo 'SECATOR_ADDONS_API_KEY=real-key-123' > "$TMPDIR/real"
assert_configured 0 "$TMPDIR/real" "real key"

# Two lines: first placeholder (we take first) -> not configured
printf '%s\n' 'SECATOR_ADDONS_API_KEY=your-generated-api-key-here' 'SECATOR_ADDONS_API_KEY=real-key' > "$TMPDIR/two_lines"
assert_configured 1 "$TMPDIR/two_lines" "two lines first is placeholder"

# Real-world: .env after merge (many lines, Secator block at end with placeholder) -> not configured
cat > "$TMPDIR/env_after_merge" << 'ENVEOF'
COMPOSE_PROJECT_NAME=rengine
POSTGRES_DB=rengine
POSTGRES_USER=rengine
POSTGRES_PORT=6432
POSTGRES_HOST=pgbouncer
USE_PGBOUNCER=1
SECATOR_ADDONS_API_ENABLED=true
SECATOR_ADDONS_API_URL=https://proxy/api/secator
SECATOR_ADDONS_API_KEY=your-generated-api-key-here
SECATOR_ADDONS_API_HEADER_NAME=Api-Key
SECATOR_ADDONS_API_FORCE_SSL=false
SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT=
ENVEOF
assert_configured 1 "$TMPDIR/env_after_merge" "real .env after merge (Secator block at end with placeholder)"

# --- ensure_secator_api_key_in_env tests (with mocks) ---
echo "=== ensure_secator_api_key_in_env ==="

# Mock: get_secator_api_key_from_container returns a key (no Docker).
get_secator_api_key_from_container() {
  printf '%s' 'mock-key-from-test'
}

# Fake make: record that restart was requested and succeed.
REPO_ROOT_FAKE="$TMPDIR/repo_root"
mkdir -p "$REPO_ROOT_FAKE"
cat > "$REPO_ROOT_FAKE/make" << 'MAKE_SCRIPT'
#!/usr/bin/env bash
touch "$(dirname "$0")/restart_called"
exit 0
MAKE_SCRIPT
chmod +x "$REPO_ROOT_FAKE/make"

# Scenario 1: .env has placeholder (as after merge_env_from_dist in update) -> must write key and "restart"
env_file_placeholder="$TMPDIR/env_placeholder"
echo 'SECATOR_ADDONS_API_KEY=your-generated-api-key-here' > "$env_file_placeholder"
PATH="$REPO_ROOT_FAKE:$PATH" ensure_secator_api_key_in_env "$env_file_placeholder" "$REPO_ROOT_FAKE" || true
if grep -q 'SECATOR_ADDONS_API_KEY=mock-key-from-test' "$env_file_placeholder" && [[ -f "$REPO_ROOT_FAKE/restart_called" ]]; then
  echo "PASS: ensure with placeholder -> key written and restart called"
  ((PASS++)) || true
else
  echo "FAIL: ensure with placeholder -> key not written or restart not called"
  ((FAIL++)) || true
fi
rm -f "$REPO_ROOT_FAKE/restart_called"

# Scenario 2: .env already has real key (as after previous install) -> must not overwrite, no restart
env_file_real="$TMPDIR/env_real"
echo 'SECATOR_ADDONS_API_KEY=already-real-key' > "$env_file_real"
PATH="$REPO_ROOT_FAKE:$PATH" ensure_secator_api_key_in_env "$env_file_real" "$REPO_ROOT_FAKE" || true
if grep -q 'SECATOR_ADDONS_API_KEY=already-real-key' "$env_file_real" && [[ ! -f "$REPO_ROOT_FAKE/restart_called" ]]; then
  echo "PASS: ensure with real key -> no change, no restart"
  ((PASS++)) || true
else
  echo "FAIL: ensure with real key -> file changed or restart was called"
  ((FAIL++)) || true
fi

# --- ensure with real .env-dist fixtures (2.2.1 style: no Secator block / 3.0.0: placeholder) ---
echo "=== ensure_secator_api_key_in_env on real .env-dist fixtures ==="

# Fake key we inject and then verify in .env
FAKE_KEY="fake-key-$(date +%s)-$$"
get_secator_api_key_from_container() {
  printf '%s' "$FAKE_KEY"
}

# 2.2.1 style: .env-dist has no SECATOR_ADDONS_API_KEY (no Secator block)
FIXTURE_221="$SCRIPT_DIR/fixtures/env_dist_2.2.1"
if [[ ! -f "$FIXTURE_221" ]]; then
  echo "FAIL: fixture not found: $FIXTURE_221"
  ((FAIL++)) || true
else
  env_221="$TMPDIR/env_221"
  cp "$FIXTURE_221" "$env_221"
  rm -f "$REPO_ROOT_FAKE/restart_called"
  PATH="$REPO_ROOT_FAKE:$PATH" ensure_secator_api_key_in_env "$env_221" "$REPO_ROOT_FAKE" || true
  if grep -q "SECATOR_ADDONS_API_KEY=$FAKE_KEY" "$env_221" && [[ -f "$REPO_ROOT_FAKE/restart_called" ]]; then
    echo "PASS: .env from 2.2.1-style .env-dist (no Secator block) -> key written and restart called"
    ((PASS++)) || true
  else
    echo "FAIL: .env from 2.2.1-style .env-dist -> key not found or restart not called"
    ((FAIL++)) || true
  fi
fi

# 3.0.0 style: .env-dist has SECATOR_ADDONS_API_KEY=your-generated-api-key-here
ENV_DIST_300="$REPO_ROOT/.env-dist"
if [[ ! -f "$ENV_DIST_300" ]]; then
  echo "FAIL: .env-dist not found: $ENV_DIST_300"
  ((FAIL++)) || true
else
  env_300="$TMPDIR/env_300"
  cp "$ENV_DIST_300" "$env_300"
  rm -f "$REPO_ROOT_FAKE/restart_called"
  PATH="$REPO_ROOT_FAKE:$PATH" ensure_secator_api_key_in_env "$env_300" "$REPO_ROOT_FAKE" || true
  if grep -q "SECATOR_ADDONS_API_KEY=$FAKE_KEY" "$env_300" && [[ -f "$REPO_ROOT_FAKE/restart_called" ]]; then
    echo "PASS: .env from 3.0.0 .env-dist (placeholder) -> key written and restart called"
    ((PASS++)) || true
  else
    echo "FAIL: .env from 3.0.0 .env-dist -> key not found or restart not called (placeholder should be replaced)"
    ((FAIL++)) || true
  fi
fi

# --- Summary ---
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
