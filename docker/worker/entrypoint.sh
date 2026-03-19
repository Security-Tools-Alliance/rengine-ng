#!/bin/bash
set -e

echo "Secator worker entrypoint starting..." >&2

start_rengine_pull_agent() {
  AGENT_SCRIPT="${RENGINE_PULL_AGENT_SCRIPT:-/rengine-pull-agent/rengine_pull_agent.py}"
  if [ ! -f "${AGENT_SCRIPT}" ]; then
    echo "RENGINE_PULL_AGENT_ENABLED but ${AGENT_SCRIPT} not found" >&2
    return 1
  fi

  # 0 means infinite restarts.
  : "${RENGINE_PULL_AGENT_MAX_RESTARTS:=0}"
  : "${RENGINE_PULL_AGENT_BACKOFF_SECONDS:=5}"

  echo "Starting reNgine pull agent supervisor (script: ${AGENT_SCRIPT})..." >&2

  restart_count=0
  while :; do
    echo "Launching reNgine pull agent (restart #${restart_count})..." >&2
    set +e
    # Send pull-agent logs to container stderr so runtime-level log rotation applies.
    python3 "${AGENT_SCRIPT}" 1>&2
    exit_code=$?
    set -e

    if [ "${exit_code}" -eq 0 ]; then
      echo "reNgine pull agent exited cleanly (exit code 0), supervisor stopping." >&2
      break
    fi

    echo "reNgine pull agent exited with code ${exit_code}" >&2
    restart_count=$((restart_count + 1))

    if [ "${RENGINE_PULL_AGENT_MAX_RESTARTS}" -gt 0 ] && \
       [ "${restart_count}" -gt "${RENGINE_PULL_AGENT_MAX_RESTARTS}" ]; then
      echo "reNgine pull agent reached max restarts (${RENGINE_PULL_AGENT_MAX_RESTARTS}), giving up." >&2
      return "${exit_code}"
    fi

    echo "Restarting reNgine pull agent in ${RENGINE_PULL_AGENT_BACKOFF_SECONDS}s..." >&2
    sleep "${RENGINE_PULL_AGENT_BACKOFF_SECONDS}"
  done
}

if [ "${RENGINE_PULL_AGENT_ENABLED}" = "true" ]; then
  start_rengine_pull_agent &
  agent_pid=$!
fi

secator "$@" &
secator_pid=$!

# Guard against secator exiting immediately (e.g., misconfiguration):
# fail fast instead of entering the supervisor loop with a dead primary process.
if ! kill -0 "${secator_pid}" >/dev/null 2>&1; then
  wait "${secator_pid}"
  secator_status=$?
  echo "secator exited immediately with status ${secator_status}, aborting." >&2
  exit "${secator_status}"
fi

cleanup() {
  if [ -n "${secator_pid:-}" ]; then
    kill "${secator_pid}" >/dev/null 2>&1 || true
  fi
  if [ -n "${agent_pid:-}" ]; then
    kill "${agent_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# If the pull-agent supervisor stops, keep secator alive and disable pull-agent.
# This avoids restart storms for persistent API/auth misconfiguration while
# preserving non pull-agent execution paths.
set +e
while true; do
  wait -n
  wait_status=$?

  if [ -n "${agent_pid:-}" ] && ! kill -0 "${agent_pid}" >/dev/null 2>&1; then
    echo "Pull agent supervisor stopped (exit code: ${wait_status}); disabling pull-agent and keeping secator running." >&2
    agent_pid=""
    continue
  fi

  if ! kill -0 "${secator_pid}" >/dev/null 2>&1; then
    exit "${wait_status}"
  fi
done
