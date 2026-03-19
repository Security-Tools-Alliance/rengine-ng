"""
Pull-agent endpoints for Secator workers (HTTPS mode, no SSH for execution).
Authenticated via X-Rengine-Worker-Pull-Token only.
"""

from __future__ import annotations

import json
import uuid

from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from reNgine.utilities.logger import get_module_logger
from scanEngine.services.worker_pull import (
    claim_next_command,
    complete_command,
    extract_validated_pull_token_from_request,
    worker_from_pull_request,
)


logger = get_module_logger(__name__)
LAST_ERROR_MAX_LEN = 4000


def _bad(message: str, status: int = 403) -> JsonResponse:
    return JsonResponse({"detail": message}, status=status)


@csrf_exempt
@require_POST
def secator_worker_pull_claim(request, worker_id: int):
    """
    Claim the next pending command for this worker.
    Returns 204 if none; else JSON { command_id, kind, payload }.
    """
    try:
        wid = int(worker_id)
    except (TypeError, ValueError):
        return _bad("Invalid worker.", 400)
    token = extract_validated_pull_token_from_request(request)
    if token is None:
        return _bad("Invalid or missing worker token.")
    worker = worker_from_pull_request(request, wid, token=token)
    if worker is None:
        return _bad("Invalid worker or token.")
    try:
        cmd = claim_next_command(worker)
    except Exception:
        logger.log_line("WORKER_PULL", "CLAIM", "failed for worker %s" % wid, level="error", exc_info=True)
        return _bad("Server error.", 500)
    if cmd is None:
        return HttpResponse(status=204)
    return JsonResponse(
        {
            "command_id": str(cmd.id),
            "kind": cmd.kind,
            "payload": cmd.payload,
        }
    )


@csrf_exempt
@require_POST
def secator_worker_pull_complete(request, worker_id: int):
    """
    Body JSON: { "command_id": "<uuid>", "ok": true|false, "error": "optional" }
    """
    try:
        wid = int(worker_id)
    except (TypeError, ValueError):
        return _bad("Invalid worker.", 400)
    token = extract_validated_pull_token_from_request(request)
    if token is None:
        return _bad("Invalid or missing worker token.")
    worker = worker_from_pull_request(request, wid, token=token)
    if worker is None:
        return _bad("Invalid worker or token.")
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _bad("Invalid JSON.", 400)
    cid = body.get("command_id")
    if not cid:
        return _bad("command_id required.", 400)
    try:
        command_uuid = uuid.UUID(str(cid))
    except (ValueError, TypeError):
        return _bad("Invalid command_id.", 400)
    ok = body.get("ok")
    if not isinstance(ok, bool):
        return _bad("ok must be a boolean.", 400)
    err = body.get("error")
    error_message = str(err).strip()[:4000] if err else ""
    try:
        updated = complete_command(command_uuid, worker, succeeded=ok, error_message=error_message)
    except Exception:
        logger.log_line("WORKER_PULL", "COMPLETE", "failed for worker %s" % wid, level="error", exc_info=True)
        return _bad("Server error.", 500)
    if not updated:
        return _bad("Command not found or not running.", 409)
    return JsonResponse({"ok": True})


@csrf_exempt
@require_POST
def secator_worker_pull_checkin(request, worker_id: int):
    """
    Pull-agent liveness/status check-in.
    Body JSON (optional): { "api_reachable": true|false, "last_error": string|null }

    Notes
    -----
    - When `api_reachable` is omitted, the existing worker `api_reachable` value is preserved.
    - When `last_error` is omitted, the existing worker `last_error` value is preserved.
    - When `last_error` is explicitly `null`, the worker `last_error` value is cleared.
    - `last_error` strings must be at most 4000 characters.
    """
    try:
        wid = int(worker_id)
    except (TypeError, ValueError):
        return _bad("Invalid worker.", 400)
    token = extract_validated_pull_token_from_request(request)
    if token is None:
        return _bad("Invalid or missing worker token.")
    worker = worker_from_pull_request(request, wid, token=token)
    if worker is None:
        return _bad("Invalid worker or token.")

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return _bad("Invalid JSON.", 400)

    has_api_reachable_key = "api_reachable" in body
    api_reachable = body.get("api_reachable")
    if has_api_reachable_key and not isinstance(api_reachable, bool):
        return _bad("api_reachable must be a boolean.", 400)

    has_last_error_key = "last_error" in body
    last_error_raw = body.get("last_error")
    if has_last_error_key and last_error_raw is not None and not isinstance(last_error_raw, str):
        return _bad("last_error must be a string or null.", 400)
    if isinstance(last_error_raw, str) and len(last_error_raw) > LAST_ERROR_MAX_LEN:
        return _bad("last_error must be at most %s characters." % LAST_ERROR_MAX_LEN, 400)
    update_fields = ["last_status_at"]
    if has_api_reachable_key:
        worker.api_reachable = api_reachable
        update_fields.append("api_reachable")
    if has_last_error_key:
        if isinstance(last_error_raw, str):
            last_error = last_error_raw.strip()[:LAST_ERROR_MAX_LEN]
            worker.last_error = last_error or None
        else:
            worker.last_error = None
        update_fields.append("last_error")
    worker.last_status_at = timezone.now()
    worker.save_partial(update_fields=update_fields)
    return JsonResponse({"ok": True})
