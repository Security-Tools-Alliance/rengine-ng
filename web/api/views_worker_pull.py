"""
Pull-agent endpoints for Secator workers (HTTPS mode, no SSH for execution).
Authenticated via X-Rengine-Worker-Pull-Token only.
"""

from __future__ import annotations

import json
import uuid

from django.http import HttpResponse, JsonResponse
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
