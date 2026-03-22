"""
Stable ``error_code`` values for IP-related API actions.

Clients may branch on ``error_code``; human text stays in ``message``.
"""

from __future__ import annotations

from rest_framework.response import Response


IP_ERR_MISSING_IP_ADDRESS_ID = "missing_ip_address_id"
IP_ERR_IP_NOT_FOUND = "ip_not_found"
IP_ERR_MISSING_REQUIRED_FIELDS = "missing_required_fields"
IP_ERR_INVALID_IP_ADDRESS_IDS = "invalid_ip_address_ids"
IP_ERR_SCAN_NOT_FOUND = "scan_not_found"
IP_ERR_TARGET_NOT_FOUND = "target_not_found"
IP_ERR_IP_NOT_IN_SCAN = "ip_not_in_scan"
IP_ERR_IP_NOT_IN_TARGET = "ip_not_in_target"


def ip_action_error(message: str, error_code: str, *, status: int = 400) -> Response:
    return Response({"status": False, "message": message, "error_code": error_code}, status=status)
