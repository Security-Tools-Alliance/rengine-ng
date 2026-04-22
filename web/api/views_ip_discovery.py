"""
API views for CIDR/IP DNS discovery and batch ping (Secator fping), used by target add UI.
"""

from __future__ import annotations

import threading
from typing import Any
import uuid

from django.core.cache import cache
from django.db import close_old_connections
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasAPIKeyOrIsAuthenticated
from reNgine.services import ip_discovery_secator as ipd
from reNgine.utilities.error import get_safe_user_message
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)
PREFIX = "[API_IP_DISCOVERY]"

PING_CACHE_KEY = "ping_hosts_v2:%s"
PING_CACHE_TTL = 600


class CidrDiscoveryToolView(APIView):
    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def get(self, request, *args: Any, **kwargs: Any) -> Response:
        if request.query_params.get("probe") == "current_dns":
            return Response(
                {
                    "status": True,
                    "current_dns_servers": ipd.get_system_nameservers(),
                }
            )

        ip_address = (request.query_params.get("ip_address") or "").strip()
        if not ip_address:
            return Response(
                {"status": False, "message": "ip_address is required"},
                status=400,
            )
        scan_id = (request.query_params.get("scan_id") or "").strip() or None
        dns_servers = request.query_params.get("dns_servers")
        use_fb = request.query_params.get("use_system_fallback", "true").lower() in (
            "1",
            "true",
            "yes",
        )

        try:
            payload = ipd.run_cidr_discovery(
                ip_address,
                dns_servers_raw=dns_servers,
                use_system_fallback=use_fb,
                scan_id=scan_id,
            )
            return Response(payload)
        except ValueError as exc:
            return Response(
                {
                    "status": False,
                    "message": str(exc),
                    "ip_address": [],
                    "total_hosts": 0,
                    "hostname_count": 0,
                    "discovered_domains": [],
                    "current_dns_servers": ipd.get_system_nameservers(),
                    "used_dns_servers": [],
                    "ping_required": False,
                    "range_warning": False,
                },
                status=400,
            )
        except Exception as exc:
            logger.log_line(PREFIX, "CIDR_DISCOVERY", "Discovery failed: %s" % (exc,), level="error")
            return Response(
                {
                    "status": False,
                    "message": get_safe_user_message(exc, None),
                    "ip_address": [],
                    "total_hosts": 0,
                    "hostname_count": 0,
                    "discovered_domains": [],
                    "current_dns_servers": ipd.get_system_nameservers(),
                    "used_dns_servers": [],
                    "ping_required": False,
                    "range_warning": False,
                },
                status=500,
            )

    def post(self, request, *args: Any, **kwargs: Any) -> Response:
        body = request.data if isinstance(request.data, dict) else {}
        ip_address = (body.get("ip_address") or "").strip()
        scan_id = (body.get("scan_id") or "").strip() or None
        dns_servers = body.get("dns_servers")
        use_fb = bool(body.get("use_system_fallback", True))

        if not ip_address:
            return Response({"status": False, "message": "ip_address is required"}, status=400)

        try:
            dns_raw = dns_servers if isinstance(dns_servers, str) else None
            payload = ipd.run_cidr_discovery(
                ip_address,
                dns_servers_raw=dns_raw,
                use_system_fallback=use_fb,
                scan_id=scan_id,
            )
            return Response(payload)
        except ValueError as exc:
            return Response(
                {
                    "status": False,
                    "message": str(exc),
                    "ip_address": [],
                    "total_hosts": 0,
                    "hostname_count": 0,
                    "discovered_domains": [],
                    "current_dns_servers": ipd.get_system_nameservers(),
                    "used_dns_servers": [],
                    "ping_required": False,
                    "range_warning": False,
                },
                status=400,
            )
        except Exception as exc:
            logger.log_line(PREFIX, "CIDR_DISCOVERY", "Discovery failed: %s" % (exc,), level="error")
            return Response(
                {
                    "status": False,
                    "message": get_safe_user_message(exc, None),
                    "ip_address": [],
                    "total_hosts": 0,
                    "hostname_count": 0,
                    "discovered_domains": [],
                    "current_dns_servers": ipd.get_system_nameservers(),
                    "used_dns_servers": [],
                    "ping_required": False,
                    "range_warning": False,
                },
                status=500,
            )


def _ping_worker(cache_key: str, ip_list: list[str], scan_id: str | None) -> None:
    try:
        ipd.emit_ip_scan_progress(
            scan_id,
            {
                "percentage": 10,
                "message": "Ping in progress",
                "details": "Checking %s hosts" % (len(ip_list),),
                "log_message": "Ping task running: 10%%",
                "log_type": "info",
            },
        )
        ping_results = ipd.run_ping_for_ips(ip_list)
        alive_count = sum(1 for v in ping_results.values() if v)
        total = len(ping_results)
        result_body = {
            "ping_results": ping_results,
            "alive_count": alive_count,
            "total_count": total,
        }
        cache.set(
            cache_key,
            {"status": True, "task_status": "completed", "result": result_body},
            PING_CACHE_TTL,
        )
        ipd.emit_ip_scan_progress(
            scan_id,
            {
                "percentage": 100,
                "message": "Ping completed",
                "details": "%s/%s hosts alive" % (alive_count, total),
                "log_message": "Ping completed: %s/%s alive" % (alive_count, total),
                "log_type": "success",
                "ping_results": ping_results,
                "alive_count": alive_count,
                "total_count": total,
            },
        )
    except Exception as exc:
        logger.log_line(PREFIX, "PING_V2", "Ping worker failed: %s" % (exc,), level="error")
        cache.set(
            cache_key,
            {
                "status": False,
                "task_status": "failed",
                "message": get_safe_user_message(exc, None),
            },
            PING_CACHE_TTL,
        )
        ipd.emit_ip_scan_progress(
            scan_id,
            {
                "log_message": "Ping failed",
                "log_type": "error",
            },
        )
    finally:
        if threading.current_thread() is not threading.main_thread():
            close_old_connections()


class PingHostsV2ToolView(APIView):
    permission_classes = [HasAPIKeyOrIsAuthenticated]

    def post(self, request, *args: Any, **kwargs: Any) -> Response:
        body = request.data if isinstance(request.data, dict) else {}
        ip_list = body.get("ip_list")
        scan_id = (body.get("scan_id") or "").strip() or None

        if not isinstance(ip_list, list):
            return Response({"status": False, "message": "ip_list must be a list"}, status=400)

        try:
            normalized = ipd.normalize_ip_list_for_ping(ip_list)
        except ValueError as exc:
            return Response({"status": False, "message": str(exc)}, status=400)

        if not normalized:
            return Response({"status": False, "message": "No valid IP addresses in ip_list"}, status=400)

        task_id = str(uuid.uuid4())
        cache_key = PING_CACHE_KEY % (task_id,)
        cache.set(
            cache_key,
            {"status": True, "task_status": "running", "result": None},
            PING_CACHE_TTL,
        )

        thread = threading.Thread(
            target=_ping_worker,
            args=(cache_key, normalized, scan_id),
            daemon=True,
        )
        thread.start()

        return Response({"status": True, "task_id": task_id})

    def get(self, request, *args: Any, **kwargs: Any) -> Response:
        task_id = (request.query_params.get("task_id") or "").strip()
        if not task_id:
            return Response({"status": False, "message": "task_id is required"}, status=400)

        cache_key = PING_CACHE_KEY % (task_id,)
        entry = cache.get(cache_key)
        if not entry:
            return Response({"status": False, "message": "Unknown or expired task_id"}, status=404)

        return Response(
            {
                "status": entry.get("status", False),
                "task_status": entry.get("task_status", "unknown"),
                "result": entry.get("result"),
                "message": entry.get("message"),
            }
        )
