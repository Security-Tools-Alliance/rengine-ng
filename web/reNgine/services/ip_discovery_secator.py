"""
CIDR / IP discovery and ping helpers using Secator fping and dnspython PTR lookups.

Used by the add-target DNS discovery UI; runs without ScanHistory or Target rows.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import re
import socket
from typing import Any, Callable

import dns.resolver
import dns.reversename
from secator.output_types import Ip as SecatorIp
from secator.runners import Task
from secator.template import TemplateLoader

from reNgine.secator.run_opts import build_ephemeral_sync_run_opts
from reNgine.utilities.domain import normalize_domain_name
from reNgine.utilities.logger import get_module_logger
from reNgine.utilities.url import get_domain_from_subdomain


logger = get_module_logger(__name__)
PREFIX = "[IP_DISCOVERY]"

MAX_HOSTS_IN_RANGE = 4096
MAX_PING_TARGETS = 4096
MAX_CUSTOM_DNS_SERVERS = 8
MAX_DISCOVERY_WORKERS = 4
FPING_CHUNK_MIN_ADDRESSES = 32
LARGE_RANGE_WARNING_ADDRESSES = 256
DNS_SERVER_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")
CHANNEL_CLEAN_PATTERN = re.compile(r"[^a-zA-Z0-9\-\.]")


def clean_scan_channel_token(scan_id: str | None) -> str:
    if not scan_id:
        return ""
    return CHANNEL_CLEAN_PATTERN.sub("-", scan_id)


def emit_ip_scan_progress(scan_id: str | None, payload: dict[str, Any]) -> None:
    if not scan_id:
        return
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        group = "ip-scan-%s" % (clean_scan_channel_token(scan_id),)
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
        async_to_sync(channel_layer.group_send)(group, {"type": "scan_progress", "message": payload})
    except Exception as exc:
        logger.log_line(
            PREFIX,
            "WS",
            "Failed to emit IP scan progress: %s" % (exc,),
            level="warning",
        )


def run_fping_sync(
    targets: list[str],
    *,
    workspace_name: str = "rengine-ephemeral-ip-discovery",
    **fping_opts: Any,
) -> list[SecatorIp]:
    if not targets:
        return []
    config = TemplateLoader({"type": "task", "name": "fping"})
    run_opts = build_ephemeral_sync_run_opts(**fping_opts)
    # Ephemeral opts disable Secator hooks; fping.before_init must run to use -g for CIDR ranges.
    run_opts["enable_hooks"] = True
    runner = Task(
        config,
        inputs=targets,
        run_opts=run_opts,
        context={"workspace_name": workspace_name},
    )
    raw = runner.run()
    sec_ips = [item for item in raw if isinstance(item, SecatorIp)]
    return sec_ips


def parse_ip_or_cidr(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]:
    text = raw.strip()
    if not text:
        raise ValueError("IP address or CIDR is required")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IP address or CIDR notation") from exc
    if net.num_addresses > MAX_HOSTS_IN_RANGE:
        raise ValueError("Network too large (max %s addresses)" % (MAX_HOSTS_IN_RANGE,))
    return net, text


def parse_dns_servers_option(raw: str | None) -> list[str]:
    if not raw or not str(raw).strip():
        return []
    parts = re.split(r"[\s,;]+", str(raw).strip())
    seen: set[str] = set()
    servers: list[str] = []
    for p in parts:
        if not p:
            continue
        candidate = p.strip()
        if candidate in seen:
            continue
        if _is_valid_dns_server_token(candidate):
            seen.add(candidate)
            servers.append(candidate)
        if len(servers) >= MAX_CUSTOM_DNS_SERVERS:
            break
    return servers


def _is_valid_dns_server_token(token: str) -> bool:
    if not token or len(token) > 253:
        return False
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    return bool(DNS_SERVER_HOST_PATTERN.fullmatch(token))


def get_system_nameservers() -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        out: list[str] = []
        for ns in resolver.nameservers:
            out.append(str(ns))
        return out or ["8.8.8.8"]
    except Exception:
        return ["8.8.8.8"]


def build_resolver_chain(custom: list[str], use_system_fallback: bool) -> tuple[list[str], list[str]]:
    chain: list[str] = []
    for item in custom:
        if item not in chain:
            chain.append(item)
    used_display = list(chain)
    if use_system_fallback:
        for sys_ns in get_system_nameservers():
            if sys_ns not in chain:
                chain.append(sys_ns)
        used_display = list(chain)
    elif not chain:
        chain = get_system_nameservers()
        used_display = list(chain)
    return chain, used_display


def _nameserver_to_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        infos = socket.getaddrinfo(host, 53, type=socket.SOCK_DGRAM)
        if not infos:
            raise OSError("Could not resolve nameserver host")
        return infos[0][4][0]


def ptr_lookup(ip: str, servers: list[str]) -> tuple[str | None, str | None]:
    try:
        rev = dns.reversename.from_address(ip)
    except Exception:
        return None, None
    for srv in servers:
        try:
            ns_ip = _nameserver_to_ip(srv)
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = [ns_ip]
            res.lifetime = 3.0
            answers = res.resolve(rev, "PTR", lifetime=3.0)
            if not answers:
                continue
            name = str(answers[0].target).rstrip(".")
            if name:
                return name, srv
        except Exception:
            continue
    return None, None


def _registered_apex(domain: str, ip: str) -> str:
    if not domain or domain == ip:
        return ""
    norm = normalize_domain_name(domain)
    if not norm:
        return ""
    return (get_domain_from_subdomain(norm) or norm) or ""


def _row(
    ip: str,
    domain: str,
    *,
    is_alive: bool,
    resolved_by: str = "",
    domains: list[str] | None = None,
) -> dict[str, Any]:
    dlist = domains if domains is not None else ([domain] if domain and domain != ip else [])
    reg_apex = _registered_apex(domain, ip)
    return {
        "ip": ip,
        "domain": domain,
        "domains": dlist,
        "resolved_by": resolved_by,
        "is_alive": is_alive,
        "registered_apex": reg_apex,
    }


def _discovered_parent_domains(rows: list[dict[str, Any]]) -> list[str]:
    parents: set[str] = set()
    for row in rows:
        apex = (row.get("registered_apex") or "").strip()
        if apex:
            parents.add(apex)
            continue
        dom = row.get("domain") or ""
        ip = row.get("ip") or ""
        if dom and dom != ip and "." in dom:
            parents.add(".".join(dom.split(".")[-2:]))
    return sorted(parents)


def _is_large_ipv4_range(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return isinstance(net, ipaddress.IPv4Network) and net.num_addresses > LARGE_RANGE_WARNING_ADDRESSES


def _split_network_into_chunks(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    max_chunks: int = MAX_DISCOVERY_WORKERS,
) -> list[list[str]]:
    all_ips = [str(ip) for ip in net]
    if not all_ips:
        return []
    if len(all_ips) < FPING_CHUNK_MIN_ADDRESSES:
        return [all_ips]
    chunk_count = min(max_chunks, len(all_ips))
    chunk_size = (len(all_ips) + chunk_count - 1) // chunk_count
    return [all_ips[idx : idx + chunk_size] for idx in range(0, len(all_ips), chunk_size)]


def _run_fping_chunks(chunks: list[list[str]]) -> list[SecatorIp]:
    if not chunks:
        return []
    if len(chunks) == 1:
        return run_fping_sync(
            chunks[0], use_dns=False, show_name=False, workspace_name="rengine-ephemeral-ip-discovery-c1"
        )

    results: list[SecatorIp] = []
    with ThreadPoolExecutor(max_workers=min(MAX_DISCOVERY_WORKERS, len(chunks))) as executor:
        futures = {
            executor.submit(
                run_fping_sync,
                chunk,
                use_dns=False,
                show_name=False,
                workspace_name="rengine-ephemeral-ip-discovery-c%s" % (idx + 1,),
            ): idx
            for idx, chunk in enumerate(chunks)
        }
        for future in as_completed(futures):
            results.extend(future.result())
    return results


def run_cidr_discovery(
    ip_or_cidr: str,
    *,
    dns_servers_raw: str | None,
    use_system_fallback: bool,
    scan_id: str | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    def _emit(payload: dict[str, Any]) -> None:
        if progress:
            progress(payload)
        emit_ip_scan_progress(scan_id, payload)

    custom = parse_dns_servers_option(dns_servers_raw)
    resolver_chain, used_display = build_resolver_chain(custom, use_system_fallback)
    current_dns = get_system_nameservers()

    net, original = parse_ip_or_cidr(ip_or_cidr)
    is_single_host = net.num_addresses == 1
    chunks = _split_network_into_chunks(net)
    is_large_range = _is_large_ipv4_range(net)

    if is_large_range:
        warning_msg = "Large range detected (> /24): scan may take longer and generate more network traffic."
        _emit(
            {
                "percentage": 2,
                "message": "Large CIDR range warning",
                "details": warning_msg,
                "log_message": warning_msg,
                "log_type": "warning",
            }
        )

    _emit(
        {
            "percentage": 5,
            "message": "Starting host discovery",
            "details": "Running ICMP probe (Secator fping; PTR enrichment follows) across %s chunk(s)" % (len(chunks),),
            "log_message": "Launched fping against %s using %s chunk(s)" % (original, len(chunks)),
            "log_type": "info",
        }
    )

    try:
        # use_dns/show_name add -d/-n and change fping output shape; item_loader then
        # often yields no Ip for CIDR + -g. PTR phase below still resolves names.
        fping_results = _run_fping_chunks(chunks)
    except Exception as exc:
        logger.log_line(PREFIX, "FPING", "fping task failed: %s" % (exc,), level="error")
        raise RuntimeError("Host discovery failed. Ensure fping is installed and reachable.") from exc

    by_ip: dict[str, dict[str, Any]] = {}
    for item in fping_results:
        ip_s = (item.ip or "").strip()
        if not ip_s:
            continue
        host = (item.host or "").strip()
        domain = host if host else ip_s
        resolved_by = "PTR (fping ICMP)" if host and host != ip_s else ""
        prev = by_ip.get(ip_s)
        if prev:
            if (not prev["is_alive"]) and item.alive:
                prev["is_alive"] = True
            if prev["domain"] == ip_s and domain != ip_s:
                by_ip[ip_s] = _row(ip_s, domain, is_alive=bool(prev["is_alive"]), resolved_by=resolved_by)
            continue
        by_ip[ip_s] = _row(ip_s, domain, is_alive=bool(item.alive), resolved_by=resolved_by)

    if is_single_host:
        sole = str(net.network_address)
        if sole not in by_ip:
            by_ip[sole] = _row(sole, sole, is_alive=False, resolved_by="")

    _emit(
        {
            "percentage": 55,
            "message": "Resolving PTR records",
            "details": "Enriching hostnames via configured DNS in parallel",
            "log_message": "PTR lookup chain: %s" % (", ".join(used_display),),
            "log_type": "info",
        }
    )

    unresolved_ips = [ip_s for ip_s, row in by_ip.items() if row["domain"] == ip_s]
    if unresolved_ips:
        with ThreadPoolExecutor(max_workers=min(MAX_DISCOVERY_WORKERS, len(unresolved_ips))) as executor:
            futures = {executor.submit(ptr_lookup, ip_s, resolver_chain): ip_s for ip_s in unresolved_ips}
            for future in as_completed(futures):
                ip_s = futures[future]
                hostname, via = future.result()
                if not hostname:
                    continue
                row = by_ip[ip_s]
                label = "PTR"
                if via:
                    label = "PTR via %s" % (via,)
                by_ip[ip_s] = _row(
                    ip_s,
                    hostname,
                    is_alive=row["is_alive"],
                    resolved_by=label,
                    domains=[hostname],
                )

    rows = sorted(by_ip.values(), key=lambda r: (not r["is_alive"], r["ip"]))
    hostname_count = sum(r["domain"] != r["ip"] for r in rows)
    discovered_domains = _discovered_parent_domains(rows)
    ping_required = bool(rows) and not any(r["is_alive"] for r in rows)

    _emit(
        {
            "percentage": 100,
            "message": "Discovery finished",
            "details": "%s host(s) processed" % (len(rows),),
            "log_message": "Discovery completed: %s hosts" % (len(rows),),
            "log_type": "success",
        }
    )

    return {
        "status": bool(rows),
        "ip_address": rows,
        "total_hosts": len(rows),
        "hostname_count": hostname_count,
        "discovered_domains": discovered_domains,
        "current_dns_servers": current_dns,
        "used_dns_servers": used_display,
        "ping_required": ping_required,
        "range_warning": is_large_range,
    }


def normalize_ip_list_for_ping(ip_list: list[Any]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in ip_list:
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        if not s or s in seen:
            continue
        try:
            ipaddress.ip_address(s)
        except ValueError:
            continue
        seen.add(s)
        cleaned.append(s)
        if len(cleaned) > MAX_PING_TARGETS:
            raise ValueError("Too many addresses for ping (max %s)" % (MAX_PING_TARGETS,))
    return cleaned


def run_ping_for_ips(ip_list: list[str]) -> dict[str, bool]:
    cleaned = normalize_ip_list_for_ping(ip_list)
    if not cleaned:
        return {}

    alive_ips = run_fping_sync(cleaned, use_dns=False)
    alive_set = {item.ip.strip() for item in alive_ips if item.ip}
    return {ip: (ip in alive_set) for ip in cleaned}
