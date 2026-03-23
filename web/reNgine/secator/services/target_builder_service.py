"""
Target builder service - builds Secator target lists by input_type from Target and linked Domain/subdomain data.
Uses optimized DB queries (values_list, single/few queries per type).
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from django.db.models import QuerySet

from startScan.models import Domain, EndPoint, IpAddress, Port, Subdomain
from targetApp.constants import (
    TARGET_TYPE_CIDR_RANGE,
    TARGET_TYPE_EMAIL,
    TARGET_TYPE_FILENAME,
    TARGET_TYPE_HOST,
    TARGET_TYPE_HOST_PORT,
    TARGET_TYPE_IP,
    TARGET_TYPE_ORG_NAME,
    TARGET_TYPE_PORT,
    TARGET_TYPE_SLUG,
    TARGET_TYPE_STR,
    TARGET_TYPE_URL,
    TARGET_TYPE_USERNAME,
)
from targetApp.models import Target


# Secator input type strings (must match secator.definitions). host:port is both a target type and input type.
HOST_PORT = TARGET_TYPE_HOST_PORT

# Input types that are satisfied by Target.value only (no domain/subdomain expansion)
SIMPLE_VALUE_TYPES = frozenset(
    {
        TARGET_TYPE_CIDR_RANGE,
        TARGET_TYPE_EMAIL,
        TARGET_TYPE_FILENAME,
        TARGET_TYPE_ORG_NAME,
        TARGET_TYPE_PORT,
        TARGET_TYPE_SLUG,
        TARGET_TYPE_STR,
        TARGET_TYPE_USERNAME,
    }
)


class TargetBuilderService:
    """Builds lists of targets per Secator input_type from a Target and its linked Domain(s)."""

    def __init__(
        self,
        target_id: Optional[int] = None,
        subdomain_ids: Optional[List[int]] = None,
    ):
        """
        Args:
            target_id: Target ID (the scannable entity). Required.
            subdomain_ids: Optional list of subdomain IDs (for subscan; restricts to these subdomains).
        """
        if target_id is not None:
            self.target_id = int(target_id)
        else:
            raise ValueError("target_id is required")
        self.subdomain_ids = subdomain_ids or []
        self._target: Optional[Target] = None
        self._domain_ids_cache: Optional[List[int]] = None

    @property
    def target(self) -> Target:
        if self._target is None:
            self._target = Target.objects.get(pk=self.target_id)
        return self._target

    @property
    def domain_ids(self) -> List[int]:
        """
        Lazily load and cache domain IDs for this target.
        Ensures we only hit the database once per TargetBuilderService instance.
        """
        if self._domain_ids_cache is None:
            self._domain_ids_cache = list(
                Domain.objects.filter(scan_history__target_id=self.target_id).values_list("id", flat=True).distinct()
            )
        return self._domain_ids_cache

    @property
    def _domain_ids(self) -> List[int]:
        """Backwards-compatible alias; prefer domain_ids in new code."""
        return self.domain_ids

    def build_targets_for_type(self, input_type: str) -> List[str]:
        """
        Build target list for a single input_type.

        Args:
            input_type: One of 'url', 'host', 'host:port', 'ip', 'email', 'org_name', etc.

        Returns:
            List of target strings (URLs, hosts, host:port, IPs, or simple value).
        """
        norm = input_type.strip().lower()
        if norm in SIMPLE_VALUE_TYPES:
            return self._targets_simple_value(norm)
        if norm == TARGET_TYPE_URL:
            if self.target.target_type == TARGET_TYPE_URL and self.target.value:
                return [self.target.value]
            return self._targets_url()
        if norm == TARGET_TYPE_HOST:
            return self._targets_host()
        if norm in (HOST_PORT, "host_port"):
            return self._targets_host_port()
        if norm == TARGET_TYPE_IP:
            return self._targets_ip()
        return []

    def _targets_simple_value(self, input_type: str) -> List[str]:
        """Return [target.value] for email, org_name, username, filename, slug, str, cidr_range, port."""
        if input_type == TARGET_TYPE_PORT:
            if self.target.port:
                return [f"{self.target.value}:{self.target.port}"] if self.target.value else []
            return [self.target.value] if self.target.value else []
        return [self.target.value] if self.target.value else []

    def build_targets_by_type(self, input_types: List[str]) -> Dict[str, List[str]]:
        """
        Build targets segmented by input_type (for workflows with multiple types).

        Args:
            input_types: List of input type strings

        Returns:
            Dict mapping each input_type to list of target strings
        """
        return {it: self.build_targets_for_type(it) for it in input_types}

    def build_flat_targets(self, input_types: List[str]) -> List[str]:
        """
        Build a single flat list of targets valid for at least one of the given input_types.
        Deduplicates while preserving order.

        Args:
            input_types: List of input type strings

        Returns:
            Single list of target strings (each valid for at least one type)
        """
        seen: set = set()
        result: List[str] = []
        for input_type in input_types:
            for t in self.build_targets_for_type(input_type):
                if t and t not in seen:
                    seen.add(t)
                    result.append(t)
        return result

    def _targets_url(self) -> List[str]:
        """Default endpoints (is_default=True) as full http_url; domain-scoped; subdomain-scoped if subdomain_ids."""
        domain_ids = self.domain_ids
        if not domain_ids:
            return []
        qs: QuerySet = EndPoint.objects.filter(
            domain_id__in=domain_ids,
            is_default=True,
        ).values_list("http_url", flat=True)
        if self.subdomain_ids:
            qs = qs.filter(subdomain_id__in=self.subdomain_ids)
        return list(qs.distinct())

    def _targets_host(self) -> List[str]:
        """Target value (if host) plus domain names and subdomain names from linked Domain(s)."""
        domain_ids = self.domain_ids
        hosts: List[str] = []
        seen: set = set()
        if not domain_ids:
            if self.target.target_type == TARGET_TYPE_HOST and self.target.value:
                return [self.target.value]
            return []
        if self.subdomain_ids:
            sub_names = list(
                Subdomain.objects.filter(
                    domain_id__in=domain_ids,
                    id__in=self.subdomain_ids,
                )
                .values_list("name", flat=True)
                .distinct()
            )
            for name in sub_names:
                if name and name not in seen:
                    seen.add(name)
                    hosts.append(name)
            return hosts
        if self.target.target_type == TARGET_TYPE_HOST and self.target.value:
            hosts = [self.target.value]
            seen.add(self.target.value)
        domain_names = list(Domain.objects.filter(id__in=domain_ids).values_list("name", flat=True))
        sub_names = list(Subdomain.objects.filter(domain_id__in=domain_ids).values_list("name", flat=True).distinct())
        for name in domain_names:
            if name and name not in seen:
                seen.add(name)
                hosts.append(name)
        for name in sub_names:
            if name and name not in seen:
                seen.add(name)
                hosts.append(name)
        return hosts

    def _targets_host_port(self) -> List[str]:
        """Target value (if host:port/port), default alive endpoints as host:port, and IP:port from Ports on IPs linked to subdomains."""
        if self.target.target_type in (TARGET_TYPE_HOST_PORT, TARGET_TYPE_PORT) and self.target.value:
            return [self.target.value]
        domain_ids = self.domain_ids
        if not domain_ids:
            return []
        host_ports: set = set()

        qs = (
            EndPoint.objects.filter(
                domain_id__in=domain_ids,
                is_default=True,
                http_status__gt=0,
            )
            .values_list("http_url", flat=True)
            .distinct()
        )
        if self.subdomain_ids:
            qs = qs.filter(subdomain_id__in=self.subdomain_ids)
        for url in qs:
            if not url:
                continue
            parsed = urlparse(url)
            host = parsed.hostname or ""
            scheme = (parsed.scheme or "").lower()
            if not host or scheme not in {"http", "https"}:
                continue
            port = parsed.port
            if port is None:
                port = 443 if scheme == "https" else 80
            host_ports.add(f"{host}:{port}")

        port_qs = (
            Port.objects.filter(ip_address__ip_addresses__domain_id__in=domain_ids)
            .values_list("ip_address__address", "number")
            .distinct()
        )
        if self.subdomain_ids:
            port_qs = port_qs.filter(ip_address__ip_addresses__id__in=self.subdomain_ids)
        for address, number in port_qs:
            if address and number is not None and 1 <= number <= 65535:
                host_ports.add(f"{address}:{number}")

        return sorted(host_ports)

    def _targets_ip(self) -> List[str]:
        """Target value (if ip/cidr_range) or IP addresses linked to scan histories of this target."""
        targets: List[str] = []
        seen: set[str] = set()
        if self.target.target_type in (TARGET_TYPE_IP, TARGET_TYPE_CIDR_RANGE) and self.target.value:
            targets.append(self.target.value)
            seen.add(self.target.value)
        if self.subdomain_ids:
            scan_history_ids = (
                Subdomain.objects.filter(
                    id__in=self.subdomain_ids,
                    scan_history__target_id=self.target_id,
                )
                .values_list("scan_history_id", flat=True)
                .distinct()
            )
            qs = IpAddress.objects.filter(scan_history_id__in=scan_history_ids)
        else:
            qs = IpAddress.objects.filter(scan_history__target_id=self.target_id)
        for address in qs.values_list("address", flat=True).distinct().iterator(chunk_size=1000):
            if address and address not in seen:
                seen.add(address)
                targets.append(address)
        return targets
