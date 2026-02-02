"""
Target builder service - builds Secator target lists by input_type from domain/subdomain data.
Uses optimized DB queries (values_list, single/few queries per type).
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse

from django.db.models import QuerySet

from startScan.models import EndPoint, Subdomain
from targetApp.models import Domain


# Secator input type strings (must match secator.definitions)
HOST_PORT = "host:port"


class TargetBuilderService:
    """Builds lists of targets per Secator input_type with optimized queries."""

    def __init__(self, domain_id: int, subdomain_ids: Optional[List[int]] = None):
        """
        Args:
            domain_id: Domain ID
            subdomain_ids: Optional list of subdomain IDs (for subscan; restricts to these subdomains)
        """
        self.domain_id = domain_id
        self.subdomain_ids = subdomain_ids or []

    def build_targets_for_type(self, input_type: str) -> List[str]:
        """
        Build target list for a single input_type.

        Args:
            input_type: One of 'url', 'host', 'host:port', 'ip', etc.

        Returns:
            List of target strings (URLs, hosts, host:port, or IPs)
        """
        if input_type == "url":
            return self._targets_url()
        if input_type == "host":
            return self._targets_host()
        if input_type in (HOST_PORT, "host_port"):
            return self._targets_host_port()
        return self._targets_ip() if input_type == "ip" else []

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
        seen = set()
        result: List[str] = []
        for input_type in input_types:
            for t in self.build_targets_for_type(input_type):
                if t not in seen:
                    seen.add(t)
                    result.append(t)
        return result

    def _targets_url(self) -> List[str]:
        """Default endpoints (is_default=True) as full http_url; subdomain-scoped if subdomain_ids."""
        qs: QuerySet = EndPoint.objects.filter(
            target_domain_id=self.domain_id,
            is_default=True,
        ).values_list("http_url", flat=True)
        if self.subdomain_ids:
            qs = qs.filter(subdomain_id__in=self.subdomain_ids)
        return list(qs.distinct())

    def _targets_host(self) -> List[str]:
        """Domain name + subdomain names (hosts). For subscan (subdomain_ids), only selected subdomain names."""
        if self.subdomain_ids:
            return list(
                Subdomain.objects.filter(target_domain_id=self.domain_id, id__in=self.subdomain_ids)
                .values_list("name", flat=True)
                .distinct()
            )
        domain_name = Domain.objects.filter(id=self.domain_id).values_list("name", flat=True).first()
        if not domain_name:
            return []
        hosts: List[str] = [domain_name]
        sub_names = list(
            Subdomain.objects.filter(target_domain_id=self.domain_id).values_list("name", flat=True).distinct()
        )
        seen = {domain_name}
        for name in sub_names:
            if name and name not in seen:
                seen.add(name)
                hosts.append(name)
        return hosts

    def _targets_host_port(self) -> List[str]:
        """Default alive endpoints as host:port (unique)."""
        qs = (
            EndPoint.objects.filter(
                target_domain_id=self.domain_id,
                is_default=True,
                http_status__gt=0,
            )
            .values_list("http_url", flat=True)
            .distinct()
        )
        if self.subdomain_ids:
            qs = qs.filter(subdomain_id__in=self.subdomain_ids)
        host_ports: set = set()
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
        return sorted(host_ports)

    def _targets_ip(self) -> List[str]:
        """IP addresses discovered for this domain (from IpAddress linked via subdomains)."""
        from startScan.models import IpAddress, Subdomain

        if self.subdomain_ids:
            subdomains_qs = Subdomain.objects.filter(
                id__in=self.subdomain_ids,
                target_domain_id=self.domain_id,
            )
            qs = IpAddress.objects.filter(ip_addresses__in=subdomains_qs)
        else:
            qs = IpAddress.objects.filter(ip_addresses__target_domain_id=self.domain_id)
        return list(qs.values_list("address", flat=True).distinct())
