"""
Resolve Target / Scope / Organization / Subdomain / IpAddress for LLM attack-surface APIs
with project membership checks (superusers bypass the filter).
"""

from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db.models import Q

from startScan.models import IpAddress, ScanHistory, Subdomain
from targetApp.models import Organization, Scope, Target


def get_target_for_llm_attack_surface(user: AbstractUser, pk: int) -> Target | None:
    qs = Target.objects.filter(pk=pk)
    if not user.is_superuser:
        qs = qs.filter(project__users=user)
    return qs.first()


def get_scan_history_for_llm_attack_surface(user: AbstractUser, pk: int) -> ScanHistory | None:
    qs = ScanHistory.objects.filter(pk=pk).select_related("target")
    if not user.is_superuser:
        qs = qs.filter(target__project__users=user)
    return qs.first()


def get_scope_for_llm_attack_surface(user: AbstractUser, pk: int) -> Scope | None:
    qs = Scope.objects.filter(pk=pk).select_related("organization")
    if not user.is_superuser:
        qs = qs.filter(organization__project__users=user)
    return qs.first()


def get_organization_for_llm_attack_surface(user: AbstractUser, pk: int) -> Organization | None:
    qs = Organization.objects.filter(pk=pk)
    if not user.is_superuser:
        qs = qs.filter(project__users=user)
    return qs.first()


def get_subdomain_for_llm_attack_surface(user: AbstractUser, pk: int) -> Subdomain | None:
    qs = Subdomain.objects.filter(pk=pk)
    if not user.is_superuser:
        qs = qs.filter(scan_history__target__project__users=user).distinct()
    return qs.first()


def get_ip_address_for_llm_attack_surface(
    user: AbstractUser,
    pk: int,
    *,
    prefetch_attack_surface: bool = False,
) -> IpAddress | None:
    qs = IpAddress.objects.filter(pk=pk)
    if prefetch_attack_surface:
        qs = qs.prefetch_related("ports", "ip_addresses")
    if not user.is_superuser:
        qs = qs.filter(
            Q(ip_addresses__scan_history__target__project__users=user)
            | Q(ip_endpoints__scan_history__target__project__users=user)
        ).distinct()
    return qs.first()
