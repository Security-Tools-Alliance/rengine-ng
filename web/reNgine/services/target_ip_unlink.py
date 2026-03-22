"""Coordinated unlink of IP addresses from a target across subdomains and endpoints."""

from django.db import transaction

from startScan.models import EndPoint, IpAddress, Subdomain


def unlink_ip_addresses_from_target(target_id: int, ip_address_ids: list[int]) -> None:
    """
    Remove the given IPs from all subdomains of the target and reconcile endpoints.

    Caller must validate that each id in ``ip_address_ids`` is linked to ``target_id``.
    All steps run in a single database transaction.
    """
    with transaction.atomic():
        subdomains = Subdomain.objects.filter(scan_history__target_id=target_id)
        for ip_row_id in ip_address_ids:
            ip_row = IpAddress.objects.filter(id=ip_row_id).first()
            if not ip_row:
                continue
            for sd in subdomains.filter(ip_addresses=ip_row):
                sd.ip_addresses.remove(ip_row)

        EndPoint.objects.filter(
            scan_history__target_id=target_id,
            ip_address_id__in=ip_address_ids,
            subdomain__isnull=True,
        ).delete()
        EndPoint.objects.filter(
            scan_history__target_id=target_id,
            ip_address_id__in=ip_address_ids,
        ).update(ip_address=None)
