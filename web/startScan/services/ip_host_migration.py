"""
Data migration helpers for 0119_ip_host (IP host on Endpoint/SubScan, IpAddress metadata).

Kept out of the migration file so schema-only edits do not require maintaining a large RunPython body.

Runtime: not a single database transaction—each step commits as it runs. Worst cost is roughly
O(number of scan-scoped Subdomains + EndPoints) with 1000-row iterator chunks for IP-literal
subdomain cleanup; duplicate-IP merges add extra queries per collision. Large databases (100k+
subdomain rows) can take several minutes—use maintenance windows and watch per-step INFO logs
(elapsed seconds and row counts where logged).
"""

from __future__ import annotations

import logging
import time

from django.db.models import Q

from reNgine.core.ip_literal import is_ip_literal_text, normalize_ip_address_text


_migration_log = logging.getLogger("startScan.migration.0119_ip_host")

_IP_SUBDOMAIN_ITER_CHUNK = 1000


def _warn_skip(step: str, detail_fmt: str, *detail_args: object) -> None:
    _migration_log.warning("0119 %s: " + detail_fmt, step, *detail_args)


def _subdomains_with_scan_ordered(subdomain_model):
    return subdomain_model.objects.exclude(scan_history_id__isnull=True).order_by("id")


def _merge_ip_rows(apps, canonical_id: int, duplicate_id: int) -> None:
    if canonical_id == duplicate_id:
        return
    IpAddress = apps.get_model("startScan", "IpAddress")
    Subdomain = apps.get_model("startScan", "Subdomain")
    EndPoint = apps.get_model("startScan", "EndPoint")
    Port = apps.get_model("startScan", "Port")
    Vulnerability = apps.get_model("startScan", "Vulnerability")
    Certificate = apps.get_model("startScan", "Certificate")
    Exploit = apps.get_model("startScan", "Exploit")

    dup = IpAddress.objects.filter(pk=duplicate_id).first()
    if not dup:
        return
    canon = IpAddress.objects.filter(pk=canonical_id).first()
    if not canon:
        return

    for sub in Subdomain.objects.filter(ip_addresses__id=duplicate_id).distinct():
        sub.ip_addresses.add(canon)
        sub.ip_addresses.remove(dup)

    EndPoint.objects.filter(ip_address_id=duplicate_id).update(ip_address_id=canonical_id)
    Port.objects.filter(ip_address_id=duplicate_id).update(ip_address_id=canonical_id)
    Vulnerability.objects.filter(ip_address_id=duplicate_id).update(ip_address_id=canonical_id)
    Certificate.objects.filter(ip_address_id=duplicate_id).update(ip_address_id=canonical_id)
    Exploit.objects.filter(ip_address_id=duplicate_id).update(ip_address_id=canonical_id)

    dup.delete()


def _ips_in_scan_for_address(apps, scan_history_id: int, address: str):
    IpAddress = apps.get_model("startScan", "IpAddress")
    q = Q(ip_addresses__scan_history_id=scan_history_id) | Q(ip_endpoints__scan_history_id=scan_history_id)
    return list(IpAddress.objects.filter(address=address).filter(q).distinct().order_by("id"))


def _merge_duplicate_ips_per_scan(apps, schema_editor) -> None:
    Subdomain = apps.get_model("startScan", "Subdomain")
    total_subs = _subdomains_with_scan_ordered(Subdomain).count()
    _migration_log.info("0119 merge_duplicate_ips_per_scan: subdomains_with_scan=%s", total_subs)
    seen: dict[tuple[int | None, str], int] = {}
    for sub in _subdomains_with_scan_ordered(Subdomain).prefetch_related("ip_addresses"):
        sid = sub.scan_history_id
        for ip_obj in sub.ip_addresses.all():
            key = (sid, ip_obj.address or "")
            if not key[1]:
                continue
            if key not in seen:
                seen[key] = ip_obj.id
            else:
                canon = seen[key]
                _merge_ip_rows(apps, canon, ip_obj.id)


def _migrate_ip_subdomains(apps, schema_editor) -> None:
    Subdomain = apps.get_model("startScan", "Subdomain")
    IpAddress = apps.get_model("startScan", "IpAddress")
    EndPoint = apps.get_model("startScan", "EndPoint")
    SubScan = apps.get_model("startScan", "SubScan")
    Vulnerability = apps.get_model("startScan", "Vulnerability")
    Certificate = apps.get_model("startScan", "Certificate")
    Exploit = apps.get_model("startScan", "Exploit")
    MetaFinderDocument = apps.get_model("startScan", "MetaFinderDocument")
    Employee = apps.get_model("startScan", "Employee")

    processed_ip_literal = 0
    _migration_log.info("0119 migrate_ip_subdomains: start")

    for sub in _subdomains_with_scan_ordered(Subdomain).iterator(chunk_size=_IP_SUBDOMAIN_ITER_CHUNK):
        if not is_ip_literal_text(sub.name):
            continue
        sub = Subdomain.objects.filter(pk=sub.pk).first()
        if not sub:
            continue
        processed_ip_literal += 1
        if processed_ip_literal % 500 == 0:
            _migration_log.info(
                "0119 migrate_ip_subdomains: progress ip-literal-subdomains=%s",
                processed_ip_literal,
            )
        scan_id = sub.scan_history_id
        normalized = normalize_ip_address_text(sub.name)
        if not normalized:
            _warn_skip("migrate_ip_subdomains", "skip subdomain pk=%s name=%r (normalize failed)", sub.pk, sub.name)
            continue

        if linked := _ips_in_scan_for_address(apps, scan_id, normalized):
            canon = linked[0]
            for extra in linked[1:]:
                _merge_ip_rows(apps, canon.id, extra.id)
        elif ips_on_row := list(sub.ip_addresses.all().order_by("id")):
            canon = ips_on_row[0]
            if canon.address != normalized:
                if clash := IpAddress.objects.filter(address=normalized).exclude(pk=canon.pk).first():
                    _merge_ip_rows(apps, clash.id, canon.id)
                    canon = IpAddress.objects.filter(pk=clash.id).first()
                else:
                    canon.address = normalized
                    canon.save(update_fields=["address"])
            for extra in ips_on_row[1:]:
                _merge_ip_rows(apps, canon.id, extra.id)
        else:
            canon = IpAddress.objects.filter(address=normalized).first()
            if not canon:
                canon = IpAddress.objects.create(
                    address=normalized,
                    is_cdn=False,
                    is_private=False,
                    version=6 if ":" in normalized else 4,
                    alive=False,
                    protocol="IPv6" if ":" in normalized else "IPv4",
                )

        canon = IpAddress.objects.filter(pk=canon.pk).first()
        if not canon:
            continue

        for ip_obj in list(sub.ip_addresses.exclude(pk=canon.pk)):
            _merge_ip_rows(apps, canon.id, ip_obj.id)

        EndPoint.objects.filter(subdomain_id=sub.pk).update(ip_address_id=canon.id, subdomain_id=None)

        SubScan.objects.filter(subdomain_id=sub.pk).update(ip_address_id=canon.id, subdomain_id=None)

        Vulnerability.objects.filter(subdomain_id=sub.pk, ip_address__isnull=True).update(
            ip_address_id=canon.id,
            subdomain_id=None,
        )
        Vulnerability.objects.filter(subdomain_id=sub.pk).exclude(ip_address__isnull=True).update(subdomain_id=None)

        Certificate.objects.filter(subdomain_id=sub.pk, ip_address__isnull=True).update(
            ip_address_id=canon.id,
            subdomain_id=None,
        )
        Certificate.objects.filter(subdomain_id=sub.pk).exclude(ip_address__isnull=True).update(subdomain_id=None)

        Exploit.objects.filter(subdomain_id=sub.pk, ip_address__isnull=True).update(
            ip_address_id=canon.id,
            subdomain_id=None,
        )
        Exploit.objects.filter(subdomain_id=sub.pk).exclude(ip_address__isnull=True).update(subdomain_id=None)

        MetaFinderDocument.objects.filter(subdomain_id=sub.pk).update(subdomain_id=None)
        Employee.objects.filter(subdomain_id=sub.pk).update(subdomain_id=None)

        for ss in SubScan.objects.filter(subdomain_subscan_ids=sub):
            ss.subdomain_subscan_ids.remove(sub)

        sub.delete()

    _migration_log.info("0119 migrate_ip_subdomains: finished ip-literal-subdomains=%s", processed_ip_literal)


def _fix_orphan_endpoints(apps, schema_editor) -> None:
    from urllib.parse import urlparse

    EndPoint = apps.get_model("startScan", "EndPoint")
    IpAddress = apps.get_model("startScan", "IpAddress")

    for ep in EndPoint.objects.filter(
        subdomain__isnull=True,
        ip_address__isnull=True,
    ).exclude(scan_history_id__isnull=True):
        parsed = urlparse(ep.http_url or "")
        host = (parsed.hostname or "").strip()
        if not host.startswith("[") and not is_ip_literal_text(host):
            continue
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not is_ip_literal_text(host):
            continue
        scan_id = ep.scan_history_id
        normalized = normalize_ip_address_text(host)
        if not normalized:
            _warn_skip("fix_orphan_endpoints", "skip endpoint pk=%s host=%r (normalize failed)", ep.pk, host)
            continue
        if linked := _ips_in_scan_for_address(apps, scan_id, normalized):
            canon_id = linked[0].id
        else:
            ep_other = (
                EndPoint.objects.filter(scan_history_id=scan_id, ip_address__address=normalized)
                .exclude(pk=ep.pk)
                .first()
            )
            if ep_other and ep_other.ip_address_id:
                canon_id = ep_other.ip_address_id
            else:
                canon = IpAddress.objects.filter(address=normalized).first()
                if not canon:
                    canon = IpAddress.objects.create(
                        address=normalized,
                        is_cdn=False,
                        is_private=False,
                        version=6 if ":" in normalized else 4,
                        alive=False,
                        protocol="IPv6" if ":" in normalized else "IPv4",
                    )
                canon_id = canon.id
        EndPoint.objects.filter(pk=ep.pk).update(ip_address_id=canon_id)


def _fix_dns_orphan_endpoints(apps, schema_editor) -> None:
    from urllib.parse import urlparse

    EndPoint = apps.get_model("startScan", "EndPoint")
    Subdomain = apps.get_model("startScan", "Subdomain")
    for ep in EndPoint.objects.filter(
        subdomain__isnull=True,
        ip_address__isnull=True,
    ).exclude(scan_history_id__isnull=True):
        host = (urlparse(ep.http_url or "").hostname or "").strip().lower()
        if not host or is_ip_literal_text(host):
            continue
        if sub := Subdomain.objects.filter(scan_history_id=ep.scan_history_id, name=host).first():
            EndPoint.objects.filter(pk=ep.pk).update(subdomain_id=sub.id)


def _remove_endpoints_without_host(apps, schema_editor) -> None:
    EndPoint = apps.get_model("startScan", "EndPoint")
    EndPoint.objects.filter(subdomain__isnull=True, ip_address__isnull=True).delete()


def _normalize_endpoint_dual_hosts(apps, schema_editor) -> None:
    EndPoint = apps.get_model("startScan", "EndPoint")
    dual_qs = EndPoint.objects.filter(subdomain__isnull=False, ip_address__isnull=False)
    n = dual_qs.count()
    if n:
        _migration_log.warning(
            "0119 normalize_endpoint_dual_hosts: clearing ip_address where both hosts set; count=%s",
            n,
        )
        dual_qs.update(ip_address_id=None)


def _final_scrub_endpoints_without_host(apps, schema_editor) -> None:
    EndPoint = apps.get_model("startScan", "EndPoint")
    orphan_qs = EndPoint.objects.filter(subdomain__isnull=True, ip_address__isnull=True)
    n = orphan_qs.count()
    if n:
        _migration_log.warning(
            "0119 final_scrub_endpoints_without_host: deleting rows with no host; count=%s",
            n,
        )
        orphan_qs.delete()


def _log_0119_preflight_counts(apps, schema_editor) -> None:
    Subdomain = apps.get_model("startScan", "Subdomain")
    EndPoint = apps.get_model("startScan", "EndPoint")
    IpAddress = apps.get_model("startScan", "IpAddress")
    _migration_log.info(
        "0119_ip_host preflight: subdomains_with_scan=%s endpoint_rows=%s ipaddress_rows=%s",
        Subdomain.objects.exclude(scan_history_id__isnull=True).count(),
        EndPoint.objects.count(),
        IpAddress.objects.count(),
    )


def forwards_migrate_ip_host_data(apps, schema_editor) -> None:
    run_t0 = time.perf_counter()
    _log_0119_preflight_counts(apps, schema_editor)

    def _step(name: str, fn) -> None:
        t0 = time.perf_counter()
        _migration_log.info("0119_ip_host: step %s (start)", name)
        fn(apps, schema_editor)
        _migration_log.info(
            "0119_ip_host: step %s done in %.2fs (elapsed since start %.2fs)",
            name,
            time.perf_counter() - t0,
            time.perf_counter() - run_t0,
        )

    _step("merge_duplicate_ips_per_scan", _merge_duplicate_ips_per_scan)
    _step("migrate_ip_subdomains", _migrate_ip_subdomains)
    _step("fix_orphan_endpoints", _fix_orphan_endpoints)
    _step("fix_dns_orphan_endpoints", _fix_dns_orphan_endpoints)
    _step("remove_endpoints_without_host", _remove_endpoints_without_host)
    _step("normalize_endpoint_dual_hosts", _normalize_endpoint_dual_hosts)
    _step("final_scrub_endpoints_without_host", _final_scrub_endpoints_without_host)
    _migration_log.info(
        "0119_ip_host: data migration completed in %.2fs",
        time.perf_counter() - run_t0,
    )


def backwards_migrate_ip_host_data(apps, schema_editor) -> None:
    pass
