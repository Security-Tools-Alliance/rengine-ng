"""Add ``EndPoint.port`` FK and backfill from URL + existing ``Port`` rows.

Operator hints for **very large** ``EndPoint`` tables:

- If logs warn about port-map size or the process is memory-bound, **lower**
  ``RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK`` first (try the 500–2000 range) so each batch’s
  in-memory ``(ip_id, port) → port_pk`` map stays smaller.
- ``RENGINE_MIG_0130_PENDING_SCAN_CHUNK`` controls ORM iterator read size; defaults are usually
  enough—raise only when the database comfortably handles larger chunks.
- ``RENGINE_MIG_0130_PROGRESS_LOG_EVERY`` balances progress visibility against log volume on long runs.

When any of these variables is set in the environment, the backfill emits one INFO line with the
effective (clamped) values and ``large_port_map_warn_threshold`` so you can correlate behaviour with tuning.
"""

from collections import defaultdict
import logging
import os
from typing import Any

from django.core.exceptions import FieldDoesNotExist
from django.db import migrations, models

from reNgine.services.endpoint_port_resolution import (
    PortIdByIpAndNumber,
    extract_port_number_from_http_url,
    resolve_port_pk_for_endpoint_maps,
)


logger = logging.getLogger("rengine.migrations")

# Optional tuning via environment (values are clamped to safe ranges to limit memory and log volume):
#   RENGINE_MIG_0130_PENDING_SCAN_CHUNK  — ORM iterator fetch size when streaming pending rows (default 5000, max 50000)
#   RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK — endpoints per in-memory port-map batch + bulk_update batch (default 1000, max 20000)
#   RENGINE_MIG_0130_PROGRESS_LOG_EVERY  — progress log interval (default 50000, max 2000000)

_PENDING_CHUNK_DEFAULT, _PENDING_CHUNK_MIN, _PENDING_CHUNK_MAX = 5000, 100, 50_000
_BACKFILL_CHUNK_DEFAULT, _BACKFILL_CHUNK_MIN, _BACKFILL_CHUNK_MAX = 1000, 50, 20_000
_PROGRESS_LOG_DEFAULT, _PROGRESS_LOG_MIN, _PROGRESS_LOG_MAX = 100_000, 1_000, 2_000_000

# Warn when a single batch port lookup map is very large (memory pressure).
_LARGE_PORT_MAP_WARNING_THRESHOLD = 500_000

_MIG_0130_ENV_KEYS = (
    "RENGINE_MIG_0130_PENDING_SCAN_CHUNK",
    "RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK",
    "RENGINE_MIG_0130_PROGRESS_LOG_EVERY",
)


def _migration_env_overrides_present() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _MIG_0130_ENV_KEYS:
        raw = os.environ.get(name)
        if raw is not None and str(raw).strip() != "":
            out[name] = str(raw).strip()
    return out


def _ip_addresses_m2m_through_meta(subdomain_model: type) -> tuple[type, str, str]:
    """
    Resolve the through model and FK column names for ``Subdomain.ip_addresses``.

    Uses Django's M2M descriptors instead of hard-coded table/column names so renames of the
    automatic through table still work when replaying migrations on a fresh database.
    """
    try:
        m2m = subdomain_model._meta.get_field("ip_addresses")
    except FieldDoesNotExist as exc:
        raise RuntimeError(
            "0130_endpoint_port_fk_and_backfill: Subdomain has no 'ip_addresses' field; "
            "update this migration if the relation was renamed."
        ) from exc
    if not getattr(m2m, "many_to_many", False):
        raise RuntimeError("0130_endpoint_port_fk_and_backfill: 'ip_addresses' must be a ManyToManyField.")
    through_model = m2m.remote_field.through
    if through_model is None:
        raise RuntimeError("0130_endpoint_port_fk_and_backfill: ip_addresses has no through model.")
    lhs_model = m2m.model
    rhs_model = m2m.remote_field.model
    lhs_key = (lhs_model._meta.app_label, lhs_model._meta.model_name)
    rhs_key = (rhs_model._meta.app_label, rhs_model._meta.model_name)
    sub_fk_attname: str | None = None
    ip_fk_attname: str | None = None
    for cand in through_model._meta.fields:
        if not isinstance(cand, models.ForeignKey):
            continue
        rel_meta = cand.remote_field.model._meta
        rel_key = (rel_meta.app_label, rel_meta.model_name)
        if rel_key == lhs_key:
            sub_fk_attname = cand.get_attname()
        elif rel_key == rhs_key:
            ip_fk_attname = cand.get_attname()
    if sub_fk_attname is None or ip_fk_attname is None:
        raise RuntimeError(
            "0130_endpoint_port_fk_and_backfill: could not resolve two ForeignKey columns on "
            "through model %r for Subdomain.ip_addresses (expected sides %s and %s)."
            % (through_model._meta.label_lower, lhs_key, rhs_key)
        )
    return through_model, sub_fk_attname, ip_fk_attname


def _migration_int_from_env(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(low, min(high, int(str(raw).strip(), 10)))
    except (TypeError, ValueError):
        return default


def backfill_endpoint_port(apps, schema_editor):
    """
    Assign ``EndPoint.port`` from URL port and existing ``Port`` rows.

    Rules: ``RESOLUTION_RULES_SUMMARY`` constant in ``reNgine.services.endpoint_port_resolution``
    (same as ``EndpointRepository._resolve_port_for_host`` at runtime).

    This migration is non-atomic (``atomic = False``) and restart-safe. On very large ``EndPoint``
    tables, expect a long run (many rows with ``port_id`` NULL are scanned); progress is logged
    at a configurable interval (see env vars, clamped). If any ``RENGINE_MIG_0130_*`` environment
    variable is set, an INFO line records the **effective** values after clamping and
    ``large_port_map_warn_threshold`` so operators can correlate tuning with behaviour. The
    effective interval is at least ``pending_count`` when that is smaller than the configured step,
    so very small tables log at most once when the scan completes.

    Port lookup maps are built **per batch** of pending endpoints (see ``RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK``)
    so peak memory stays bounded by the batch size instead of scaling with the full pending set.
    """
    endpoint_model = apps.get_model("startScan", "EndPoint")
    port_model = apps.get_model("startScan", "Port")
    subdomain_model = apps.get_model("startScan", "Subdomain")

    pending_chunk = _migration_int_from_env(
        "RENGINE_MIG_0130_PENDING_SCAN_CHUNK",
        _PENDING_CHUNK_DEFAULT,
        _PENDING_CHUNK_MIN,
        _PENDING_CHUNK_MAX,
    )
    backfill_chunk = _migration_int_from_env(
        "RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK",
        _BACKFILL_CHUNK_DEFAULT,
        _BACKFILL_CHUNK_MIN,
        _BACKFILL_CHUNK_MAX,
    )
    progress_every = _migration_int_from_env(
        "RENGINE_MIG_0130_PROGRESS_LOG_EVERY",
        _PROGRESS_LOG_DEFAULT,
        _PROGRESS_LOG_MIN,
        _PROGRESS_LOG_MAX,
    )

    pending = endpoint_model.objects.filter(port_id__isnull=True).only(
        "id",
        "http_url",
        "ip_address_id",
        "subdomain_id",
        "port_id",
    )

    pending_count = pending.count()
    logger.info(
        "0130_endpoint_port_fk_and_backfill: %s EndPoint row(s) with null port_id (pending)",
        pending_count,
    )
    if pending_count == 0:
        return

    effective_progress_every = progress_every if pending_count >= progress_every else max(pending_count, 1)
    env_overrides = _migration_env_overrides_present()
    if env_overrides:
        logger.info(
            "0130_endpoint_port_fk_and_backfill: operator env override(s) %r — effective "
            "pending_scan_chunk=%s backfill_batch_chunk=%s progress_log_every(config)=%s "
            "progress_log_every(effective)=%s large_port_map_warn_threshold=%s",
            env_overrides,
            pending_chunk,
            backfill_chunk,
            progress_every,
            effective_progress_every,
            _LARGE_PORT_MAP_WARNING_THRESHOLD,
        )

    through_model, sub_fk_attname, ip_fk_attname = _ip_addresses_m2m_through_meta(subdomain_model)
    large_map_warned = False
    processed = 0

    def process_batch(batch: list[Any]) -> None:
        nonlocal processed, large_map_warned
        if not batch:
            return

        # Per batch: collect IP ids from endpoints and expand via subdomain→IP M2M so port lookup
        # only loads Port rows for IPs that can matter for this batch (bounded by batch size).
        relevant_ip_ids: set[int] = set()
        subdomain_ids_needed: set[int] = set()
        for row in batch:
            if row.ip_address_id:
                relevant_ip_ids.add(row.ip_address_id)
            if row.subdomain_id:
                subdomain_ids_needed.add(row.subdomain_id)

        subdomain_to_ip_ids: dict[int, set[int]] = defaultdict(set)
        if subdomain_ids_needed:
            sub_in = {f"{sub_fk_attname}__in": subdomain_ids_needed}
            for sid, iid in through_model.objects.filter(**sub_in).values_list(sub_fk_attname, ip_fk_attname):
                subdomain_to_ip_ids[sid].add(iid)
                relevant_ip_ids.add(iid)

        # Map (ip_address_id, port_number) → port row id; built only from IPs referenced above.
        # Large-map warning compares len(port_id_by_ip_and_number) to _LARGE_PORT_MAP_WARNING_THRESHOLD.
        port_id_by_ip_and_number: PortIdByIpAndNumber = {}
        if relevant_ip_ids:
            for ip_id, number, port_id in (
                port_model.objects.filter(ip_address_id__in=relevant_ip_ids)
                .order_by("id")
                .values_list("ip_address_id", "number", "id")
            ):
                key = (ip_id, number)
                if key not in port_id_by_ip_and_number:
                    port_id_by_ip_and_number[key] = port_id

        n_port_keys = len(port_id_by_ip_and_number)
        if n_port_keys > _LARGE_PORT_MAP_WARNING_THRESHOLD and not large_map_warned:
            logger.warning(
                "0130_endpoint_port_fk_and_backfill: port lookup map size %s exceeds threshold %s "
                "(batch_endpoints=%s, effective_backfill_batch_chunk=%s, effective_pending_scan_chunk=%s, "
                "env RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK=%r, env RENGINE_MIG_0130_PENDING_SCAN_CHUNK=%r). "
                "Lower RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK to reduce peak memory per batch.",
                n_port_keys,
                _LARGE_PORT_MAP_WARNING_THRESHOLD,
                len(batch),
                backfill_chunk,
                pending_chunk,
                os.environ.get("RENGINE_MIG_0130_BACKFILL_BATCH_CHUNK"),
                os.environ.get("RENGINE_MIG_0130_PENDING_SCAN_CHUNK"),
            )
            large_map_warned = True

        # Memoize subdomain+port → resolved Port id within this batch to avoid repeated scans over ip_ids.
        port_id_by_subdomain_and_number: dict[tuple[int, int], int | None] = {}
        to_update: list[Any] = []

        for endpoint in batch:
            processed += 1
            if effective_progress_every > 0 and processed % effective_progress_every == 0:
                logger.info(
                    "0130_endpoint_port_fk_and_backfill: scanned %s / %s EndPoint rows (port_id still null)",
                    processed,
                    pending_count,
                )

            port_number = extract_port_number_from_http_url(endpoint.http_url)
            if port_number is None:
                continue

            resolved_port_id = resolve_port_pk_for_endpoint_maps(
                port_number=port_number,
                ip_address_id=endpoint.ip_address_id,
                subdomain_id=endpoint.subdomain_id,
                subdomain_to_ip_ids=subdomain_to_ip_ids,
                port_id_by_ip_and_number=port_id_by_ip_and_number,
                subdomain_port_cache=port_id_by_subdomain_and_number,
            )

            if resolved_port_id is None:
                continue

            endpoint.port_id = resolved_port_id
            to_update.append(endpoint)

        if to_update:
            endpoint_model.objects.bulk_update(to_update, ["port_id"], batch_size=backfill_chunk)

    batch: list[Any] = []
    for row in pending.order_by("id").iterator(chunk_size=pending_chunk):
        batch.append(row)
        if len(batch) >= backfill_chunk:
            process_batch(batch)
            batch = []
    process_batch(batch)


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("startScan", "0129_remove_subdomain_ipaddress_attack_surface"),
    ]

    operations = [
        migrations.AddField(
            model_name="endpoint",
            name="port",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name="endpoints",
                to="startScan.port",
            ),
        ),
        migrations.RunPython(backfill_endpoint_port, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="endpoint",
            index=models.Index(fields=["subdomain_id", "port_id", "is_default"], name="ss_ep_sub_port_def_idx"),
        ),
        migrations.AddIndex(
            model_name="endpoint",
            index=models.Index(fields=["ip_address_id", "port_id", "is_default"], name="ss_ep_ip_port_def_idx"),
        ),
        migrations.AddIndex(
            model_name="endpoint",
            index=models.Index(fields=["scan_history_id", "port_id"], name="ss_ep_scan_port_idx"),
        ),
    ]
