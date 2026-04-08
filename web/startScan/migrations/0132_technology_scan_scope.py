from django.db import migrations, models
import django.db.models.deletion


def _backfill_technology_scan_scope(apps, schema_editor):
    Technology = apps.get_model("startScan", "Technology")
    Subdomain = apps.get_model("startScan", "Subdomain")
    SubdomainTechnology = apps.get_model("startScan", "SubdomainTechnology")
    EndPoint = apps.get_model("startScan", "EndPoint")
    endpoint_tech_through = EndPoint.techs.through

    subdomain_scan_by_id = dict(Subdomain.objects.values_list("id", "scan_history_id"))
    endpoint_scan_by_id = dict(EndPoint.objects.values_list("id", "scan_history_id"))
    technology_rows = {
        row["id"]: row
        for row in Technology.objects.values(
            "id",
            "scan_history_id",
            "name",
            "value",
            "category",
            "stored_response_path",
        )
    }
    cloned_cache = {}
    technology_scan_ids = {}

    def remember_scan(technology_id, scan_id):
        if not technology_id or not scan_id:
            return
        technology_scan_ids.setdefault(technology_id, set()).add(scan_id)

    def scoped_technology_id(technology_id, scan_id):
        if not technology_id or not scan_id:
            return technology_id
        cache_key = (technology_id, scan_id)
        if cache_key in cloned_cache:
            return cloned_cache[cache_key]

        current = technology_rows.get(technology_id)
        if not current:
            return technology_id
        if current.get("scan_history_id") == scan_id:
            cloned_cache[cache_key] = technology_id
            return technology_id

        scoped_technology, _ = Technology.objects.get_or_create(
            scan_history_id=scan_id,
            name=current.get("name"),
            value=current.get("value"),
            category=current.get("category"),
            stored_response_path=current.get("stored_response_path"),
        )
        if scoped_technology.id not in technology_rows:
            technology_rows[scoped_technology.id] = {
                "id": scoped_technology.id,
                "scan_history_id": scan_id,
                "name": current.get("name"),
                "value": current.get("value"),
                "category": current.get("category"),
                "stored_response_path": current.get("stored_response_path"),
            }
        cloned_cache[cache_key] = scoped_technology.id
        return scoped_technology.id

    subdomain_updates = []
    subdomain_delete_ids = []
    for row in SubdomainTechnology.objects.values("id", "subdomain_id", "technology_id").iterator(chunk_size=2000):
        scan_id = subdomain_scan_by_id.get(row["subdomain_id"])
        tech_id = row["technology_id"]
        remember_scan(tech_id, scan_id)
        scoped_id = scoped_technology_id(tech_id, scan_id)
        remember_scan(scoped_id, scan_id)
        if not scoped_id or scoped_id == tech_id:
            continue
        if SubdomainTechnology.objects.filter(subdomain_id=row["subdomain_id"], technology_id=scoped_id).exists():
            subdomain_delete_ids.append(row["id"])
            continue
        subdomain_updates.append(SubdomainTechnology(id=row["id"], technology_id=scoped_id))
    if subdomain_updates:
        SubdomainTechnology.objects.bulk_update(subdomain_updates, ["technology_id"], batch_size=1000)
    if subdomain_delete_ids:
        SubdomainTechnology.objects.filter(id__in=subdomain_delete_ids).delete()

    endpoint_updates = []
    endpoint_delete_ids = []
    for row in endpoint_tech_through.objects.values("id", "endpoint_id", "technology_id").iterator(chunk_size=2000):
        scan_id = endpoint_scan_by_id.get(row["endpoint_id"])
        tech_id = row["technology_id"]
        remember_scan(tech_id, scan_id)
        scoped_id = scoped_technology_id(tech_id, scan_id)
        remember_scan(scoped_id, scan_id)
        if not scoped_id or scoped_id == tech_id:
            continue
        if endpoint_tech_through.objects.filter(endpoint_id=row["endpoint_id"], technology_id=scoped_id).exists():
            endpoint_delete_ids.append(row["id"])
            continue
        endpoint_updates.append(endpoint_tech_through(id=row["id"], technology_id=scoped_id))
    if endpoint_updates:
        endpoint_tech_through.objects.bulk_update(endpoint_updates, ["technology_id"], batch_size=1000)
    if endpoint_delete_ids:
        endpoint_tech_through.objects.filter(id__in=endpoint_delete_ids).delete()

    for technology_id, scan_ids in technology_scan_ids.items():
        if len(scan_ids) != 1:
            continue
        scan_id = next(iter(scan_ids))
        Technology.objects.filter(id=technology_id, scan_history_id__isnull=True).update(scan_history_id=scan_id)

    duplicate_groups = (
        Technology.objects.exclude(scan_history_id__isnull=True)
        .exclude(name__isnull=True)
        .values("scan_history_id", "name")
        .annotate(c=models.Count("id"))
        .filter(c__gt=1)
    )
    for group in duplicate_groups.iterator(chunk_size=500):
        tech_ids = list(
            Technology.objects.filter(
                scan_history_id=group["scan_history_id"],
                name=group["name"],
            )
            .order_by("id")
            .values_list("id", flat=True)
        )
        if len(tech_ids) <= 1:
            continue
        keep_id = tech_ids[0]
        duplicate_ids = tech_ids[1:]

        endpoint_tech_through.objects.filter(technology_id__in=duplicate_ids).update(technology_id=keep_id)
        SubdomainTechnology.objects.filter(technology_id__in=duplicate_ids).update(technology_id=keep_id)

        duplicate_link_ids = []
        for link_group in (
            SubdomainTechnology.objects.filter(technology_id=keep_id)
            .values("subdomain_id")
            .annotate(c=models.Count("id"))
            .filter(c__gt=1)
            .iterator(chunk_size=500)
        ):
            ids = list(
                SubdomainTechnology.objects.filter(
                    technology_id=keep_id,
                    subdomain_id=link_group["subdomain_id"],
                )
                .order_by("id")
                .values_list("id", flat=True)
            )
            duplicate_link_ids.extend(ids[1:])
        if duplicate_link_ids:
            SubdomainTechnology.objects.filter(id__in=duplicate_link_ids).delete()

        endpoint_dupe_ids = []
        for link_group in (
            endpoint_tech_through.objects.filter(technology_id=keep_id)
            .values("endpoint_id")
            .annotate(c=models.Count("id"))
            .filter(c__gt=1)
            .iterator(chunk_size=500)
        ):
            ids = list(
                endpoint_tech_through.objects.filter(
                    technology_id=keep_id,
                    endpoint_id=link_group["endpoint_id"],
                )
                .order_by("id")
                .values_list("id", flat=True)
            )
            endpoint_dupe_ids.extend(ids[1:])
        if endpoint_dupe_ids:
            endpoint_tech_through.objects.filter(id__in=endpoint_dupe_ids).delete()

        Technology.objects.filter(id__in=duplicate_ids).delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("startScan", "0131_rename_startscan_llm_at_content_16e0db_idx_startscan_l_content_6b1cca_idx_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="technology",
            name="scan_history",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="technologies",
                to="startScan.scanhistory",
            ),
        ),
        migrations.RunPython(_backfill_technology_scan_scope, migrations.RunPython.noop),
    ]
