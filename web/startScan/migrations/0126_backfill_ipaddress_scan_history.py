from django.db import migrations


def _copy_model_fields(instance, excluded_field_names):
    data = {}
    for field in instance._meta.concrete_fields:
        if field.name in excluded_field_names:
            continue
        data[field.name] = getattr(instance, field.name)
    return data


def _duplicate_ports_for_target(port_model, source_ip, target_ip):
    source_ports = list(port_model.objects.filter(ip_address_id=source_ip.id))
    if not source_ports:
        return
    target_port_numbers = set(port_model.objects.filter(ip_address_id=target_ip.id).values_list("number", flat=True))
    new_ports = []
    for source_port in source_ports:
        if source_port.number in target_port_numbers:
            continue
        port_data = _copy_model_fields(source_port, {"id", "ip_address"})
        port_data["ip_address_id"] = target_ip.id
        new_ports.append(port_model(**port_data))
    if new_ports:
        port_model.objects.bulk_create(new_ports)


def _migrate_relations_for_scan(subdomain_model, endpoint_model, subscan_model, source_ip, target_ip, scan_history_id):
    if target_ip.id != source_ip.id:
        subdomains = subdomain_model.objects.filter(scan_history_id=scan_history_id, ip_addresses=source_ip).distinct()
        for subdomain in subdomains:
            subdomain.ip_addresses.add(target_ip)
            subdomain.ip_addresses.remove(source_ip)

        endpoint_model.objects.filter(scan_history_id=scan_history_id, ip_address_id=source_ip.id).update(
            ip_address_id=target_ip.id
        )

        subscans = subscan_model.objects.filter(scan_history_id=scan_history_id, ip_subscan_ids=source_ip).distinct()
        for subscan in subscans:
            subscan.ip_subscan_ids.add(target_ip)
            subscan.ip_subscan_ids.remove(source_ip)


def backfill_scan_history(apps, schema_editor):
    ip_model = apps.get_model("startScan", "IpAddress")
    subdomain_model = apps.get_model("startScan", "Subdomain")
    endpoint_model = apps.get_model("startScan", "EndPoint")
    port_model = apps.get_model("startScan", "Port")
    subscan_model = apps.get_model("startScan", "SubScan")

    address_scan_to_id = {
        (address, scan_history_id): ip_id
        for ip_id, address, scan_history_id in ip_model.objects.exclude(address__isnull=True)
        .exclude(scan_history_id__isnull=True)
        .values_list("id", "address", "scan_history_id")
    }
    ip_to_subdomain_scan_ids = {}
    for ip_id, scan_history_id in (
        subdomain_model.objects.filter(ip_addresses__isnull=False)
        .exclude(scan_history_id__isnull=True)
        .values_list("ip_addresses__id", "scan_history_id")
        .distinct()
    ):
        if ip_id is None or scan_history_id is None:
            continue
        ip_to_subdomain_scan_ids.setdefault(ip_id, set()).add(scan_history_id)

    ip_to_endpoint_scan_ids = {}
    for ip_id, scan_history_id in (
        endpoint_model.objects.filter(ip_address_id__isnull=False)
        .exclude(scan_history_id__isnull=True)
        .values_list("ip_address_id", "scan_history_id")
        .distinct()
    ):
        if ip_id is None or scan_history_id is None:
            continue
        ip_to_endpoint_scan_ids.setdefault(ip_id, set()).add(scan_history_id)

    ip_instance_cache = {}

    for ip_row in ip_model.objects.all().order_by("id").iterator(chunk_size=1000):
        candidate_scans = set()
        if ip_row.scan_history_id:
            candidate_scans.add(ip_row.scan_history_id)
        candidate_scans.update(ip_to_subdomain_scan_ids.get(ip_row.id, set()))
        candidate_scans.update(ip_to_endpoint_scan_ids.get(ip_row.id, set()))
        if not candidate_scans:
            continue

        ordered_scan_ids = sorted(candidate_scans)
        primary_scan_id = ip_row.scan_history_id if ip_row.scan_history_id in candidate_scans else ordered_scan_ids[0]
        if ip_row.scan_history_id != primary_scan_id:
            ip_row.scan_history_id = primary_scan_id
            ip_row.save(update_fields=["scan_history_id"])
            if ip_row.address:
                address_scan_to_id[(ip_row.address, primary_scan_id)] = ip_row.id

        for scan_id in ordered_scan_ids:
            if scan_id == primary_scan_id:
                target_ip = ip_row
            else:
                target_ip_id = address_scan_to_id.get((ip_row.address, scan_id)) if ip_row.address else None
                if target_ip_id:
                    if target_ip_id in ip_instance_cache:
                        target_ip = ip_instance_cache[target_ip_id]
                    else:
                        target_ip = ip_model.objects.get(id=target_ip_id)
                        ip_instance_cache[target_ip_id] = target_ip
                else:
                    ip_data = _copy_model_fields(ip_row, {"id", "scan_history"})
                    ip_data["scan_history_id"] = scan_id
                    target_ip = ip_model.objects.create(**ip_data)
                    if ip_row.address:
                        address_scan_to_id[(ip_row.address, scan_id)] = target_ip.id
                    ip_instance_cache[target_ip.id] = target_ip

                _duplicate_ports_for_target(port_model, ip_row, target_ip)

            _migrate_relations_for_scan(
                subdomain_model=subdomain_model,
                endpoint_model=endpoint_model,
                subscan_model=subscan_model,
                source_ip=ip_row,
                target_ip=target_ip,
                scan_history_id=scan_id,
            )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("startScan", "0125_ipaddress_scan_history"),
    ]

    operations = [
        migrations.RunPython(backfill_scan_history, migrations.RunPython.noop),
    ]
