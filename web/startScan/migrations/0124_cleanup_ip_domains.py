from contextlib import suppress
import ipaddress

from django.db import migrations


CHILD_MODELS_WITH_DOMAIN_FK = (
    "Subdomain",
    "EndPoint",
    "Vulnerability",
    "MetaFinderDocument",
    "Employee",
    "Exploit",
    "SecatorRunner",
    "Certificate",
)


def _is_ip_literal(value: str) -> bool:
    if not value:
        return False

    candidate = value.strip().strip(".")
    if not candidate:
        return False

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return _is_ip_range(candidate)
    return True


def _is_ip_range(value: str) -> bool:
    with suppress(ValueError):
        ipaddress.ip_network(value, strict=False)
        return True

    if "-" not in value:
        return False

    start_str, end_str = (part.strip() for part in value.split("-", maxsplit=1))
    if not start_str or not end_str:
        return False

    try:
        start_ip = ipaddress.ip_address(start_str)
        end_ip = ipaddress.ip_address(end_str)
    except ValueError:
        return False

    if start_ip.version != end_ip.version:
        return False

    return int(start_ip) <= int(end_ip)


def cleanup_ip_domains(apps, schema_editor):
    Domain = apps.get_model("startScan", "Domain")
    ip_domain_ids = [domain_id for domain_id, name in Domain.objects.values_list("id", "name") if _is_ip_literal(name)]
    if not ip_domain_ids:
        return

    for model_name in CHILD_MODELS_WITH_DOMAIN_FK:
        model = apps.get_model("startScan", model_name)
        model.objects.filter(domain_id__in=ip_domain_ids).update(domain_id=None)

    Domain.objects.filter(id__in=ip_domain_ids).delete()


def noop_reverse(apps, schema_editor):
    return None


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0123_alter_subdomain_technologies_and_more"),
    ]

    operations = [
        migrations.RunPython(cleanup_ip_domains, noop_reverse),
    ]
