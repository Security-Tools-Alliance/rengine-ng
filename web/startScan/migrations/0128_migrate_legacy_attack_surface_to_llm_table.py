from django.apps import apps as global_apps
from django.contrib.contenttypes.management import create_contenttypes
from django.db import migrations


_UNSPECIFIED = "__unspecified__"


def _ensure_content_types_for_apps(schema_editor, app_labels: tuple[str, ...]) -> None:
    """Populate django_content_type rows before lookups (post_migrate has not run yet)."""
    using = schema_editor.connection.alias
    for app_label in app_labels:
        create_contenttypes(
            global_apps.get_app_config(app_label),
            interactive=False,
            verbosity=0,
            using=using,
        )


def _legacy_model_key_and_body(raw):
    if raw is None:
        return _UNSPECIFIED, ""
    text = str(raw).strip()
    if not text:
        return _UNSPECIFIED, ""
    if text.startswith("[LLM:") and "]" in text:
        close = text.index("]")
        inner = text[5:close].strip()
        body = text[close + 1 :].lstrip("\n").strip("\n")
        key = inner if inner else _UNSPECIFIED
        return key, body
    if text.startswith("[LLM]"):
        body = text[5:].lstrip("\n").strip("\n")
        return _UNSPECIFIED, body
    return _UNSPECIFIED, text


def _migrate_rows(apps, django_app_label, model_class_name, ct_map, field_name):
    llm_attack_surface_model = apps.get_model("startScan", "LlmAttackSurfaceAnalysis")
    Model = apps.get_model(django_app_label, model_class_name)
    ct_id = ct_map[(django_app_label.lower(), model_class_name.lower())]
    qs = Model.objects.exclude(**{f"{field_name}__isnull": True}).exclude(**{field_name: ""})
    for row in qs.iterator(chunk_size=500):
        raw = getattr(row, field_name)
        llm_key, body = _legacy_model_key_and_body(raw)
        if not (body or "").strip():
            continue
        llm_attack_surface_model.objects.update_or_create(
            content_type_id=ct_id,
            object_id=row.pk,
            llm_model=llm_key,
            defaults={"body_markdown": body.strip()},
        )


def forwards(apps, schema_editor):
    _ensure_content_types_for_apps(schema_editor, ("startScan", "targetApp"))
    content_type_model = apps.get_model("contenttypes", "ContentType")

    def cid(app_label, model_name_lower):
        return content_type_model.objects.only("id").get(app_label=app_label, model=model_name_lower).id

    # AppConfig.label values (not lowercased) match django_content_type.app_label.
    ct_map = {
        ("startscan", "subdomain"): cid("startScan", "subdomain"),
        ("startscan", "ipaddress"): cid("startScan", "ipaddress"),
        ("targetapp", "target"): cid("targetApp", "target"),
        ("targetapp", "scope"): cid("targetApp", "scope"),
        ("targetapp", "organization"): cid("targetApp", "organization"),
    }

    _migrate_rows(apps, "startScan", "Subdomain", ct_map, "attack_surface")
    _migrate_rows(apps, "startScan", "IpAddress", ct_map, "attack_surface")
    _migrate_rows(apps, "targetApp", "Target", ct_map, "attack_surface")
    _migrate_rows(apps, "targetApp", "Scope", ct_map, "attack_surface")
    _migrate_rows(apps, "targetApp", "Organization", ct_map, "attack_surface")


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0127_llm_attack_surface_analysis"),
        ("targetApp", "0064_target_scope_organization_attack_surface"),
    ]

    operations = [
        migrations.RunPython(forwards, noop_reverse),
    ]
