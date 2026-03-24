"""
Persist and query LLM attack-surface analyses per asset (GenericFK).

Legacy markdown used a single TextField with an optional ``[LLM:model]`` prefix; rows here
store the model key in ``llm_model`` and raw markdown in ``body_markdown``.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models import Exists, OuterRef, QuerySet

from reNgine.llm.utils import convert_markdown_to_html


# Stored when the legacy header was ``[LLM]`` or no model was provided.
UNSPECIFIED_LLM_MODEL_KEY = "__unspecified__"


def parse_legacy_attack_surface_text(raw: str | None) -> tuple[str, str]:
    """
    Parse legacy ``attack_surface`` TextField content into (model_key, body_markdown).

    ``model_key`` is the string inside ``[LLM:...]`` or empty when unspecified.
    """
    if raw is None:
        return "", ""
    text = str(raw).strip()
    if not text:
        return "", ""
    if text.startswith("[LLM:") and "]" in text:
        close = text.index("]")
        inner = text[5:close].strip()
        body = text[close + 1 :].lstrip("\n").strip("\n")
        return inner, body
    if text.startswith("[LLM]"):
        body = text[5:].lstrip("\n").strip("\n")
        return "", body
    return "", text


def normalized_llm_model_storage_key(selected_model: str | None) -> str:
    s = (selected_model or "").strip()
    return s if s else UNSPECIFIED_LLM_MODEL_KEY


def display_llm_model(stored_key: str) -> str:
    if stored_key == UNSPECIFIED_LLM_MODEL_KEY:
        return "(unspecified)"
    return stored_key


def analyses_for_parent(parent: models.Model) -> QuerySet:
    from startScan.models import LlmAttackSurfaceAnalysis

    ct = ContentType.objects.get_for_model(parent.__class__)
    return LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=parent.pk).order_by("-updated_at", "-id")


def parent_has_llm_attack_surface_analyses(parent: models.Model) -> bool:
    return analyses_for_parent(parent).exists()


def get_analysis_for_parent(parent: models.Model, analysis_id: int) -> Any:
    if analysis_id <= 0:
        return None
    return analyses_for_parent(parent).filter(pk=analysis_id).first()


def serialized_saved_analyses(qs: QuerySet) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "llm_model": display_llm_model(row.llm_model),
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        }
        for row in qs
    ]


def analysis_body_as_html(analysis: Any) -> str:
    return convert_markdown_to_html(analysis.body_markdown or "")


def upsert_llm_attack_surface_analysis(parent: models.Model, selected_model: str | None, body_markdown: str) -> Any:
    from startScan.models import LlmAttackSurfaceAnalysis

    ct = ContentType.objects.get_for_model(parent.__class__)
    key = normalized_llm_model_storage_key(selected_model)
    obj, _created = LlmAttackSurfaceAnalysis.objects.update_or_create(
        content_type=ct,
        object_id=parent.pk,
        llm_model=key,
        defaults={"body_markdown": body_markdown},
    )
    return obj


def delete_all_analyses_for_parent(parent: models.Model) -> int:
    return analyses_for_parent(parent).delete()[0]


def delete_one_analysis_for_parent(parent: models.Model, analysis_id: int) -> bool:
    row = get_analysis_for_parent(parent, analysis_id)
    if row is None:
        return False
    row.delete()
    return True


def annotate_subdomain_queryset_with_llm_attack_surface_flag(queryset: QuerySet) -> QuerySet:
    """Add ``llm_attack_surface_exists`` (bool) for Subdomain rows."""
    from startScan.models import LlmAttackSurfaceAnalysis, Subdomain

    ct = ContentType.objects.get_for_model(Subdomain)
    subq = LlmAttackSurfaceAnalysis.objects.filter(content_type=ct, object_id=OuterRef("pk"))
    return queryset.annotate(llm_attack_surface_exists=Exists(subq))
