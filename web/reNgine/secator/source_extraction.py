"""Extract Secator tool/source string from hook payloads (OutputType JSON)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def extract_secator_tool_source(
    item: Dict[str, Any],
    *,
    include_provider: bool = True,
    max_length: int = 200,
) -> Optional[str]:
    """
    Return a single non-empty tool/source label from a Secator finding dict.

    Order: ``provider`` (optional), ``_source``, then ``_context`` keys
    ``runner_name``, ``name``, ``node_id``.
    """
    if not isinstance(item, dict):
        return None
    candidates: List[str] = []
    if include_provider:
        prov = item.get("provider")
        if isinstance(prov, str) and prov.strip():
            candidates.append(prov.strip())
    src = item.get("_source")
    if isinstance(src, str) and src.strip():
        candidates.append(src.strip())
    ctx = item.get("_context")
    if isinstance(ctx, dict):
        for key in ("runner_name", "name", "node_id"):
            val = ctx.get(key)
            if isinstance(val, str) and val.strip():
                candidates.append(val.strip())
    if not candidates:
        return None
    out = candidates[0]
    if len(out) > max_length:
        return out[:max_length]
    return out


def merge_subdomain_sources_from_item(sources: Optional[List[str]], item: Dict[str, Any]) -> List[str]:
    """
    Build an ordered unique list for Subdomain.sources from Secator ``sources`` and ``_source``.

    Preserves order: existing ``sources`` first, then ``_source`` if not already present.
    """
    seen: set[str] = set()
    result: List[str] = []
    for raw in sources or []:
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        result.append(s)
    extra = extract_secator_tool_source(item, include_provider=False, max_length=200)
    if extra and extra not in seen:
        result.append(extra)
    return result
