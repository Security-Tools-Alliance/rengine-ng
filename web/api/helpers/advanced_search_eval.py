"""
AST evaluation helpers for advanced search (Q-tree construction, legacy detection).

Keeps view mixins focused on wiring search_config into queryset operations.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from django.db.models import Q

from api.helpers.advanced_search import parse_advanced_search_term


def boolean_field_value_from_token(content: str, true_val: str, false_val: str) -> Optional[bool]:
    """Parse boolean literal; return None if the token is not a recognized true/false."""
    c = (content or "").lower().strip()
    tv = (true_val or "").lower().strip()
    fv = (false_val or "").lower().strip()
    if c in ("true", "1", "yes", tv):
        return True
    if c in ("false", "0", "no", fv):
        return False
    return None


def ast_branch_children(node: tuple[Any, ...]) -> Optional[list[Any]]:
    if not isinstance(node, tuple) or len(node) != 2 or node[0] not in ("and", "or"):
        return None
    ch = node[1]
    if not isinstance(ch, (list, tuple)):
        return None
    return list(ch)


def ast_requires_legacy_eval(node: Any, atom_requires_legacy: Callable[[str], bool]) -> bool:
    """True if any atom must use legacy per-branch queryset evaluation (e.g. port!)."""
    if not isinstance(node, tuple) or len(node) != 2:
        return False
    kind = node[0]
    if kind == "atom":
        if not isinstance(node[1], str):
            return False
        return atom_requires_legacy(node[1])
    children = ast_branch_children(node)
    if children is None:
        return False
    return any(ast_requires_legacy_eval(ch, atom_requires_legacy) for ch in children)


def ast_to_q(node: Any, atom_to_q: Callable[[str], Q]) -> Q:
    """Fold AST into a single Q using atom_to_q for leaf terms."""
    if not isinstance(node, tuple) or len(node) != 2:
        return Q()
    kind = node[0]
    if kind == "atom":
        if not isinstance(node[1], str):
            return Q()
        term = node[1].strip()
        if not term:
            return Q()
        return atom_to_q(term)
    children = ast_branch_children(node)
    if children is None:
        return Q()
    if kind == "and":
        parts = [ast_to_q(ch, atom_to_q) for ch in children]
        non_empty = [p for p in parts if p]
        if not non_empty:
            return Q()
        out = non_empty[0]
        for p in non_empty[1:]:
            out &= p
        return out
    if kind == "or":
        parts = [ast_to_q(ch, atom_to_q) for ch in children]
        non_empty = [p for p in parts if p]
        if not non_empty:
            return Q()
        out = non_empty[0]
        for p in non_empty[1:]:
            out |= p
        return out
    return Q()


def atom_requires_port_bang_legacy(term_raw: str, custom_handlers: Optional[dict[str, Any]]) -> bool:
    """Whether this atom must use legacy eval (subdomain port! exclude)."""
    term = (term_raw or "").strip()
    parsed, term_err = parse_advanced_search_term(term)
    if not parsed or term_err:
        return False
    lookup_title, operator, _ = parsed
    if lookup_title != "port" or operator != "!":
        return False
    return "port" in (custom_handlers or {})
