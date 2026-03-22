"""
Advanced search: tokenization, boolean AST (AND before OR), validation, field catalogs.

AND binds tighter than OR: A|B&C is A|(B&C). Use parentheses to override.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Union


AstNode = Union[tuple[str, list[Any]], tuple[str, str]]

KEYWORD_AND = "AND"
KEYWORD_OR = "OR"


def _is_ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _try_keyword(s: str, i: int, kw: str) -> bool:
    n = len(kw)
    if i + n > len(s) or s[i : i + n].upper() != kw.upper():
        return False
    before = s[i - 1] if i > 0 else " "
    after = s[i + n] if i + n < len(s) else " "
    if _is_ident_char(before):
        return False
    if _is_ident_char(after):
        return False
    return True


def tokenize_advanced_search(raw: str) -> tuple[Optional[list[Any]], Optional[str]]:
    """
    Tokenize into ATOM tuples ('ATOM', text), 'LP', 'RP', 'AND', 'OR'.
    Joiners (&, |, AND, OR) are recognized only outside double-quoted segments so
    literal text like name="foo AND bar" stays a single atom. Inside quotes, \\\" and \\\\ apply.
    """
    s = (raw or "").strip()
    if not s:
        return [], None

    tokens: list[Any] = []
    depth = 0
    buf: list[str] = []
    i = 0
    n = len(s)
    in_dquote = False

    def flush_atom() -> None:
        text = "".join(buf).strip()
        buf.clear()
        if text:
            tokens.append(("ATOM", text))

    while i < n:
        c = s[i]
        if in_dquote:
            if c == "\\" and i + 1 < n:
                buf.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_dquote = False
                buf.append(c)
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_dquote = True
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n and s[i + 1] in ("\\", "&", "|", "(", ")"):
            buf.append(s[i + 1])
            i += 2
            continue
        if c.isspace():
            buf.append(c)
            i += 1
            continue
        if c == "(":
            flush_atom()
            tokens.append("LP")
            depth += 1
            i += 1
            continue
        if c == ")":
            flush_atom()
            depth -= 1
            if depth < 0:
                return None, "unmatched_parenthesis"
            tokens.append("RP")
            i += 1
            continue
        if c == "&":
            flush_atom()
            tokens.append("AND")
            i += 1
            continue
        if c == "|":
            flush_atom()
            tokens.append("OR")
            i += 1
            continue
        if _try_keyword(s, i, KEYWORD_AND):
            flush_atom()
            tokens.append("AND")
            i += len(KEYWORD_AND)
            continue
        if _try_keyword(s, i, KEYWORD_OR):
            flush_atom()
            tokens.append("OR")
            i += len(KEYWORD_OR)
            continue
        buf.append(c)
        i += 1

    flush_atom()
    if in_dquote:
        return None, "unclosed_quote"
    if depth != 0:
        return None, "unclosed_parenthesis"
    return tokens, None


def _parse_primary(tokens: list[Any], pos: int) -> tuple[Optional[AstNode], int, Optional[str]]:
    if pos >= len(tokens):
        return None, pos, "unexpected_end"
    t = tokens[pos]
    if t == "LP":
        node, pos2, err = _parse_or(tokens, pos + 1)
        if err:
            return None, pos2, err
        if pos2 >= len(tokens) or tokens[pos2] != "RP":
            return None, pos2, "expected_rparen"
        return node, pos2 + 1, None
    if isinstance(t, tuple) and t[0] == "ATOM":
        return ("atom", t[1]), pos + 1, None
    return None, pos, "expected_atom_or_lparen"


def _parse_and(tokens: list[Any], pos: int) -> tuple[Optional[AstNode], int, Optional[str]]:
    left, pos, err = _parse_primary(tokens, pos)
    if err:
        return None, pos, err
    children: list[AstNode] = [left]
    while pos < len(tokens) and tokens[pos] == "AND":
        pos += 1
        right, pos, err = _parse_primary(tokens, pos)
        if err:
            return None, pos, err
        children.append(right)
    if len(children) == 1:
        return children[0], pos, None
    return ("and", children), pos, None


def _parse_or(tokens: list[Any], pos: int) -> tuple[Optional[AstNode], int, Optional[str]]:
    left, pos, err = _parse_and(tokens, pos)
    if err:
        return None, pos, err
    children: list[AstNode] = [left]
    while pos < len(tokens) and tokens[pos] == "OR":
        pos += 1
        right, pos, err = _parse_and(tokens, pos)
        if err:
            return None, pos, err
        children.append(right)
    if len(children) == 1:
        return children[0], pos, None
    return ("or", children), pos, None


def parse_advanced_search_ast(raw: str) -> tuple[Optional[AstNode], Optional[str]]:
    tokens, err = tokenize_advanced_search(raw)
    if err:
        return None, err
    if not tokens:
        return None, "empty"
    node, pos, err = _parse_or(tokens, 0)
    if err:
        return None, err
    if pos < len(tokens):
        return None, "trailing_tokens"
    return node, None


_FIELD_TOKEN_RE = re.compile(r"^[\w.-]+$")


class _MalformedQuotedValue:
    """Sentinel for syntactically invalid double-quoted value literals."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover
        return "<MALFORMED_QUOTED_VALUE>"


MALFORMED_QUOTED_VALUE = _MalformedQuotedValue()


def _parse_advanced_search_value_literal(
    tail: str,
) -> Union[None, str, _MalformedQuotedValue]:
    """Unquoted value (trimmed) or double-quoted string with \\\" and \\\\ escapes."""
    s = (tail or "").strip()
    if not s:
        return None
    if s[0] != '"':
        return s
    i = 1
    parts: list[str] = []
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            if i + 1 >= len(s):
                return MALFORMED_QUOTED_VALUE
            parts.append(s[i + 1])
            i += 2
            continue
        if ch == '"':
            out = "".join(parts)
            return out if out else None
        parts.append(ch)
        i += 1
    return MALFORMED_QUOTED_VALUE


def parse_advanced_search_term(term: str) -> tuple[Optional[tuple[str, str, str]], Optional[str]]:
    """
    Parse field op value. != maps to operator '!'.

    Returns:
        (triple, None) on success;
        (None, None) if not a structured term;
        (None, 'invalid_quoted_value') if a quoted literal is syntactically invalid.
    """
    value = (term or "").strip()
    if not value:
        return None, None
    search_from = 0
    while True:
        j = value.find("!=", search_from)
        if j <= 0:
            break
        left = value[:j].strip().lower()
        if _FIELD_TOKEN_RE.match(left):
            lit = _parse_advanced_search_value_literal(value[j + 2 :])
            if lit is MALFORMED_QUOTED_VALUE:
                return None, "invalid_quoted_value"
            if lit is not None:
                return (left, "!", lit), None
        search_from = j + 2
    best: Optional[tuple[int, str, str, str]] = None
    for op_sym in ("=", ">", "<", "!"):
        start = 0
        while True:
            k = value.find(op_sym, start)
            if k <= 0:
                break
            left = value[:k].strip().lower()
            if _FIELD_TOKEN_RE.match(left):
                lit = _parse_advanced_search_value_literal(value[k + 1 :])
                if lit is MALFORMED_QUOTED_VALUE:
                    return None, "invalid_quoted_value"
                if lit is not None:
                    if best is None or k < best[0]:
                        best = (k, left, op_sym, lit)
            start = k + 1
    if best:
        return (best[1], best[2], best[3]), None
    return None, None


def term_has_structured_op(term: str) -> bool:
    parsed, _err = parse_advanced_search_term(term)
    return parsed is not None


ADVANCED_SEARCH_PARSE_ERROR_DESCRIPTIONS: dict[str, str] = {
    "unmatched_parenthesis": "Unmatched parenthesis in the expression.",
    "unclosed_quote": "A double-quoted value is missing the closing quote.",
    "unclosed_parenthesis": "Opening parenthesis was not closed before the end of the expression.",
    "expected_rparen": "Missing closing parenthesis before the next token or end of expression.",
    "unexpected_end": "Expression ends inside a group or is incomplete.",
    "expected_atom_or_lparen": "Expected a field condition or '(' after an operator.",
    "trailing_tokens": "Extra tokens after a complete expression (check operators and parentheses).",
    "empty": "Expression is empty after trimming.",
    "invalid_quoted_value": "A double-quoted value is malformed (unclosed string or stray backslash at end).",
}


def validate_advanced_search_expression(expression: str) -> dict[str, Any]:
    """Validate syntax; does not check field names against a catalog."""
    raw = (expression or "").strip()
    if not raw:
        return {"valid": True, "error": None, "parse_error": None, "error_detail": None, "warnings": []}
    ast, err = parse_advanced_search_ast(raw)
    if err:
        detail = ADVANCED_SEARCH_PARSE_ERROR_DESCRIPTIONS.get(err, err.replace("_", " "))
        return {
            "valid": False,
            "error": err,
            "parse_error": err,
            "error_detail": detail,
            "warnings": [],
        }
    warnings: list[str] = []
    malformed_literal = False

    def walk(node: AstNode) -> None:
        nonlocal malformed_literal
        if node[0] == "atom":
            t = node[1].strip()
            _parsed, term_err = parse_advanced_search_term(t)
            if term_err == "invalid_quoted_value":
                malformed_literal = True
                return
            if not t:
                warnings.append("empty_atom")
            elif not term_has_structured_op(t) and any(x in t for x in ("&", "|")):
                warnings.append("ambiguous_atom")
        else:
            for ch in node[1]:
                walk(ch)

    if ast:
        walk(ast)
    if malformed_literal:
        code = "invalid_quoted_value"
        detail = ADVANCED_SEARCH_PARSE_ERROR_DESCRIPTIONS[code]
        return {
            "valid": False,
            "error": code,
            "parse_error": code,
            "error_detail": detail,
            "warnings": [],
        }
    return {"valid": True, "error": None, "parse_error": None, "error_detail": None, "warnings": warnings}


# Single source: (field_name, ui_kind, aggregate_kind, db_path). Field names must be lowercase
# to match tokenized atoms, search_config keys, and frontend profiles (advanced_search_profiles.js).
_ADVANCED_SEARCH_FIELD_DEFS: dict[str, list[tuple[str, str, str, Optional[str]]]] = {
    "subdomains": [
        ("name", "text", "scalar", "name"),
        ("page_title", "text", "scalar", "page_title"),
        ("http_status", "numeric", "scalar", "http_status"),
        ("is_important", "boolean", "bool", "is_important"),
        ("technology", "text", "m2m", "technologies__name"),
        ("port", "text", "scalar", "ip_addresses__ports__number"),
        ("webserver", "text", "scalar", "webserver"),
        ("ip_address", "text", "m2m", "ip_addresses__address"),
        ("content_length", "numeric", "scalar", "content_length"),
    ],
    "endpoints": [
        ("http_url", "text", "scalar", "http_url"),
        ("http_status", "numeric", "scalar", "http_status"),
        ("page_title", "text", "scalar", "page_title"),
        ("gf_pattern", "text", "scalar", "matched_gf_patterns"),
        ("content_type", "text", "scalar", "content_type"),
        ("content_length", "numeric", "scalar", "content_length"),
        ("technology", "text", "m2m", "techs__name"),
        ("webserver", "text", "scalar", "webserver"),
    ],
    "vulnerabilities": [
        ("name", "text", "scalar", "name"),
        ("tag", "text", "m2m", "tags__name"),
        ("severity", "text", "severity", None),
        ("cvss_score", "numeric", "scalar", "cvss_score"),
        ("http_url", "text", "scalar", "http_url"),
        ("status", "text", "status", None),
        ("description", "text", "scalar", "description"),
    ],
    "ips": [
        ("address", "text", "scalar", "address"),
        ("subdomain", "text", "m2m", "ip_addresses__name"),
        ("port", "numeric", "scalar", "ports__number"),
        ("alive", "boolean", "bool", "alive"),
        ("is_cdn", "boolean", "bool", "is_cdn"),
        ("is_private", "boolean", "bool", "is_private"),
        ("is_important", "boolean", "bool", "is_important"),
        ("reverse_pointer", "text", "scalar", "reverse_pointer"),
        ("protocol", "text", "scalar", "protocol"),
        # IpAddress.version is IntegerField (IP stack version, e.g. 4 or 6), not a free-form string.
        ("version", "numeric", "scalar", "version"),
    ],
}

ADVANCED_SEARCH_FIELD_CATALOG: dict[str, list[dict[str, str]]] = {
    ctx: [{"name": name, "kind": ui_kind} for name, ui_kind, _, _ in rows]
    for ctx, rows in _ADVANCED_SEARCH_FIELD_DEFS.items()
}

ADVANCED_SEARCH_FIELD_VALUE_SPECS: dict[str, dict[str, tuple[str, Optional[str]]]] = {
    ctx: {name: (agg, db) for name, _, agg, db in rows} for ctx, rows in _ADVANCED_SEARCH_FIELD_DEFS.items()
}

ALLOWED_CONTEXTS = frozenset(_ADVANCED_SEARCH_FIELD_DEFS.keys())


def validate_expression_for_context(expression: str, context: str) -> dict[str, Any]:
    base = validate_advanced_search_expression(expression)
    if not base["valid"]:
        return base
    if context not in ALLOWED_CONTEXTS:
        return {
            **base,
            "valid": False,
            "error": "unknown_context",
            "parse_error": "unknown_context",
            "error_detail": "Invalid context; use subdomains, endpoints, vulnerabilities, or ips.",
        }
    allowed = {f["name"] for f in ADVANCED_SEARCH_FIELD_CATALOG[context]}
    warnings = list(base.get("warnings") or [])

    def check_atom(term: str) -> None:
        parsed, term_err = parse_advanced_search_term(term.strip())
        if term_err == "invalid_quoted_value":
            return
        if parsed and parsed[0] not in allowed:
            warnings.append("unknown_field:%s" % (parsed[0],))

    def walk(node: AstNode) -> None:
        if node[0] == "atom":
            check_atom(node[1])
        else:
            for ch in node[1]:
                walk(ch)

    ast, _ = parse_advanced_search_ast((expression or "").strip())
    if ast:
        walk(ast)
    elif (expression or "").strip():
        parsed, term_err = parse_advanced_search_term(expression.strip())
        if term_err == "invalid_quoted_value":
            code = "invalid_quoted_value"
            return {
                **base,
                "valid": False,
                "error": code,
                "parse_error": code,
                "error_detail": ADVANCED_SEARCH_PARSE_ERROR_DESCRIPTIONS[code],
                "warnings": [],
            }
        if parsed and parsed[0] not in allowed:
            warnings.append("unknown_field:%s" % (parsed[0],))
    return {**base, "warnings": warnings}
