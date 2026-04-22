"""
HTML sanitization for safe display (e.g. markdown-rendered content, user-facing HTML).

Used by: reNgine.llm.utils.convert_markdown_to_html (and thus model formatted_* fields),
PDF report template, and any API returning pre-rendered HTML. Frontend (DOMPurify in custom.js)
should align with ALLOWED_HTML_TAGS / ALLOWED_ATTRIBUTES when rendering the same content.

To extend safely:
- Add only tag names that cannot execute script.
- Add only attributes that cannot carry script (no onclick, style with expression, etc.).
- Document any addition in this module.
"""

from urllib.parse import urlparse

from bs4 import BeautifulSoup


ALLOWED_HTML_TAGS = frozenset(
    {
        "p",
        "div",
        "span",
        "br",
        "ul",
        "ol",
        "li",
        "strong",
        "em",
        "b",
        "i",
        "code",
        "pre",
        "a",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "dl",
        "dt",
        "dd",
    }
)

ALLOWED_ATTRIBUTES = {
    "a": frozenset({"href", "title", "id", "class", "aria-label", "aria-expanded", "role"}),
    "div": frozenset({"id", "class", "role", "aria-label", "aria-hidden"}),
    "span": frozenset({"id", "class", "role", "aria-label", "aria-hidden"}),
    "pre": frozenset({"id", "class", "aria-label"}),
    "code": frozenset({"id", "class", "aria-label"}),
    "ul": frozenset({"id", "class", "aria-label"}),
    "ol": frozenset({"id", "class", "aria-label"}),
    "li": frozenset({"id", "class", "aria-label"}),
    "h1": frozenset({"id", "class", "aria-label"}),
    "h2": frozenset({"id", "class", "aria-label"}),
    "h3": frozenset({"id", "class", "aria-label"}),
    "h4": frozenset({"id", "class", "aria-label"}),
    "h5": frozenset({"id", "class", "aria-label"}),
    "h6": frozenset({"id", "class", "aria-label"}),
}

HIGH_RISK_TAGS = frozenset({"script", "style", "iframe", "object", "embed"})


def get_dompurify_config_for_frontend() -> dict:
    """
    Return DOMPurify config (ALLOWED_TAGS, ALLOWED_ATTR) as a JSON-serializable dict
    for injection into the frontend (e.g. window.VULN_DOMPURIFY_CONFIG).
    Single source of truth: frontend uses this instead of duplicating the allowlist.
    """
    all_attrs = set()
    for attrs in ALLOWED_ATTRIBUTES.values():
        all_attrs.update(attrs)
    return {
        "ALLOWED_TAGS": sorted(ALLOWED_HTML_TAGS),
        "ALLOWED_ATTR": sorted(all_attrs),
    }


def _is_safe_href(href: str) -> bool:
    """Return True if href is http/https or path-only (leading /). Rejects protocol-relative and dangerous schemes."""
    try:
        parsed = urlparse(href)
        if parsed.scheme not in ("http", "https", ""):
            return False
        if parsed.scheme == "" and parsed.netloc:
            return False
        return bool(parsed.scheme != "" or (parsed.path or "").startswith("/"))
    except Exception:
        return False


def _process_anchor_tag(tag) -> bool:
    """Apply href validation, rel and target rules to an <a> tag. Returns False if tag was removed (decompose/unwrap)."""
    href = tag.get("href")
    if not href:
        tag.unwrap()
        return False
    if not _is_safe_href(href):
        tag.decompose()
        return False
    existing_rel = tag.get("rel", "")
    rel_tokens = {v for v in str(existing_rel).split() if v}
    rel_tokens.update({"noopener", "noreferrer"})
    tag["rel"] = " ".join(sorted(rel_tokens))
    target = tag.get("target")
    if target is not None:
        if str(target).strip().lower() != "_blank":
            del tag["target"]
        else:
            tag["target"] = "_blank"
    return True


def sanitize_html_for_display(html_content: str) -> str:
    """
    Sanitize HTML so it is safe to render with |safe (e.g. in templates or API responses).

    - Disallowed tags: high-risk (script, style, iframe, object, embed) are decompose()d;
      others are unwrapped (content kept).
    - Keeps only ALLOWED_ATTRIBUTES per tag; strips style, onclick, data-*, etc.
    - For <a>: allows only http/https or path-only href; enforces rel="noopener noreferrer";
      target is kept only when "_blank", otherwise stripped.

    Always returns a string; for falsy or whitespace-only input, returns "".
    """
    if not html_content or not html_content.strip():
        return ""
    soup = BeautifulSoup(html_content, "html.parser")
    for tag in list(soup.find_all(True)):
        tag_name = getattr(tag, "name", None)
        if not isinstance(tag_name, str):
            continue
        name_lower = tag_name.lower()
        if name_lower not in ALLOWED_HTML_TAGS:
            if name_lower in HIGH_RISK_TAGS:
                tag.decompose()
            else:
                tag.unwrap()
            continue
        allowed_attrs = ALLOWED_ATTRIBUTES.get(name_lower, frozenset())
        for attr in list(tag.attrs):
            if attr.lower() not in allowed_attrs:
                del tag[attr]
        if name_lower == "a" and not _process_anchor_tag(tag):
            continue
    return str(soup)
