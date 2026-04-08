"""
Nuclei Secator Tag (_source=nuclei): classify info-level output before Technology fallback.

- DNS protocol templates (``extra_data.type == "dns"`` or ``dns`` in template tags for Nuclei) map to
  Secator Record-shaped payloads for DnsRepository (not Technology).
- Technology fingerprints use Nuclei template ``info.tags`` allowlist; other Nuclei info findings are ignored.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Set, Tuple

from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)

NUCLEI_SOURCE = "nuclei"

# Lowercase Nuclei template tags that indicate product/stack fingerprinting (not misconfig-only info).
NUCLEI_TECH_TAG_ALLOWLIST: FrozenSet[str] = frozenset(
    {
        "tech",
        "panel",
        "wappalyzer",
        "cms",
        "framework",
        "server",
        "middleware",
        "cdn",
    }
)

# Template IDs blocked from technology storage even if tag intersection matches.
NUCLEI_TECH_TEMPLATE_BLOCKLIST: FrozenSet[str] = frozenset()

# (substring of template_id, DNS RR type). Longer / more specific patterns first.
NUCLEI_DNS_TEMPLATE_TO_RR_TYPE: Tuple[Tuple[str, str], ...] = (
    ("nameserver-fingerprint", "NS"),
    ("nameserver", "NS"),
    ("spf-record-detect", "TXT"),
    ("spf-record", "TXT"),
    ("dmarc-detect", "TXT"),
    ("dmarc", "TXT"),
    ("txt-fingerprint", "TXT"),
    ("txt-record", "TXT"),
    ("mx-service-detector", "MX"),
    ("mx-fingerprint", "MX"),
    ("mx-record", "MX"),
    ("caa-fingerprint", "CAA"),
    ("srv-fingerprint", "SRV"),
    ("ptr-fingerprint", "PTR"),
    ("soa-fingerprint", "SOA"),
)

# Nuclei template tags (lowercase) -> DNS RR type when template_id mapping is ambiguous.
NUCLEI_DNS_TAG_TO_RR_TYPE: Tuple[Tuple[str, str], ...] = (
    ("caa", "CAA"),
    ("mx", "MX"),
    ("ns", "NS"),
    ("srv", "SRV"),
    ("ptr", "PTR"),
    ("spf", "TXT"),
    ("dmarc", "TXT"),
    ("txt", "TXT"),
    ("soa", "SOA"),
)


def is_nuclei_tag(finding_data: Dict[str, Any]) -> bool:
    src = (finding_data.get("_source") or "").strip().lower()
    return src == NUCLEI_SOURCE


def _normalized_template_tags(finding_data: Dict[str, Any]) -> Set[str]:
    extra = finding_data.get("extra_data")
    if not isinstance(extra, dict):
        return set()
    raw = extra.get("tags")
    if not isinstance(raw, (list, tuple)):
        return set()
    out: Set[str] = set()
    for t in raw:
        if t is None:
            continue
        s = str(t).strip().lower()
        if s:
            out.add(s)
    return out


def nuclei_template_id(finding_data: Dict[str, Any]) -> str:
    extra = finding_data.get("extra_data")
    if isinstance(extra, dict):
        tid = extra.get("template_id")
        if isinstance(tid, str) and tid.strip():
            return tid.strip()
    name = (finding_data.get("name") or "").strip()
    return name


def is_nuclei_technology_tag(finding_data: Dict[str, Any]) -> bool:
    if not is_nuclei_tag(finding_data):
        return False
    if should_route_nuclei_tag_to_dns_record(finding_data):
        return False
    tid = nuclei_template_id(finding_data)
    if tid in NUCLEI_TECH_TEMPLATE_BLOCKLIST:
        return False
    tags = _normalized_template_tags(finding_data)
    return bool(tags & NUCLEI_TECH_TAG_ALLOWLIST)


def should_route_nuclei_tag_to_dns_record(finding_data: Dict[str, Any]) -> bool:
    """
    True when this tag payload represents a Nuclei DNS template and should use DnsRepository (Record shape).

    Matches ``extra_data.type == "dns"`` (Nuclei JSON) or Nuclei-sourced tags that include ``dns``.
    """
    extra = finding_data.get("extra_data")
    if not isinstance(extra, dict):
        return False
    if (extra.get("type") or "").strip().lower() == "dns":
        return True
    if not is_nuclei_tag(finding_data):
        return False
    tags = _normalized_template_tags(finding_data)
    return "dns" in tags


def infer_nuclei_dns_record_type(finding_data: Dict[str, Any]) -> str:
    """
    Return a VALID_DNS_TYPES label (uppercase) for a Nuclei DNS template.

    Resolution order (first match wins; do not reorder without updating callers/tests):
    1) ``template_id`` / finding ``name`` substring map (``NUCLEI_DNS_TEMPLATE_TO_RR_TYPE``,
       longest-specific substrings should remain earlier in that tuple).
    2) Normalized ``extra_data.tags`` keys (``NUCLEI_DNS_TAG_TO_RR_TYPE``).
    3) Default ``TXT``.
    """
    tid = nuclei_template_id(finding_data).lower()
    for needle, rrtype in NUCLEI_DNS_TEMPLATE_TO_RR_TYPE:
        if needle in tid:
            return rrtype
    tags = _normalized_template_tags(finding_data)
    for tag_key, rrtype in NUCLEI_DNS_TAG_TO_RR_TYPE:
        if tag_key in tags:
            return rrtype
    return "TXT"


def _nuclei_dns_rdata(finding_data: Dict[str, Any]) -> str:
    parts: List[str] = []
    value = finding_data.get("value")
    if isinstance(value, str) and value.strip():
        for line in value.splitlines():
            s = line.strip()
            if s and s not in parts:
                parts.append(s)
    extra = finding_data.get("extra_data")
    if isinstance(extra, dict):
        for entry in extra.get("data") or []:
            if isinstance(entry, str):
                s = entry.strip()
                if s and s not in parts:
                    parts.append(s)
    return "\n".join(parts)


def build_nuclei_dns_record_item(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a Secator Record-shaped dict for DnsRepository from a Nuclei Tag payload.
    """
    record_name = (finding_data.get("match") or "").strip()
    host = _nuclei_dns_rdata(finding_data)
    template_id = nuclei_template_id(finding_data)
    if not host and template_id:
        host = "[%s]" % template_id
    extra_in = finding_data.get("extra_data")
    extra_payload: Dict[str, Any] = dict(extra_in) if isinstance(extra_in, dict) else {}
    extra_payload["nuclei_template_id"] = template_id
    tags = sorted(_normalized_template_tags(finding_data))
    if tags:
        extra_payload["nuclei_tags"] = tags
    return {
        "_type": "record",
        "name": record_name,
        "type": infer_nuclei_dns_record_type(finding_data),
        "host": host,
        "_source": (finding_data.get("_source") or "nuclei").strip() or "nuclei",
        "extra_data": extra_payload,
    }


def extract_nuclei_technology_name(finding_data: Dict[str, Any]) -> str:
    value = finding_data.get("value")
    if isinstance(value, str):
        for line in value.splitlines():
            s = line.strip()
            if s:
                return s
    extra = finding_data.get("extra_data")
    if isinstance(extra, dict):
        data = extra.get("data")
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, str) and entry.strip():
                    return entry.strip()
    return ""


def build_nuclei_technology_item(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a tag-shaped dict for TechnologyRepository with a human-readable name, not Nuclei template-id.
    """
    item = dict(finding_data)
    tech_name = extract_nuclei_technology_name(finding_data)
    template_id = nuclei_template_id(finding_data)
    if not tech_name:
        if template_id:
            logger.log_line(
                "[TAG_NUCLEI]",
                "TECH_NAME",
                "No extracted technology name; using template_id=%s" % (template_id,),
                level="warning",
            )
        tech_name = template_id
    item["name"] = tech_name
    return item
