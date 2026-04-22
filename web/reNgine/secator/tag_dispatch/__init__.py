"""
Secator tag dispatch: route _type=tag findings to repositories (WHOIS, ASN, patterns, secrets, Nuclei DNS records, Nuclei tech).

Public API mirrors the former ``reNgine.secator.tag_routing`` module.
Wiki: ref-secator-tag-routing.
"""

from .dispatch import (
    TAG_IGNORED,
    dispatch_secator_tag,
    get_tag_handler,
    is_registered_ignored_tag_pair,
    is_tag_ignored,
    register_ignored_tag,
    register_tag_handler,
)


__all__ = [
    "TAG_IGNORED",
    "dispatch_secator_tag",
    "get_tag_handler",
    "is_registered_ignored_tag_pair",
    "is_tag_ignored",
    "register_ignored_tag",
    "register_tag_handler",
]
