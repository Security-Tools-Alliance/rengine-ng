"""
Secret Repository - Data access for secret findings from Secator (gitleaks, trufflehog, trivy).
"""

from typing import Any, Dict, Optional

from reNgine.utilities.logger import get_module_logger
from startScan.models import ScanHistory, Secret


logger = get_module_logger(__name__)

SECRET_SOURCE_NAMES = frozenset({"gitleaks", "trufflehog", "trivy"})


def _infer_source(data: Dict[str, Any]) -> Optional[str]:
    """Infer tool source from tag data (_context or extra_data)."""
    context = data.get("_context") or {}
    if isinstance(context, dict):
        task = (context.get("task") or context.get("task_name") or "").strip().lower()
        if task in SECRET_SOURCE_NAMES:
            return task
        if task:
            for known in SECRET_SOURCE_NAMES:
                if known in task:
                    return known
    extra = data.get("extra_data") or {}
    if isinstance(extra, dict):
        src = (extra.get("source") or extra.get("tool") or "").strip().lower()
        if src in SECRET_SOURCE_NAMES:
            return src
    return None


class SecretRepository:
    """Repository for secret findings from Secator tag output."""

    def save_from_secator_tag(
        self,
        data: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
    ) -> Optional[Secret]:
        """
        Create a Secret from a Secator tag (category=secret).

        Args:
            data: Tag payload with name, match, value, extra_data (and optionally _context).
            scan_history_id: ScanHistory id.
            target_id: Target id (unused in V1, for future link to target).

        Returns:
            Secret instance or None on validation failure.
        """
        rule_name = (data.get("name") or "").strip()
        matched_at = (data.get("match") or "").strip()
        value = data.get("value")
        if value is None:
            value = ""
        else:
            value = str(value)
        # Store raw value; do not strip so leading/trailing chars are preserved for forensics.

        if not rule_name:
            logger.log_line(
                "[SECRET_REPO]",
                "SAVE",
                "Secret tag: empty rule name",
                level="warning",
            )
            return None

        try:
            ScanHistory.objects.get(pk=scan_history_id)
        except ScanHistory.DoesNotExist:
            logger.log_line(
                "[SECRET_REPO]",
                "SAVE",
                "Secret tag: ScanHistory id=%s not found" % (scan_history_id,),
                level="warning",
            )
            return None

        extra_data = data.get("extra_data")
        if extra_data is not None and not isinstance(extra_data, dict):
            extra_data = None
        source = _infer_source(data)

        secret = Secret(
            scan_history_id=scan_history_id,
            rule_name=rule_name[:500],
            matched_at=matched_at[:2000],
            source=source,
            value=value,
            extra_data=extra_data,
        )
        secret.save()
        return secret
