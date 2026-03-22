"""
Endpoint Repository - Data access for endpoint operations.

Handles EndPoint database operations with enriched Secator integration.

Host invariants (see also ``reNgine.services.scan_finding_metrics`` for “IP in scan”):
- Each ``EndPoint`` has exactly one of ``subdomain`` or ``ip_address`` set (DB check constraint);
  use ``startScan.services.host_assignment.apply_endpoint_host`` when building rows outside this module.
- Name-based HTTP hosts resolve to a ``Subdomain`` for the scan when possible; URL hosts that are
  literal IPs resolve to ``IpAddress`` rows scoped to the scan (via ``IpRepository`` / lookups).
- Secator save paths (``save_from_secator``, ``add_gf_pattern_from_secator_tag``, ``get_or_create``,
  bulk create, ``create_endpoint_for_ip``) all resolve or assign a host before persisting; unresolved
  hosts skip new rows and log (see ``_resolve_endpoint_host_for_scan`` / ``EndpointHostResolution``).
"""

from collections import defaultdict
import contextlib
from dataclasses import dataclass
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.db.models import Count
from django.utils import timezone
import validators

from reNgine.core.exceptions import FindingOutOfScopeError
from reNgine.core.secator_target import parse_secator_target_value
from reNgine.core.validators import is_valid_ip, is_valid_url
from reNgine.secator.path_utils import strip_secator_reports_prefix
from reNgine.services.repositories.ip_repository import IpRepository, normalize_ip_address_string
from reNgine.services.repositories.subdomain_repository import SubdomainRepository
from reNgine.utilities.distributed_lock import DistributedLock
from reNgine.utilities.domain import get_domain_by_id, resolve_domain_for_scan
from reNgine.utilities.endpoint_ingest_logging import format_endpoint_host_unresolved_suffix
from reNgine.utilities.logger import format_exception_for_log, get_module_logger
from reNgine.utilities.url import is_acceptable_subdomain_name
from startScan.models import DirectoryFile, Domain, EndPoint, IpAddress, ScanHistory, Subdomain, Technology
from targetApp.models import Target
from targetApp.services.scope_params import get_finding_scope_filter_host_for_target


PREFIX_ENDPOINT_REPO = "[ENDPOINT_REPO]"
logger = get_module_logger(__name__)

_RESOLVE_HOST_OK = ""
_RESOLVE_MISSING_HOSTNAME = "missing_hostname"
_RESOLVE_MISSING_SCAN = "missing_scan"
_RESOLVE_MISSING_TARGET = "missing_target"
_RESOLVE_IP_NORMALIZE_FAILED = "ip_normalize_failed"
_RESOLVE_IP_ROW_MISSING = "ip_row_not_created"
_RESOLVE_UNACCEPTABLE_HOSTNAME = "unacceptable_hostname"
_RESOLVE_SUBDOMAIN_NOT_IN_SCAN = "subdomain_not_in_scan"
_RESOLVE_SUBDOMAIN_CREATE_FAILED = "subdomain_create_failed"
_RESOLVE_OUT_OF_SCOPE = "out_of_scope"
_RESOLVE_EXCEPTION = "resolver_exception"

_RESOLVE_REASONS_INGEST_ALERT = frozenset({_RESOLVE_EXCEPTION, _RESOLVE_IP_ROW_MISSING})


def _endpoint_host_unresolved_severity(reason: str) -> str:
    return "error" if reason in _RESOLVE_REASONS_INGEST_ALERT else "warning"


@dataclass(frozen=True)
class EndpointHostResolution:
    """URL host resolved to at most one of Subdomain or IpAddress; ``reason`` explains (None, None)."""

    subdomain: Optional[Subdomain]
    ip_address: Optional[IpAddress]
    reason: str

    def has_host(self) -> bool:
        return self.subdomain is not None or self.ip_address is not None


class EndpointRepository:
    """Repository for endpoint-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[EndPoint]:
        """
        Save endpoint from Secator result with enriched data.

        Args:
            item: Secator URL item
            scan_history_id: ID of the scan history
            target_id: ID of the target (reNgine-ng scan context)
            rengine_context: Optional context (e.g. subscan_id for SubScan linking)

        Returns:
            EndPoint: Saved endpoint object or None
        """
        try:
            return self._process_secator_endpoint_item(item, scan_history_id, target_id, rengine_context or {})
        except FindingOutOfScopeError as e:
            reason = format_exception_for_log(e)
            url = (item.get("url") or item.get("host") or "?").strip()
            if len(url) > 80:
                url = url[:80] + "..."
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Skipped (out of scope): url=%s | %s scan_id=%s" % (url, reason, scan_history_id),
                level="info",
            )
            raise
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Object not found when saving endpoint: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return None
        except IntegrityError as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Integrity error saving endpoint: %s" % (e,),
                level="error",
                exc_info=True,
            )
            return None

    def _process_secator_endpoint_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        target_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[EndPoint]:
        ctx = rengine_context or {}
        http_url = item.get("url")

        if not http_url:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Endpoint item missing URL field. Available fields: %s" % (list(item.keys()),),
                level="warning",
            )
            return None

        if not is_valid_url(http_url):
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Invalid URL: %s" % (http_url,),
                level="warning",
            )
            return None

        parsed = parse_secator_target_value(http_url)
        if parsed.is_valid and parsed.kind == "url" and parsed.url_normalized:
            http_url = parsed.url_normalized

        parsed_url = urlparse(http_url)
        hostname_raw = (parsed_url.hostname or "").strip() or (item.get("host") or "").strip() or ""
        normalized_hostname = hostname_raw.lower() if hostname_raw else ""
        if normalized_hostname and is_acceptable_subdomain_name(normalized_hostname):
            scope_filter = None
            filters = ctx.get("finding_scope_filters") or {}
            if isinstance(filters, dict):
                scope_filter = filters.get("host_filter")
            if scope_filter is None or not callable(scope_filter):
                scope_filter = get_finding_scope_filter_host_for_target(target_id)
            if scope_filter is not None and not scope_filter(normalized_hostname):
                raise FindingOutOfScopeError("Host out of scope (restrict_findings_to_target)")

        host = parsed_url.hostname or ""
        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = resolve_domain_for_scan(
            scan_history_id,
            host,
            target_value,
            create=True,
            log_failure={
                "logger": logger,
                "prefix": PREFIX_ENDPOINT_REPO,
                "extra": "target_id=%s, url=%s" % (target_id, http_url),
            },
        )
        if not domain:
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        defaults = self._build_secator_endpoint_defaults(item, domain)
        hostname_override = (item.get("host") or "").strip() or None

        host_res = self._resolve_endpoint_host_for_scan(
            http_url,
            scan_history_id,
            hostname_override,
            ctx,
            auto_create_subdomain=True,
        )
        if host_res.subdomain is not None:
            defaults["subdomain"] = host_res.subdomain
            defaults["ip_address"] = None
        elif host_res.ip_address is not None:
            defaults["ip_address"] = host_res.ip_address
            defaults["subdomain"] = None
        elif not EndPoint.objects.filter(http_url=http_url, scan_history=scan_history).exists():
            suffix = format_endpoint_host_unresolved_suffix(
                scan_history_id,
                http_url,
                hostname_override=hostname_override,
                reason=host_res.reason,
            )
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Skipped new endpoint (host unresolved; check ingestion if recurrent): " + suffix,
                level=_endpoint_host_unresolved_severity(host_res.reason or ""),
            )
            return None

        endpoint, created = EndPoint.objects.update_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults=defaults,
        )

        self._associate_with_subdomain(
            endpoint,
            http_url,
            scan_history_id,
            hostname_override=hostname_override,
            rengine_context=ctx,
        )
        self._mark_as_default_if_first(endpoint)
        self._associate_technologies(endpoint, item)

        if created:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Created endpoint: %s" % (http_url,),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "Endpoint already exists: %s" % (http_url,),
                level="debug",
            )

        subscan_id = ctx.get("subscan_id")
        if subscan_id:
            self._link_subscan_to_endpoint(endpoint, subscan_id)

        if item.get("is_directory") and subscan_id:
            self._link_directory_scan_for_secator(
                item=item,
                http_url=http_url,
                subscan_id=subscan_id,
                endpoint=endpoint,
            )

        return endpoint

    def add_gf_pattern_from_secator_tag(
        self,
        scan_history_id: int,
        target_id: int,
        http_url: str,
        pattern_name: str,
    ) -> Optional[EndPoint]:
        """
        Add a GF pattern name to an endpoint's matched_gf_patterns from Secator gf tag.

        Finds or creates the EndPoint for the given URL in this scan, then appends
        the pattern name to matched_gf_patterns (comma-separated, deduplicated, max 10000 chars).
        """
        http_url = (http_url or "").strip()
        pattern_name = (pattern_name or "").strip()
        if not http_url:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "add_gf_pattern: empty URL",
                level="warning",
            )
            return None
        if not pattern_name:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "add_gf_pattern: empty pattern name",
                level="warning",
            )
            return None
        if not is_valid_url(http_url):
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "add_gf_pattern: invalid URL: %s" % (http_url,),
                level="warning",
            )
            return None

        parsed = parse_secator_target_value(http_url)
        if parsed.is_valid and parsed.kind == "url" and parsed.url_normalized:
            http_url = parsed.url_normalized

        parsed_url = urlparse(http_url)
        hostname_raw = (parsed_url.hostname or "").strip() or ""
        normalized_hostname = hostname_raw.lower() if hostname_raw else ""
        if normalized_hostname and is_acceptable_subdomain_name(normalized_hostname):
            scope_filter = get_finding_scope_filter_host_for_target(target_id)
            if scope_filter is not None and not scope_filter(normalized_hostname):
                raise FindingOutOfScopeError("Host out of scope (restrict_findings_to_target)")

        host = parsed_url.hostname or ""
        target_value = Target.objects.filter(id=target_id).values_list("value", flat=True).first() or ""
        domain = resolve_domain_for_scan(
            scan_history_id,
            host,
            target_value,
            create=True,
            log_failure={
                "logger": logger,
                "prefix": PREFIX_ENDPOINT_REPO,
                "extra": "target_id=%s, url=%s" % (target_id, http_url),
            },
        )
        if not domain:
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        defaults = {
            "domain": domain,
            "discovered_date": timezone.now(),
        }
        host_res = self._resolve_endpoint_host_for_scan(
            http_url,
            scan_history_id,
            None,
            {},
            auto_create_subdomain=True,
        )
        if host_res.subdomain is not None:
            defaults["subdomain"] = host_res.subdomain
            defaults["ip_address"] = None
        elif host_res.ip_address is not None:
            defaults["ip_address"] = host_res.ip_address
            defaults["subdomain"] = None
        elif not EndPoint.objects.filter(http_url=http_url, scan_history=scan_history).exists():
            suffix = format_endpoint_host_unresolved_suffix(
                scan_history_id,
                http_url,
                reason=host_res.reason,
            )
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "SAVE",
                "add_gf_pattern: skipped new endpoint (host unresolved; check ingestion if recurrent): " + suffix,
                level=_endpoint_host_unresolved_severity(host_res.reason or ""),
            )
            return None

        endpoint, _ = EndPoint.objects.update_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults=defaults,
        )

        current = (endpoint.matched_gf_patterns or "").strip()
        parts = [p.strip() for p in current.split(",") if p.strip()]
        if pattern_name not in parts:
            parts.append(pattern_name)
        new_value = ",".join(parts)
        max_len = EndPoint._meta.get_field("matched_gf_patterns").max_length
        if len(new_value) > max_len:
            new_value = new_value[:max_len].rsplit(",", 1)[0] if "," in new_value[:max_len] else new_value[:max_len]
        endpoint.matched_gf_patterns = new_value
        endpoint.save()
        return endpoint

    @staticmethod
    def _extract_secator_source(item: Dict[str, Any], max_length: int = 200) -> Optional[str]:
        """Extract source from Secator finding (_source or _context.node_id). Returns truncated string or None."""
        source = item.get("_source")
        if not source and "_context" in item:
            ctx = item["_context"]
            if isinstance(ctx, dict):
                source = ctx.get("node_id")
        if not source or not isinstance(source, str):
            return None
        return source[:max_length] if len(source) > max_length else source

    @staticmethod
    def _parse_response_time(item: Dict[str, Any]) -> Optional[float]:
        """Parse response time from item (ms string or seconds number). Returns seconds or None."""
        raw = item.get("time")
        if raw is None:
            return None
        if isinstance(raw, str) and raw.endswith("ms"):
            try:
                return float(raw[:-2]) / 1000.0
            except ValueError:
                return None
        return float(raw) if isinstance(raw, (int, float)) else None

    def _build_secator_endpoint_defaults(self, item: Dict[str, Any], domain) -> Dict[str, Any]:
        """Build defaults dict for EndPoint from Secator item."""
        source = self._extract_secator_source(item)
        defaults = {
            "domain": domain,
            "source": source,
            "http_status": item.get("status_code") or item.get("status") or 0,
            "content_length": item.get("content_length", 0),
            "page_title": item.get("title", ""),
            "content_type": item.get("content_type", ""),
            "webserver": item.get("webserver", ""),
            "discovered_date": timezone.now(),
            "method": item.get("method", ""),
            "words": item.get("words", 0),
            "lines": item.get("lines", 0),
        }
        if (response_time := self._parse_response_time(item)) is not None:
            defaults["response_time"] = response_time

        headers_dict = {}
        if "response_headers" in item:
            headers_dict["response"] = item["response_headers"]
        if "request_headers" in item:
            headers_dict["request"] = item["request_headers"]
        if headers_dict:
            defaults["headers"] = headers_dict

        # Normalize paths for storage (prefix strip); file access and project check
        # are in api.scan_file (ServeScanFile, get_project_for_scan_file_path).
        if "screenshot_path" in item:
            val = item["screenshot_path"]
            max_len = EndPoint._meta.get_field("screenshot_path").max_length
            defaults["screenshot_path"] = strip_secator_reports_prefix(
                val if isinstance(val, str) else str(val), max_length=max_len
            )
        if "stored_response_path" in item:
            val = item["stored_response_path"]
            max_len = EndPoint._meta.get_field("stored_response_path").max_length
            defaults["stored_response_path"] = strip_secator_reports_prefix(
                val if isinstance(val, str) else str(val), max_length=max_len
            )
        if "is_directory" in item:
            defaults["is_directory"] = item["is_directory"]

        if "confidence" in item:
            from reNgine.core.validators import validate_confidence

            validated = validate_confidence(item["confidence"])
            if validated is not None:
                defaults["confidence"] = validated

        return defaults

    def _link_subscan_to_endpoint(self, endpoint: EndPoint, subscan_id: int) -> None:
        """Link SubScan to endpoint by id; no-op if SubScan does not exist."""
        from startScan.models import SubScan

        with contextlib.suppress(SubScan.DoesNotExist):
            subscan = SubScan.objects.get(id=subscan_id)
            endpoint.endpoint_subscan_ids.add(subscan)

    def _link_directory_scan_for_secator(
        self,
        item: Dict[str, Any],
        http_url: str,
        subscan_id: int,
        endpoint: EndPoint,
    ) -> None:
        """
        When a directory URL is saved from Secator, create/update DirectoryScan and
        DirectoryFile and link the SubScan via dir_subscan_ids so dir_file_fuzz results
        show correctly per subscan.
        """
        from startScan.models import DirectoryScan, SubScan

        try:
            with transaction.atomic():
                subscan = SubScan.objects.select_for_update().get(id=subscan_id)
                directory_scan = DirectoryScan.objects.filter(
                    dir_subscan_ids=subscan
                ).first() or DirectoryScan.objects.create(
                    command_line="Secator directory discovery",
                    scanned_date=timezone.now(),
                )
                directory_scan.dir_subscan_ids.add(subscan)
        except SubScan.DoesNotExist:
            return

        path = urlparse(http_url).path.rstrip("/") or "/"
        name = path.split("/")[-1] if path != "/" else "/"
        http_status = item.get("status_code") or item.get("status") or 0
        length = item.get("content_length", 0)
        words = item.get("words", 0)
        lines = item.get("lines", 0)
        content_type = item.get("content_type") or ""

        directory_file, _ = self._save_fuzzing_file(
            name=name,
            url=http_url,
            http_status=http_status,
            length=length,
            words=words,
            lines=lines,
            content_type=content_type,
        )
        if directory_file:
            directory_scan.directory_files.add(directory_file)

        if endpoint.subdomain_id:
            endpoint.subdomain.directories.add(directory_scan)

    def get_or_create(self, http_url, scan_history_id, domain_id, **kwargs):
        """
        Get or create an endpoint.

        Args:
            http_url: Endpoint URL
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            **kwargs: Additional fields

        Returns:
            tuple: (EndPoint, created boolean) or (None, False)
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            domain = get_domain_by_id(domain_id)
            if domain is None:
                return None, False

            defaults = {
                "domain": domain,
                "http_status": 0,
            } | kwargs
            has_host = bool(
                kwargs.get("subdomain")
                or kwargs.get("subdomain_id")
                or kwargs.get("ip_address")
                or kwargs.get("ip_address_id")
            )
            if not has_host and scan_history.target_id:
                host_res = self._resolve_endpoint_host_for_scan(
                    http_url,
                    scan_history_id,
                    None,
                    {},
                    auto_create_subdomain=True,
                )
                if host_res.subdomain is not None:
                    defaults["subdomain"] = host_res.subdomain
                    defaults["ip_address"] = None
                elif host_res.ip_address is not None:
                    defaults["ip_address"] = host_res.ip_address
                    defaults["subdomain"] = None
                elif not EndPoint.objects.filter(http_url=http_url, scan_history=scan_history).exists():
                    suffix = format_endpoint_host_unresolved_suffix(
                        scan_history_id,
                        http_url,
                        reason=host_res.reason,
                    )
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "GET_OR_CREATE",
                        "Skipped new endpoint (host unresolved; check ingestion if recurrent): " + suffix,
                        level=_endpoint_host_unresolved_severity(host_res.reason or ""),
                    )
                    return None, False

            endpoint, created = EndPoint.objects.get_or_create(
                http_url=http_url, scan_history=scan_history, defaults=defaults
            )

            return endpoint, created

        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "GET_OR_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return None, False
        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "GET_OR_CREATE",
                "Error in get_or_create endpoint: %s" % (e,),
                level="error",
            )
            return None, False

    def bulk_create(self, endpoints, scan_history_id, domain_id):
        """
        Bulk create endpoints.

        Args:
            endpoints: List of endpoint dictionaries
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created EndPoint objects
        """
        try:
            return self._create_endpoints_in_bulk(scan_history_id, domain_id, endpoints)
        except ObjectDoesNotExist as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "BULK_CREATE",
                "Object not found: %s" % (e,),
                level="error",
            )
            return []
        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "BULK_CREATE",
                "Error in bulk create endpoints: %s" % (e,),
                level="error",
            )
            return []

    def _create_endpoints_in_bulk(
        self, scan_history_id: int, domain_id: int, endpoints: List[Dict[str, Any]]
    ) -> List[EndPoint]:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = get_domain_by_id(domain_id)
        if domain is None:
            return []
        if not scan_history.target_id:
            return []

        endpoint_objects: List[EndPoint] = []
        empty_ctx: Dict[str, Any] = {}
        for endpoint_data in endpoints:
            http_url = endpoint_data.get("http_url")
            if not http_url or not is_valid_url(http_url):
                continue
            host_res = self._resolve_endpoint_host_for_scan(
                http_url,
                scan_history_id,
                None,
                empty_ctx,
                auto_create_subdomain=True,
            )
            if not host_res.has_host():
                if host_res.reason in _RESOLVE_REASONS_INGEST_ALERT:
                    bulk_suffix = format_endpoint_host_unresolved_suffix(
                        scan_history_id,
                        http_url,
                        reason=host_res.reason,
                    )
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "BULK_CREATE",
                        "Skipped row (host unresolved; possible ingest issue): " + bulk_suffix,
                        level="error",
                    )
                continue
            if host_res.subdomain is not None:
                endpoint_objects.append(
                    EndPoint(
                        http_url=http_url,
                        scan_history=scan_history,
                        domain=domain,
                        subdomain=host_res.subdomain,
                        ip_address=None,
                        http_status=endpoint_data.get("http_status", 0),
                        content_length=endpoint_data.get("content_length", 0),
                        page_title=endpoint_data.get("page_title", ""),
                    )
                )
            else:
                endpoint_objects.append(
                    EndPoint(
                        http_url=http_url,
                        scan_history=scan_history,
                        domain=domain,
                        subdomain=None,
                        ip_address=host_res.ip_address,
                        http_status=endpoint_data.get("http_status", 0),
                        content_length=endpoint_data.get("content_length", 0),
                        page_title=endpoint_data.get("page_title", ""),
                    )
                )

        if endpoint_objects:
            created = EndPoint.objects.bulk_create(endpoint_objects, ignore_conflicts=True)
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "BULK_CREATE",
                "Bulk created %s endpoints" % (len(created),),
                level="info",
            )
            return created

        return []

    def update_http_status(self, endpoint_id, http_status):
        """
        Update HTTP status for an endpoint.

        Args:
            endpoint_id: ID of the endpoint
            http_status: HTTP status code

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            endpoint = EndPoint.objects.get(id=endpoint_id)
            endpoint.http_status = http_status
            endpoint.save(update_fields=["http_status"])
            return True
        except ObjectDoesNotExist:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "UPDATE",
                "EndPoint with ID %s not found" % (endpoint_id,),
                level="error",
            )
            return False
        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "UPDATE",
                "Error updating endpoint HTTP status: %s" % (e,),
                level="error",
            )
            return False

    def _resolve_endpoint_host_for_scan(
        self,
        http_url: str,
        scan_history_id: int,
        hostname_override: Optional[str],
        rengine_context: Dict[str, Any],
        auto_create_subdomain: bool = True,
    ) -> EndpointHostResolution:
        """
        Resolve exactly one of Subdomain or IpAddress for the URL host (FQDN or literal IP).

        On failure, both ``subdomain`` and ``ip_address`` are None and ``reason`` is a stable code
        for logs and for callers that skip creating rows (DB requires exactly one host).
        """
        ctx = rengine_context or {}
        hostname_raw = ""
        try:
            parsed_url = urlparse(http_url)
            hostname_raw = (parsed_url.hostname or "").strip() or (hostname_override or "").strip()
            if not hostname_raw:
                return EndpointHostResolution(None, None, _RESOLVE_MISSING_HOSTNAME)
            hn_lower = hostname_raw.strip().lower()
            if hn_lower.startswith("[") and hn_lower.endswith("]"):
                hn_lower = hn_lower[1:-1]

            if is_valid_ip(hn_lower):
                try:
                    scan_history = ScanHistory.objects.get(id=scan_history_id)
                    target_id = scan_history.target_id
                except ObjectDoesNotExist:
                    return EndpointHostResolution(None, None, _RESOLVE_MISSING_SCAN)
                if not target_id:
                    return EndpointHostResolution(None, None, _RESOLVE_MISSING_TARGET)
                normalized_ip = normalize_ip_address_string(hn_lower)
                if not normalized_ip:
                    return EndpointHostResolution(None, None, _RESOLVE_IP_NORMALIZE_FAILED)
                ip_obj, _ = IpRepository().get_or_create_for_scan(
                    scan_history_id,
                    target_id,
                    normalized_ip,
                    rengine_context=ctx,
                )
                if not ip_obj:
                    return EndpointHostResolution(None, None, _RESOLVE_IP_ROW_MISSING)
                return EndpointHostResolution(None, ip_obj, _RESOLVE_HOST_OK)

            if not is_acceptable_subdomain_name(hostname_raw):
                return EndpointHostResolution(None, None, _RESOLVE_UNACCEPTABLE_HOSTNAME)

            if not auto_create_subdomain:
                subdomain = Subdomain.objects.filter(
                    name=hostname_raw.strip().lower(), scan_history_id=scan_history_id
                ).first()
                if not subdomain:
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "RESOLVE_HOST",
                        "Subdomain not found in scan (auto_create_subdomain=False), skipping: hostname=%s scan_id=%s"
                        % (hostname_raw, scan_history_id),
                        level="debug",
                    )
                    return EndpointHostResolution(None, None, _RESOLVE_SUBDOMAIN_NOT_IN_SCAN)
            else:
                try:
                    scan_history = ScanHistory.objects.get(id=scan_history_id)
                    target_id = scan_history.target_id
                except ObjectDoesNotExist:
                    return EndpointHostResolution(None, None, _RESOLVE_MISSING_SCAN)
                if not target_id:
                    return EndpointHostResolution(None, None, _RESOLVE_MISSING_TARGET)
                subdomain = SubdomainRepository().get_or_create_from_host(
                    scan_history_id, target_id, hostname_raw, rengine_context=ctx
                )
                if not subdomain:
                    return EndpointHostResolution(None, None, _RESOLVE_SUBDOMAIN_CREATE_FAILED)
                return EndpointHostResolution(subdomain, None, _RESOLVE_HOST_OK)

            return EndpointHostResolution(subdomain, None, _RESOLVE_HOST_OK)

        except FindingOutOfScopeError:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "RESOLVE_HOST",
                "Skipped (out of scope): hostname=%s | url=%s scan_id=%s"
                % (hostname_raw or "?", http_url[:80] if http_url else "", scan_history_id),
                level="info",
            )
            return EndpointHostResolution(None, None, _RESOLVE_OUT_OF_SCOPE)
        except Exception as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "RESOLVE_HOST",
                "Error resolving endpoint host: %s | url=%s scan_id=%s"
                % (reason, http_url[:80] if http_url else "", scan_history_id),
                level="error",
            )
            return EndpointHostResolution(None, None, _RESOLVE_EXCEPTION)

    def _associate_with_subdomain(
        self,
        endpoint: EndPoint,
        http_url: str,
        scan_history_id: int,
        auto_create_subdomain: bool = True,
        hostname_override: Optional[str] = None,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Associate endpoint with a DNS Subdomain or an IpAddress from URL hostname.

        Literal IPs use IpRepository; DNS names use SubdomainRepository.
        When URL parsing yields no hostname, hostname_override (e.g. item["host"]) is used.
        """
        if endpoint.subdomain_id or endpoint.ip_address_id:
            return
        ctx = rengine_context or {}
        host_res = self._resolve_endpoint_host_for_scan(
            http_url,
            scan_history_id,
            hostname_override,
            ctx,
            auto_create_subdomain=auto_create_subdomain,
        )
        if host_res.subdomain:
            endpoint.subdomain = host_res.subdomain
            endpoint.ip_address = None
            endpoint.save(update_fields=["subdomain", "ip_address"])
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "ASSOCIATE_ENDPOINT_TO_SUBDOMAIN",
                "Endpoint %s linked to subdomain %s" % (http_url[:80] if http_url else "", host_res.subdomain.name),
                level="debug",
            )
        elif host_res.ip_address:
            endpoint.ip_address = host_res.ip_address
            endpoint.subdomain = None
            endpoint.save(update_fields=["ip_address", "subdomain"])
            addr = host_res.ip_address.address or "?"
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "ASSOCIATE_ENDPOINT_TO_HOST",
                "Endpoint %s linked to IP %s" % (http_url[:80] if http_url else "", addr),
                level="debug",
            )
        elif not host_res.has_host() and host_res.reason not in (
            _RESOLVE_MISSING_HOSTNAME,
            _RESOLVE_OUT_OF_SCOPE,
        ):
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "ASSOCIATE_HOST",
                "Could not attach host to existing endpoint: url=%s scan_id=%s reason=%s"
                % (http_url[:120] if http_url else "", scan_history_id, host_res.reason),
                level="debug",
            )

    def _get_port_from_url(self, http_url: str) -> int:
        """Extract port from URL; returns 80 or 443 if scheme has no explicit port."""
        parsed = urlparse(http_url)
        if parsed.port is not None:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    def _mark_as_default_if_first(self, endpoint: EndPoint) -> None:
        """
        Mark endpoint as default only if it is the first endpoint for (host, port).
        Host is either subdomain (DNS) or ip_address. First-wins per port.
        """
        try:
            if not endpoint.subdomain_id and not endpoint.ip_address_id:
                logger.log_line(
                    PREFIX_ENDPOINT_REPO,
                    "DEFAULT",
                    "Endpoint %s has no host, skipping default marking" % (endpoint.http_url,),
                    level="debug",
                )
                return

            port = self._get_port_from_url(endpoint.http_url)
            host_label = (
                endpoint.subdomain.name
                if endpoint.subdomain_id
                else (endpoint.ip_address.address if endpoint.ip_address_id else "?")
            )

            def _has_other_default_for_port() -> bool:
                qs = EndPoint.objects.filter(is_default=True).exclude(id=endpoint.id).select_for_update()
                if endpoint.subdomain_id:
                    qs = qs.filter(subdomain_id=endpoint.subdomain_id, ip_address__isnull=True)
                else:
                    qs = qs.filter(ip_address_id=endpoint.ip_address_id, subdomain__isnull=True)
                other_urls = list(qs.values_list("http_url", flat=True))
                return any(self._get_port_from_url(url) == port for url in other_urls)

            with transaction.atomic():
                if _has_other_default_for_port():
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "DEFAULT",
                        "A default endpoint already exists for host %s on port %s, skipping default for %s"
                        % (host_label, port, endpoint.http_url),
                        level="debug",
                    )
                    return

                endpoint.refresh_from_db()
                if _has_other_default_for_port():
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "DEFAULT",
                        "Default already set for (host, port) by concurrent transaction, skipping %s"
                        % (endpoint.http_url,),
                        level="debug",
                    )
                    return
                endpoint.is_default = True
                endpoint.save(update_fields=["is_default"])
                logger.log_line(
                    PREFIX_ENDPOINT_REPO,
                    "DEFAULT",
                    "Marked endpoint %s as default for host %s (port %s)" % (endpoint.http_url, host_label, port),
                    level="info",
                )
        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "DEFAULT",
                "Error marking endpoint as default: %s" % (e,),
                level="error",
                exc_info=True,
            )

    def create_endpoint_for_ip(self, ip_address: str, scan_history_id: int, domain_id: int) -> Optional[EndPoint]:
        """
        Create an endpoint with the IP as URL so the IP can be used as a Secator target (e.g. for subscans).

        Called whenever an IP is discovered so that IP-based targets appear in the endpoint list.

        Args:
            ip_address: IP address string (IPv4 or IPv6)
            scan_history_id: Scan history ID
            domain_id: Domain ID

        Returns:
            EndPoint or None if invalid or error
        """
        try:
            return self._get_or_create_endpoint_for_ip(ip_address, scan_history_id, domain_id)
        except FindingOutOfScopeError:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "CREATE_IP",
                "Skipped (out of scope): IP %s" % (ip_address,),
                level="info",
            )
            return None
        except (ObjectDoesNotExist, IntegrityError) as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "CREATE_IP",
                "create_endpoint_for_ip: %s" % (e,),
                level="debug",
            )
            return None
        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "CREATE_IP",
                "Error creating endpoint for IP %s: %s" % (ip_address, e),
                level="error",
                exc_info=True,
            )
            return None

    def _get_or_create_endpoint_for_ip(self, ip_address, scan_history_id, domain_id):
        if not validators.ipv4(ip_address) and not validators.ipv6(ip_address):
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "CREATE_IP",
                "create_endpoint_for_ip: invalid IP %s, skipping" % (ip_address,),
                level="debug",
            )
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = get_domain_by_id(domain_id)
        if domain is None:
            return None

        http_url = f"http://[{ip_address}]" if validators.ipv6(ip_address) else f"http://{ip_address}"

        ip_obj = None
        if target_id := getattr(scan_history, "target_id", None):
            if normalized := normalize_ip_address_string(ip_address):
                ip_obj, _ = IpRepository().get_or_create_for_scan(scan_history_id, target_id, normalized)

        endpoint = EndPoint.objects.filter(http_url=http_url, scan_history=scan_history).order_by("id").first()
        created = False
        if endpoint is None:
            if not ip_obj:
                return None
            endpoint = EndPoint.objects.create(
                http_url=http_url,
                scan_history=scan_history,
                domain=domain,
                subdomain=None,
                ip_address=ip_obj,
                http_status=0,
                discovered_date=timezone.now(),
            )
            created = True
        elif ip_obj and (endpoint.ip_address_id != ip_obj.id or endpoint.subdomain_id):
            endpoint.ip_address = ip_obj
            endpoint.subdomain = None
            endpoint.save(update_fields=["ip_address", "subdomain"])
        if created:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "CREATE_IP",
                "Created endpoint for IP %s" % (ip_address,),
                level="info",
            )
        return endpoint

    def _associate_technologies(self, endpoint: EndPoint, item: Dict[str, Any]) -> None:
        """
        Associate technologies with endpoint.

        Args:
            endpoint: Endpoint object
            item: Secator item
        """
        try:
            # Check if there are technologies in the 'tech' field
            technologies = item.get("tech", [])

            if not technologies or not isinstance(technologies, list):
                return

            for tech_name in technologies:
                if tech_name and isinstance(tech_name, str):
                    tech_obj, _ = Technology.objects.get_or_create(name=tech_name.strip())
                    endpoint.techs.add(tech_obj)
                    logger.log_line(
                        PREFIX_ENDPOINT_REPO,
                        "ASSOCIATE_TECH_TO_ENDPOINT",
                        "Technology %s linked to endpoint %s"
                        % (tech_name, endpoint.http_url[:80] if endpoint and endpoint.http_url else ""),
                        level="debug",
                    )

        except Exception as e:
            reason = format_exception_for_log(e)
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "ASSOCIATE_TECH_TO_ENDPOINT",
                "Error linking technology to endpoint: %s | endpoint=%s"
                % (reason, endpoint.http_url[:80] if endpoint and endpoint.http_url else ""),
                level="error",
            )

    def extract_technologies_from_list(self, tech_list: List[str]) -> List[Technology]:
        """
        Extract and create technologies from a list of technology names.

        Args:
            tech_list: List of technology names

        Returns:
            list: List of Technology objects
        """
        try:
            technologies = []
            for tech_name in tech_list:
                if tech_name and tech_name.strip():
                    tech_obj, _ = Technology.objects.get_or_create(name=tech_name.strip())
                    technologies.append(tech_obj)

            return technologies

        except Exception as e:
            logger.log_line(
                PREFIX_ENDPOINT_REPO,
                "TECH",
                "Error extracting technologies from list: %s" % (e,),
                level="error",
            )
            return []

    def _save_fuzzing_file(
        self,
        name: str,
        url: str,
        http_status: int,
        length: int = 0,
        words: int = 0,
        lines: int = 0,
        content_type: str = "",
    ) -> Tuple[Optional[DirectoryFile], bool]:
        """
        Save or retrieve DirectoryFile with Redis-based distributed locking.

        Args:
            name: File/directory name
            url: Full URL
            http_status: HTTP status code
            length: Content length
            words: Word count
            lines: Line count
            content_type: Content type header

        Returns:
            tuple: (DirectoryFile or None, created boolean)
        """
        lock_key = f"fuzzing_file_lock:{hashlib.md5(f'{name}:{url}:{http_status}'.encode()).hexdigest()}"
        base_data: Dict[str, Any] = {"name": name, "url": url, "http_status": http_status}
        full_data: Dict[str, Any] = {
            **base_data,
            "length": length,
            "lines": lines,
            "words": words,
            "content_type": content_type or "",
        }
        if directory_file := DistributedLock.safe_get_or_create_with_lock(
            model_class=DirectoryFile,
            lock_key=lock_key,
            get_kwargs=base_data,
            create_kwargs=full_data,
            update_existing_callback=lambda obj: self._update_directory_file_fields(obj, full_data),
        ):
            was_created = getattr(directory_file, "_was_created", False)
            return directory_file, was_created
        return None, False

    @staticmethod
    def _update_directory_file_fields(directory_file: DirectoryFile, full_data: Dict[str, Any]) -> DirectoryFile:
        """Update DirectoryFile fields when record already exists."""
        fields_to_update: List[str] = []
        if directory_file.length != full_data["length"]:
            directory_file.length = full_data["length"]
            fields_to_update.append("length")
        if directory_file.lines != full_data["lines"]:
            directory_file.lines = full_data["lines"]
            fields_to_update.append("lines")
        if directory_file.words != full_data["words"]:
            directory_file.words = full_data["words"]
            fields_to_update.append("words")
        if directory_file.content_type != full_data["content_type"]:
            directory_file.content_type = full_data["content_type"]
            fields_to_update.append("content_type")
        if fields_to_update:
            directory_file.save(update_fields=fields_to_update)
        return directory_file

    def get_http_status_breakdown(self, scope: Union[ScanHistory, Domain]) -> List[Dict[str, int]]:
        """
        Return HTTP status breakdown for charts (detail_scan or target summary).

        Legacy: counts from Subdomain.http_status.
        Secator: counts from EndPoint.http_status where is_default=True.
        Returns list of dicts {"http_status": int, "http_status__count": int}.
        """
        if isinstance(scope, ScanHistory):
            if scope.is_legacy_scan:
                qs = (
                    Subdomain.objects.filter(scan_history=scope)
                    .exclude(http_status=0)
                    .values("http_status")
                    .annotate(Count("http_status"))
                )
            else:
                qs = (
                    EndPoint.objects.filter(scan_history=scope, is_default=True)
                    .exclude(http_status=0)
                    .exclude(http_status__isnull=True)
                    .values("http_status")
                    .annotate(Count("http_status"))
                )
            return [
                {
                    "http_status": int(r["http_status"]),
                    "http_status__count": int(r["http_status__count"]),
                }
                for r in qs
            ]
        if isinstance(scope, Domain):
            return self._get_http_status_breakdown_for_domain(scope)
        return []

    def _get_http_status_breakdown_for_domain(self, scope: Domain) -> List[Dict[str, int]]:
        """
        HTTP status breakdown for domain: web server endpoints (per port) without double-counting.
        Legacy subdomains that have at least one default EndPoint (Secator) are excluded from
        Subdomain counts; only default EndPoints and legacy-only subdomains contribute.
        """
        target_id = scope.scan_history_id and getattr(scope.scan_history, "target_id", None)
        if not target_id:
            return []
        subdomain_names_with_default = set(
            EndPoint.objects.filter(scan_history__target_id=target_id, is_default=True)
            .exclude(subdomain_id__isnull=True)
            .values_list("subdomain__name", flat=True)
            .distinct()
        )
        sub_qs = (
            Subdomain.objects.filter(domain_id=scope.id)
            .exclude(name__in=subdomain_names_with_default)
            .exclude(http_status=0)
            .values("http_status")
            .annotate(Count("http_status"))
        )
        ep_qs = (
            EndPoint.objects.filter(scan_history__target_id=target_id, is_default=True)
            .exclude(http_status=0)
            .exclude(http_status__isnull=True)
            .values("http_status")
            .annotate(Count("http_status"))
        )
        merged: Dict[int, int] = defaultdict(int)
        for row in sub_qs:
            merged[row["http_status"]] += row["http_status__count"]
        for row in ep_qs:
            merged[row["http_status"]] += row["http_status__count"]
        return [{"http_status": int(k), "http_status__count": int(v)} for k, v in sorted(merged.items())]
