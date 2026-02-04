"""
Endpoint Repository - Data access for endpoint operations.
Handles EndPoint database operations with enriched Secator integration.
"""

from collections import defaultdict
import contextlib
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from reNgine.utilities.logger import get_module_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.db.models import Count
from django.utils import timezone
import validators

from reNgine.core.validators import is_valid_domain, is_valid_url
from reNgine.secator.path_utils import strip_secator_reports_prefix
from reNgine.utilities.distributed_lock import DistributedLock
from startScan.models import DirectoryFile, EndPoint, ScanHistory, Subdomain, Technology
from targetApp.models import Domain


logger = get_module_logger(__name__)


class EndpointRepository:
    """Repository for endpoint-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[EndPoint]:
        """
        Save endpoint from Secator result with enriched data.

        Args:
            item: Secator URL item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (e.g. subscan_id for SubScan linking)

        Returns:
            EndPoint: Saved endpoint object or None
        """
        try:
            return self._process_secator_endpoint_item(item, scan_history_id, domain_id, rengine_context or {})
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving endpoint: {e}", exc_info=True)
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving endpoint: {e}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Error saving endpoint from Secator: {e}", exc_info=True)
            logger.error(f"Endpoint item data: {item}")
            return None

    def _process_secator_endpoint_item(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[EndPoint]:
        ctx = rengine_context or {}
        http_url = item.get("url")

        if not http_url:
            logger.warning(f"Endpoint item missing URL field. Available fields: {list(item.keys())}")
            return None

        if not is_valid_url(http_url):
            logger.warning(f"Invalid URL: {http_url}")
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)
        defaults = self._build_secator_endpoint_defaults(item, domain)

        endpoint, created = EndPoint.objects.update_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults=defaults,
        )

        self._associate_with_subdomain(endpoint, http_url, scan_history_id)
        self._mark_as_default_if_first(endpoint)
        self._associate_technologies(endpoint, item)

        if created:
            logger.info(f"Created endpoint: {http_url}")
        else:
            logger.debug(f"Endpoint already exists: {http_url}")

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
            "target_domain": domain,
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
            domain = Domain.objects.get(id=domain_id)

            defaults = {
                "target_domain": domain,
                "http_status": 0,
            } | kwargs
            endpoint, created = EndPoint.objects.get_or_create(
                http_url=http_url, scan_history=scan_history, defaults=defaults
            )

            return endpoint, created

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return None, False
        except Exception as e:
            logger.error(f"Error in get_or_create endpoint: {e}")
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
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create endpoints: {e}")
            return []

    def _create_endpoints_in_bulk(
        self, scan_history_id: int, domain_id: int, endpoints: List[Dict[str, Any]]
    ) -> List[EndPoint]:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        endpoint_objects = []
        for endpoint_data in endpoints:
            http_url = endpoint_data.get("http_url")
            if http_url and is_valid_url(http_url):
                endpoint_objects.append(
                    EndPoint(
                        http_url=http_url,
                        scan_history=scan_history,
                        target_domain=domain,
                        http_status=endpoint_data.get("http_status", 0),
                        content_length=endpoint_data.get("content_length", 0),
                        page_title=endpoint_data.get("page_title", ""),
                    )
                )

        if endpoint_objects:
            created = EndPoint.objects.bulk_create(endpoint_objects, ignore_conflicts=True)
            logger.info(f"Bulk created {len(created)} endpoints")
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
            logger.error(f"EndPoint with ID {endpoint_id} not found")
            return False
        except Exception as e:
            logger.error(f"Error updating endpoint HTTP status: {e}")
            return False

    def _associate_with_subdomain(
        self, endpoint: EndPoint, http_url: str, scan_history_id: int, auto_create_subdomain: bool = True
    ) -> None:
        """
        Associate endpoint with subdomain based on URL hostname.

        Args:
            endpoint: Endpoint object
            http_url: Endpoint URL
            scan_history_id: Scan history ID
            auto_create_subdomain: If True, create subdomain if it doesn't exist. If False, only associate if subdomain exists.
        """
        try:
            if endpoint.subdomain_id:
                return

            parsed_url = urlparse(http_url)
            hostname = parsed_url.hostname
            if not hostname or not is_valid_domain(hostname):
                return

            try:
                with transaction.atomic():
                    scan_history = ScanHistory.objects.select_for_update().get(id=scan_history_id)
                    target_domain_id = endpoint.target_domain_id or scan_history.domain_id
                    subdomain = Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first()
                    if not subdomain:
                        if not auto_create_subdomain:
                            logger.debug(
                                "Subdomain %s not found in scan %s and auto_create_subdomain=False, "
                                "skipping association",
                                hostname,
                                scan_history_id,
                            )
                            return

                        scheme = parsed_url.scheme
                        subdomain_http_url = None
                        if scheme in ("http", "https"):
                            subdomain_http_url = f"{scheme}://{hostname}"

                        subdomain = Subdomain.objects.create(
                            name=hostname,
                            scan_history_id=scan_history_id,
                            target_domain_id=target_domain_id,
                            discovered_date=timezone.now(),
                            http_url=subdomain_http_url,
                        )
                        logger.info(f"Created subdomain {hostname} for scan {scan_history_id}")
            except ObjectDoesNotExist:
                return

            endpoint.subdomain = subdomain
            endpoint.save(update_fields=["subdomain"])
            logger.debug(f"Associated endpoint {http_url} with subdomain {hostname}")

        except Exception as e:
            logger.error(f"Error associating endpoint with subdomain: {e}")

    def _get_port_from_url(self, http_url: str) -> int:
        """Extract port from URL; returns 80 or 443 if scheme has no explicit port."""
        parsed = urlparse(http_url)
        if parsed.port is not None:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    def _mark_as_default_if_first(self, endpoint: EndPoint) -> None:
        """
        Mark endpoint as default only if it is the first endpoint for (subdomain, port).
        One default endpoint per (subdomain, port). First-wins policy: only the first
        endpoint added for a given port gets default; later ones do not override.
        Uses database locking to prevent race conditions in concurrent scenarios.

        Args:
            endpoint: Endpoint object
        """
        try:
            if not endpoint.subdomain:
                logger.debug(f"Endpoint {endpoint.http_url} has no subdomain, skipping default marking")
                return

            port = self._get_port_from_url(endpoint.http_url)

            def _has_other_default_for_port() -> bool:
                other_urls = list(
                    EndPoint.objects.filter(subdomain=endpoint.subdomain, is_default=True)
                    .exclude(id=endpoint.id)
                    .select_for_update()
                    .values_list("http_url", flat=True)
                )
                return any(self._get_port_from_url(url) == port for url in other_urls)

            with transaction.atomic():
                if _has_other_default_for_port():
                    logger.debug(
                        f"A default endpoint already exists for subdomain {endpoint.subdomain.name} on port {port}, "
                        f"skipping default for {endpoint.http_url}"
                    )
                    return

                endpoint.refresh_from_db()
                # Re-check immediately before setting to avoid race with concurrent creations
                if _has_other_default_for_port():
                    logger.debug(
                        f"Default already set for (subdomain, port) by concurrent transaction, skipping {endpoint.http_url}"
                    )
                    return
                endpoint.is_default = True
                endpoint.save(update_fields=["is_default"])
                logger.info(
                    f"Marked endpoint {endpoint.http_url} as default for subdomain {endpoint.subdomain.name} (port {port})"
                )
        except Exception as e:
            logger.error(f"Error marking endpoint as default: {e}", exc_info=True)

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
        except (ObjectDoesNotExist, IntegrityError) as e:
            logger.debug(f"create_endpoint_for_ip: {e}")
            return None
        except Exception as e:
            logger.error(f"Error creating endpoint for IP {ip_address}: {e}", exc_info=True)
            return None

    def _get_or_create_endpoint_for_ip(self, ip_address, scan_history_id, domain_id):
        if not validators.ipv4(ip_address) and not validators.ipv6(ip_address):
            logger.debug(f"create_endpoint_for_ip: invalid IP {ip_address}, skipping")
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)
        http_url = f"http://[{ip_address}]" if validators.ipv6(ip_address) else f"http://{ip_address}"

        endpoint, created = EndPoint.objects.get_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults={
                "target_domain": domain,
                "subdomain": None,
                "http_status": 0,
                "discovered_date": timezone.now(),
            },
        )
        if created:
            logger.info(f"Created endpoint for IP {ip_address}")
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
                    logger.debug(f"Associated technology {tech_name} with endpoint {endpoint.http_url}")

        except Exception as e:
            logger.error(f"Error associating technologies with endpoint: {e}")

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
            logger.error(f"Error extracting technologies from list: {e}")
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
        subdomain_names_with_default = set(
            EndPoint.objects.filter(scan_history__domain_id=scope.id, is_default=True)
            .exclude(subdomain_id__isnull=True)
            .values_list("subdomain__name", flat=True)
            .distinct()
        )
        sub_qs = (
            Subdomain.objects.filter(target_domain_id=scope.id)
            .exclude(name__in=subdomain_names_with_default)
            .exclude(http_status=0)
            .values("http_status")
            .annotate(Count("http_status"))
        )
        ep_qs = (
            EndPoint.objects.filter(scan_history__domain_id=scope.id, is_default=True)
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
