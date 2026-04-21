from django.db import transaction
from django.db.models.signals import m2m_changed, post_save, pre_delete
from django.dispatch import receiver

from reNgine.utilities.logger import get_module_logger

from .cron_utils import ensure_run_scheduled_scans_cron
from .models import IpAddress, ScanSchedule, Subdomain


PREFIX_SIGNALS = "[SIGNALS]"
logger = get_module_logger(__name__)


@receiver(pre_delete, sender=Subdomain)
def handle_subdomain_deletion(sender, instance, **kwargs):
    """Cleanup orphaned IPs after subdomain deletion."""
    try:
        ips_to_check = list(instance.ip_addresses.all())
        logger.log_line(
            PREFIX_SIGNALS,
            "SUBDOMAIN_DELETE",
            "Handling deletion of subdomain %s (ID: %s). Checking its associated IPs" % (instance.name, instance.id),
            level="info",
        )
        if ips_to_check:
            logger.log_line(
                PREFIX_SIGNALS,
                "SUBDOMAIN_DELETE",
                "Found %s IPs associated with subdomain %s" % (len(ips_to_check), instance.name),
                level="info",
            )
        else:
            logger.log_line(
                PREFIX_SIGNALS,
                "SUBDOMAIN_DELETE",
                "No IPs associated with subdomain %s" % (instance.name,),
                level="info",
            )
            return

        def post_deletion_cleanup():
            """Callback executed after transaction validation."""
            for ip in ips_to_check:
                # Final check after complete deletion
                if not Subdomain.objects.filter(ip_addresses=ip).exists():
                    logger.log_line(
                        PREFIX_SIGNALS,
                        "SUBDOMAIN_DELETE",
                        "Deleting orphaned IP %s as it is orphaned after deletion of subdomain %s (ID: %s)"
                        % (ip.address, instance.name, instance.id),
                        level="warning",
                    )
                    ip.delete()
                else:
                    logger.log_line(
                        PREFIX_SIGNALS,
                        "SUBDOMAIN_DELETE",
                        "IP %s still in use" % (ip.address,),
                        level="info",
                    )

        # Defer the check after the transaction
        transaction.on_commit(post_deletion_cleanup)

    except Exception as e:
        logger.log_line(
            PREFIX_SIGNALS,
            "SUBDOMAIN_DELETE",
            "Error during post-deletion cleanup: %s" % (e,),
            level="error",
            exc_info=True,
        )


@receiver(m2m_changed, sender=Subdomain.ip_addresses.through)
def handle_subdomain_ip_changes(sender, instance, action, pk_set, **kwargs):
    """Handle cleanup when IPs are removed from a subdomain."""
    if action == "post_remove" and pk_set:
        try:
            with transaction.atomic():
                removed_ips = IpAddress.objects.filter(id__in=pk_set)
                for ip in removed_ips:
                    if not Subdomain.objects.filter(ip_addresses=ip).exists():
                        # Validation and cleanup of the IP address
                        cleaned_ip = (
                            ip.address.strip()[:45].replace("\r\n", "").replace("\n", "")
                        )  # Limit the length and sanitize
                        sanitized_subdomain = instance.name[:255].replace("\r\n", "").replace("\n", "")
                        logger.log_line(
                            PREFIX_SIGNALS,
                            "M2M_IP_CLEANUP",
                            "Deleting orphaned IP %s (subdomain: %s)" % (cleaned_ip, sanitized_subdomain),
                            level="warning",
                        )
                        ip.delete()
        except Exception as e:
            logger.log_line(
                PREFIX_SIGNALS,
                "M2M_IP_CLEANUP",
                "Error during M2M IP cleanup: %s" % (e,),
                level="error",
                exc_info=True,
            )


@receiver(post_save, sender=ScanSchedule)
def ensure_cron_on_schedule_created(sender, instance, created, **kwargs):
    """When a scheduled scan is created and enabled, ensure the cron job is present (see startScan.cron_utils)."""
    if created and instance.enabled:
        transaction.on_commit(lambda: ensure_run_scheduled_scans_cron())
