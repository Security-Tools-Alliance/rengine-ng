from django.db.models.signals import m2m_changed, pre_delete
from django.dispatch import receiver
from .models import Subdomain, IpAddress
from django.db import transaction
import logging

logger = logging.getLogger(__name__)

@receiver(pre_delete, sender=Subdomain)
def handle_subdomain_deletion(sender, instance, **kwargs):
    """Handle cleanup when a subdomain is deleted."""
    try:
        with transaction.atomic():
            # Store IPs before deletion
            ips_to_check = list(instance.ip_addresses.all())
            logger.warning(f"Found {len(ips_to_check)} IPs for subdomain {instance.name}")
            
            # Let the subdomain be deleted (this will remove the M2M relationships)
            # Then check each stored IP
            for ip in ips_to_check:
                # Check if this IP will still be used by other subdomains after deletion
                other_subdomains = Subdomain.objects.filter(ip_addresses=ip).exclude(id=instance.id)
                if not other_subdomains.exists():
                    logger.warning(f"Deleting orphaned IP {ip.address} after subdomain deletion")
                    ip.delete()
    except Exception as e:
        logger.error(f"Error during subdomain deletion cleanup: {str(e)}")

@receiver(m2m_changed, sender=Subdomain.ip_addresses.through)
def handle_subdomain_ip_changes(sender, instance, action, pk_set, **kwargs):
    """Handle cleanup when IPs are removed from a subdomain."""
    if action == "post_remove" and pk_set:
        try:
            with transaction.atomic():
                removed_ips = IpAddress.objects.filter(id__in=pk_set)
                for ip in removed_ips:
                    if not Subdomain.objects.filter(ip_addresses=ip).exists():
                        logger.warning(f"Deleting orphaned IP {ip.address} after M2M change")
                        ip.delete()
        except Exception as e:
            logger.error(f"Error during M2M IP cleanup: {str(e)}")
