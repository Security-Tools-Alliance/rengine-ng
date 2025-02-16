from django.db.models.signals import m2m_changed, pre_delete
from django.dispatch import receiver
from .models import Subdomain, IpAddress, Port
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

@receiver(pre_delete, sender=IpAddress)
def handle_ip_deletion(sender, instance, **kwargs):
    """Handle cleanup when an IP address is deleted."""
    try:
        with transaction.atomic():
            # Store ports before deletion
            ports_to_check = list(instance.ports.all())
            logger.warning(f"Found {len(ports_to_check)} ports for IP {instance.address}")
            
            # Let the IP be deleted (this will remove the M2M relationships)
            # Then check each stored port
            for port in ports_to_check:
                # Check if this port will still be used by other IPs after deletion
                other_ips = IpAddress.objects.filter(ports=port).exclude(id=instance.id)
                if not other_ips.exists():
                    logger.warning(f"Deleting orphaned port {port.number} after IP deletion")
                    port.delete()
    except Exception as e:
        logger.error(f"Error during IP deletion cleanup: {str(e)}")

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

@receiver(m2m_changed, sender=IpAddress.ports.through)
def handle_ip_port_changes(sender, instance, action, pk_set, **kwargs):
    """Handle cleanup when ports are removed from an IP."""
    if action == "post_remove" and pk_set:
        try:
            with transaction.atomic():
                # Bulk fetch all removed ports
                removed_port_ids = list(pk_set)

                # Find ports that are not referenced by any IP
                used_ports = set(
                    IpAddress.objects.filter(ports__in=removed_port_ids)
                    .values_list('ports', flat=True)
                    .distinct()
                )

                if orphaned_port_ids := list(
                    set(removed_port_ids) - used_ports
                ):
                    # Bulk delete orphaned ports
                    deleted_count, _ = Port.objects.filter(id__in=orphaned_port_ids).delete()
                    logger.warning(
                        f"Deleted {deleted_count} orphaned ports in bulk "
                        f"from IP {instance.address}"
                    )
        except Exception as e:
            logger.error(f"Error during M2M port cleanup: {str(e)}") 