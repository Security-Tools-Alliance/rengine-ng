from django.utils import timezone

from reNgine.services.target_ip_unlink import unlink_ip_addresses_from_target
from startScan.models import EndPoint, IpAddress
from utils.test_base import BaseTestCase


class TargetIpUnlinkServiceTestCase(BaseTestCase):
    def test_unlink_removes_subdomain_m2m_and_deletes_ip_only_endpoint(self) -> None:
        dg = self.data_generator
        dg.subdomain.ip_addresses.add(dg.ip_address)
        orphan = IpAddress.objects.create(address="203.0.113.121", alive=True)
        EndPoint.objects.create(
            domain=dg.domain,
            subdomain=None,
            scan_history=dg.scan_history,
            http_url="http://203.0.113.121/",
            discovered_date=timezone.now(),
            ip_address=orphan,
        )
        tid = dg.scan_history.target_id
        unlink_ip_addresses_from_target(tid, [dg.ip_address.id, orphan.id])
        dg.subdomain.refresh_from_db()
        self.assertFalse(dg.subdomain.ip_addresses.filter(pk=dg.ip_address.id).exists())
        self.assertFalse(
            EndPoint.objects.filter(scan_history=dg.scan_history, http_url="http://203.0.113.121/").exists()
        )
