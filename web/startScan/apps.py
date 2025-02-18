from django.apps import AppConfig
from reNgine.definitions import logger


class StartscanConfig(AppConfig):
    name = 'startScan'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        '''
        Any Scans that were incomplete in the last scan, we will mark them failed after
        server restarted
        This does not include pending_scans, pending_scans are taken care by celery
        '''
        # Import signals when Django is ready.
        import startScan.signals

        # Additional initialization can be added here
        logger.info('StartScan app initialized - Signals registered')
        pass
        # logger.info('Cancelling all the ongoing scans')
        # ScanHistory = self.get_model('ScanHistory')
        # ScanHistory.objects.filter(scan_status=1).update(scan_status=0)

