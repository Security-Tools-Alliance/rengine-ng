import os
import requests

from celery import group
from discord_webhook import DiscordWebhook

from reNgine.definitions import (
    NUCLEI_SEVERITY_MAP,
    STATUS_TO_SEVERITIES,
)
from reNgine.celery import app
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import (
    get_scan_url,
    get_task_title,
)
from reNgine.utils.notifications import (
    build_notification_message,
    enrich_notification,
    get_scan_with_related,
    send_discord_message,
    send_lark_message,
    send_slack_message,
    send_telegram_message,
)
from scanEngine.models import (
    EngineType,
    Hackerone,
    Notification,
)
from startScan.models import (
    ScanHistory,
    SubScan,
    Vulnerability,
)
from django.core.cache import cache

logger = Logger(True)

@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
        message,
        scan_history_id=None,
        subscan_id=None,
        **options):
    """Send notification to all configured channels.
    
    Args:
        message (str): Message to send
        scan_history_id (int, optional): ScanHistory id
        subscan_id (int, optional): SubScan id
        **options: Additional options for notification
    """
    if 'title' not in options:
        message = enrich_notification(message, scan_history_id, subscan_id)
    tasks = []
    if options.get('discord_enabled'):
        tasks.append(send_discord_message.si(message, **options))
    if options.get('slack_enabled'):
        tasks.append(send_slack_message.si(message))
    if options.get('lark_enabled'):
        tasks.append(send_lark_message.si(message))
    if options.get('telegram_enabled'):
        tasks.append(send_telegram_message.si(message))
    
    return group(tasks).apply_async()

@app.task(
    name='send_scan_notif',
    bind=True,
    queue='send_notif_queue',
    retry_backoff=True,
    max_retries=3
)
def send_scan_notif(
        self,
        scan_history_id,
        subscan_id=None,
        engine_id=None,
        status='RUNNING'):
    try:
        notif = get_notification_settings()
        if not (notif and notif.send_scan_status_notif):
            return

        # Get all related objects in one optimized query
        scan, subscan, engine, tasks = get_scan_with_related(
            scan_history_id, 
            subscan_id, 
            engine_id
        )
        if not scan:
            logger.error(f"📢 Scan {scan_history_id} not found")
            return

        # Build message with already fetched objects
        msg_data = build_notification_message(
            scan=scan,
            subscan=subscan,
            engine=engine,
            status=status,
            tasks=tasks
        )

        # Send async
        return send_notif.delay(
            msg_data['message'],
            scan_history_id,
            subscan_id,
            **msg_data['options']
        )

    except Exception as e:
        logger.exception(f"📢 Error sending notification: {str(e)}")
        raise self.retry(exc=e) from e

@app.task(name='send_task_notif', bind=False, queue='send_notif_queue')
def send_task_notif(task_name, status=None, result=None, output_path=None, traceback=None, scan_history_id=None, engine_id=None, subscan_id=None, severity=None, add_meta_info=True, update_fields=None):
    """Send task status notification.

    Args:
        task_name (str): Task name.
        status (str, optional): Task status.
        result (str, optional): Task result.
        output_path (str, optional): Task output path.
        traceback (str, optional): Task traceback.
        scan_history_id (int, optional): ScanHistory id.
        subscan_id (int, optional): SubScan id.
        engine_id (int, optional): EngineType id.
        severity (str, optional): Severity (will be mapped to notif colors)
        add_meta_info (bool, optional): Whether to add scan / subscan info to notif.
        update_fields (dict, optional): Fields key / value to update.
    """
    if update_fields is None:
        update_fields = {}
    # Skip send if notification settings are not configured
    notif = Notification.objects.first()
    if not (notif and notif.send_scan_status_notif):
        return

    # Build fields
    url = None
    fields = {}
    if add_meta_info:
        engine = EngineType.objects.filter(pk=engine_id).first()
        scan = ScanHistory.objects.filter(pk=scan_history_id).first()
        subscan = SubScan.objects.filter(pk=subscan_id).first()
        url = get_scan_url(scan_history_id)
        if status:
            fields['Status'] = f'**{status}**'
        if engine:
            fields['Engine'] = engine.engine_name
        if scan:
            fields['Scan ID'] = f'[#{scan.id}]({url})'
        if subscan:
            url = get_scan_url(scan_history_id, subscan_id)
            fields['Subscan ID'] = f'[#{subscan.id}]({url})'
    title = get_task_title(task_name, scan_history_id, subscan_id)
    if status:
        severity = STATUS_TO_SEVERITIES.get(status)

    msg = f'{title} {status}\n'
    msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

    # Add fields to update
    for k, v in update_fields.items():
        fields[k] = v

    # Add traceback to notif
    if traceback and notif.send_scan_tracebacks:
        fields['Traceback'] = f'```\n{traceback}\n```'

    # Add files to notif
    files = []
    attach_file = (
        notif.send_scan_output_file and
        output_path and
        result and
        not traceback
    )
    if attach_file:
        output_title = output_path.split('/')[-1]
        files = [(output_path, output_title)]

    # Send notif
    opts = {
        'title': title,
        'url': url,
        'files': files,
        'severity': severity,
        'fields': fields,
        'fields_append': update_fields.keys()
    }
    send_notif(
        msg,
        scan_history_id=scan_history_id,
        subscan_id=subscan_id,
        **opts)

@app.task(name='send_file_to_discord', bind=False, queue='io_queue')
def send_file_to_discord(file_path, title=None):
    """Send file to Discord webhook.
    
    Args:
        file_path (str): Path to file to send
        title (str, optional): Title for Discord message
    """
    notif = Notification.objects.first()
    do_send = notif and notif.send_to_discord and notif.discord_hook_url
    if not do_send:
        return False

    webhook = DiscordWebhook(
        url=notif.discord_hook_url,
        rate_limit_retry=True,
        username=title or "reNgine Discord Plugin"
    )
    with open(file_path, "rb") as f:
        head, tail = os.path.split(file_path)
        webhook.add_file(file=f.read(), filename=tail)
    webhook.execute()

@app.task(name='send_hackerone_report', bind=False, queue='io_queue')
def send_hackerone_report(vulnerability_id):
    """Send HackerOne vulnerability report.

    Args:
        vulnerability_id (int): Vulnerability id.

    Returns:
        int: HTTP response status code.
    """
    vulnerability = Vulnerability.objects.get(id=vulnerability_id)
    severities = {v: k for k,v in NUCLEI_SEVERITY_MAP.items()}
    # can only send vulnerability report if team_handle exists
    if len(vulnerability.target_domain.h1_team_handle) !=0:
        hackerone_query = Hackerone.objects.all()
        if hackerone_query.exists():
            hackerone = Hackerone.objects.first()
            severity_value = severities[vulnerability.severity]
            tpl = hackerone.report_template

            # Replace syntax of report template with actual content
            tpl = tpl.replace('{vulnerability_name}', vulnerability.name)
            tpl = tpl.replace('{vulnerable_url}', vulnerability.http_url)
            tpl = tpl.replace('{vulnerability_severity}', severity_value)
            tpl = tpl.replace('{vulnerability_description}', vulnerability.description or '')
            tpl = tpl.replace('{vulnerability_extracted_results}', vulnerability.extracted_results or '')
            tpl = tpl.replace('{vulnerability_reference}', vulnerability.reference or '')

            data = {
              "data": {
                "type": "report",
                "attributes": {
                  "team_handle": vulnerability.target_domain.h1_team_handle,
                  "title": f'{vulnerability.name} found in {vulnerability.http_url}',
                  "vulnerability_information": tpl,
                  "severity_rating": severity_value,
                  "impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
                }
              }
            }

            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            r = requests.post(
              'https://api.hackerone.com/v1/hackers/reports',
              auth=(hackerone.username, hackerone.api_key),
              json=data,
              headers=headers
            )
            response = r.json()
            status_code = r.status_code
            if status_code == 201:
                vulnerability.hackerone_report_id = response['data']["id"]
                vulnerability.open_status = False
                vulnerability.save()
            return status_code

    else:
        logger.error('No team handle found.')
        return 111

def get_notification_settings():
    """Get cached notification settings."""
    cache_key = 'notification_settings'
    settings = cache.get(cache_key)
    if not settings:
        settings = Notification.objects.first()
        if settings:
            cache.set(cache_key, settings, timeout=300)  # 5 minutes
    return settings