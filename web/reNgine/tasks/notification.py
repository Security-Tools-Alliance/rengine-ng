import os
import requests
from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.utilities.notification import (
    send_discord_message, send_slack_message, send_lark_message,
    send_telegram_message, enrich_notification, get_scan_url, get_scan_title,
    get_scan_fields, get_task_title
)
from reNgine.definitions import NUCLEI_SEVERITY_MAP, STATUS_TO_SEVERITIES
from scanEngine.models import EngineType, Notification, Hackerone
from startScan.models import ScanActivity, ScanHistory, SubScan, Vulnerability
from discord_webhook import DiscordWebhook

logger = get_task_logger(__name__)


@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
        message,
        scan_history_id=None,
        subscan_id=None,
        **options):
    if 'title' not in options:
        message = enrich_notification(message, scan_history_id, subscan_id)
    send_discord_message(message, **options)
    send_slack_message(message)
    send_lark_message(message)
    send_telegram_message(message)


@app.task(name='send_scan_notif', bind=False, queue='send_notif_queue')
def send_scan_notif(
        scan_history_id,
        subscan_id=None,
        engine_id=None,
        status='RUNNING'):
    """Send scan status notification. Works for scan or a subscan if subscan_id
    is passed.

    Args:
        scan_history_id (int, optional): ScanHistory id.
        subscan_id (int, optional): SuScan id.
        engine_id (int, optional): EngineType id.
    """

    # Skip send if notification settings are not configured
    notif = Notification.objects.first()
    if not (notif and notif.send_scan_status_notif):
        return

    # Get domain, engine, scan_history objects
    engine = EngineType.objects.filter(pk=engine_id).first()
    scan = ScanHistory.objects.filter(pk=scan_history_id).first()
    subscan = SubScan.objects.filter(pk=subscan_id).first()
    tasks = ScanActivity.objects.filter(scan_of=scan) if scan else 0

    # Build notif options
    url = get_scan_url(scan_history_id, subscan_id)
    title = get_scan_title(scan_history_id, subscan_id)
    fields = get_scan_fields(engine, scan, subscan, status, tasks)
    msg = f'{title} {status}\n'
    msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
    severity = STATUS_TO_SEVERITIES.get(status) if status else None
    opts = {
        'title': title,
        'url': url,
        'fields': fields,
        'severity': severity
    }
    logger.warning(f'Sending notification "{title}" [{severity}]')

    # Send notification
    send_notif(
        msg,
        scan_history_id,
        subscan_id,
        **opts)


@app.task(name='send_task_notif', bind=False, queue='send_notif_queue')
def send_task_notif(
        task_name,
        status=None,
        result=None,
        output_path=None,
        traceback=None,
        scan_history_id=None,
        engine_id=None,
        subscan_id=None,
        severity=None,
        add_meta_info=True,
        update_fields=None):
    """Send task status notification.

    Args:
        task_name (str): Task name.
        status (str, optional): Task status.
        result (str, optional): Task result.
        output_path (str, optional): Task output path.
        traceback (str, optional): Task traceback.
        scan_history_id (int, optional): ScanHistory id.
        subscan_id (int, optional): SuScan id.
        engine_id (int, optional): EngineType id.
        severity (str, optional): Severity (will be mapped to notif colors)
        add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
        update_fields (dict, optional): Fields key / value to update.
    """

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


@app.task(name='send_file_to_discord', bind=False, queue='send_notif_queue')
def send_file_to_discord(file_path, title=None):
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


@app.task(name='send_hackerone_report', bind=False, queue='send_notif_queue')
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