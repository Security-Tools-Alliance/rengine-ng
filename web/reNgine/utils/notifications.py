import requests
import json
import redis

from time import sleep
from discord_webhook import DiscordEmbed, DiscordWebhook

from reNgine.definitions import (
    DISCORD_SEVERITY_COLORS,
    STATUS_TO_SEVERITIES
)
from reNgine.settings import CELERY_BROKER_URL
from scanEngine.models import Notification, EngineType
from startScan.models import ScanHistory, SubScan, ScanActivity
from reNgine.utils.logger import Logger
from reNgine.utils.formatters import get_scan_fields, get_scan_title, get_scan_url

logger = Logger(True)

DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)

def send_telegram_message(message):
    """Send Telegram message.

    Args:
        message (str): Message.
    """
    notif = Notification.objects.first()
    do_send = (
        notif and
        notif.send_to_telegram and
        notif.telegram_bot_token and
        notif.telegram_bot_chat_id)
    if not do_send:
        return
    telegram_bot_token = notif.telegram_bot_token
    telegram_bot_chat_id = notif.telegram_bot_chat_id
    send_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_bot_chat_id}&parse_mode=Markdown&text={message}'
    requests.get(send_url)


def send_slack_message(message):
    """Send Slack message.

    Args:
        message (str): Message.
    """
    headers = {'content-type': 'application/json'}
    message = {'text': message}
    notif = Notification.objects.first()
    do_send = (
        notif and
        notif.send_to_slack and
        notif.slack_hook_url)
    if not do_send:
        return
    hook_url = notif.slack_hook_url
    requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_lark_message(message):
    """Send lark message.

    Args:
        message (str): Message.
    """
    headers = {'content-type': 'application/json'}
    message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
    notif = Notification.objects.first()
    do_send = (
        notif and
        notif.send_to_lark and
        notif.lark_hook_url)
    if not do_send:
        return
    hook_url = notif.lark_hook_url
    requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_discord_message(message, title='', severity=None, url=None, files=None, fields=None, fields_append=None):
    """Send Discord message.

    If title and fields are specified, ignore the 'message' and create a Discord
    embed that can be updated later if specifying the same title (title is the
    cache key).

    Args:
        message (str): Message to send. If an embed is used, this is ignored.
        severity (str, optional): Severity. Colors are picked based on severity.
        files (list, optional): List of files to attach to message.
        title (str, optional): Discord embed title.
        url (str, optional): Discord embed URL.
        fields (dict, optional): Discord embed fields.
        fields_append (list, optional): Discord embed field names to update
            instead of overwrite.
    """

    if fields is None:
        fields = {}
    if fields_append is None:
        fields_append = []
    # Check if do send
    notif = Notification.objects.first()
    if not (notif and notif.send_to_discord and notif.discord_hook_url):
        return False

    # If fields and title, use an embed
    use_discord_embed = fields and title
    if use_discord_embed:
        message = '' # no need for message in embeds

    # Check for cached response in cache, using title as key
    cached_response = DISCORD_WEBHOOKS_CACHE.get(title) if title else None
    if cached_response:
        cached_response = json.loads(cached_response)



    # Get existing webhook if found in cache
    cached_webhook = (
        DISCORD_WEBHOOKS_CACHE.get(f'{title}_webhook') if title else None
    )
    if cached_webhook:
        webhook = json.loads(cached_webhook)
        webhook.remove_embeds()
    else:
        webhook = DiscordWebhook(
            url=notif.discord_hook_url,
            rate_limit_retry=False,
            content=message)

    # Get existing embed if found in cache
    embed = None
    cached_embed = DISCORD_WEBHOOKS_CACHE.get(f'{title}_embed') if title else None
    if cached_embed:
        embed = json.loads(cached_embed)
    elif use_discord_embed:
        embed = DiscordEmbed(title=title)

    # Set embed fields
    if embed:
        if url:
            embed.set_url(url)
        if severity:
            embed.set_color(DISCORD_SEVERITY_COLORS[severity])
        embed.set_description(message)
        embed.set_timestamp()
        existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
        logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
        for name, value in fields.items():
            if not value: # cannot send empty field values to Discord [error 400]
                continue
            value = str(value)
            new_field = {'name': name, 'value': value, 'inline': False}

            # If field already existed in previous embed, update it.
            if name in existing_fields_dict:
                field = [f for f in embed.fields if f['name'] == name][0]

                # Append to existing field value
                if name in fields_append:
                    existing_val = field['value']
                    existing_val = str(existing_val)
                    if value not in existing_val:
                        value = f'{existing_val}\n{value}'

                    if len(value) > 1024: # character limit for embed field
                        value = value[:1016] + '\n[...]'

                # Update existing embed
                ix = embed.fields.index(field)
                embed.fields[ix]['value'] = value

            else:
                embed.add_embed_field(**new_field)

        webhook.add_embed(embed)

        # Add webhook and embed objects to cache, so we can pick them up later
        DISCORD_WEBHOOKS_CACHE.set(f'{title}_webhook', json.dumps(webhook))
        DISCORD_WEBHOOKS_CACHE.set(f'{title}_embed', json.dumps(embed))

    # Add files to webhook
    if files:
        for (path, name) in files:
            with open(path, 'r') as f:
                content = f.read()
            webhook.add_file(content, name)

    # Edit webhook if it already existed, otherwise send new webhook
    if cached_response:
        response = webhook.edit(cached_response)
    else:
        response = webhook.execute()
        if use_discord_embed and response.status_code == 200:
            DISCORD_WEBHOOKS_CACHE.set(title, json.dumps(response))

    # Get status code
    if response.status_code == 429:
        errors = json.loads(
            response.content.decode('utf-8'))
        wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
        sleep(wh_sleep)
        send_discord_message(
                message,
                title,
                severity,
                url,
                files,
                fields,
                fields_append)
    elif response.status_code != 200:
        logger.error(
            f'Error while sending webhook data to Discord.'
            f'\n\tHTTP code: {response.status_code}.'
            f'\n\tDetails: {response.content}')


def enrich_notification(message, scan_history_id, subscan_id):
    """Add scan id / subscan id to notification message.

    Args:
        message (str): Original notification message.
        scan_history_id (int): Scan history id.
        subscan_id (int): Subscan id.

    Returns:
        str: Message.
    """
    if scan_history_id is not None:
        if subscan_id:
            message = f'`#{scan_history_id}_{subscan_id}`: {message}'
        else:
            message = f'`#{scan_history_id}`: {message}'
    return message

def get_scan_with_related(scan_history_id, subscan_id=None, engine_id=None):
    """Get scan history with all related objects needed for notifications.
    
    Args:
        scan_history_id (int): ScanHistory id
        subscan_id (int, optional): SubScan id
        engine_id (int, optional): EngineType id
        
    Returns:
        tuple: (ScanHistory, SubScan, EngineType, QuerySet[ScanActivity])
            Returns None for any object that doesn't exist
    """
    try:
        # Get scan with related objects
        scan = (ScanHistory.objects
               .select_related('domain', 'scan_type')
               .prefetch_related('tasks', 'scan_activities')
               .get(id=scan_history_id))
               
        # Get engine if provided
        engine = (EngineType.objects
                 .filter(pk=engine_id)
                 .first()) if engine_id else None
                 
        # Get subscan if provided
        subscan = (SubScan.objects
                  .select_related('scan_history')
                  .filter(pk=subscan_id)
                  .first()) if subscan_id else None
                  
        # Get related activities
        tasks = (ScanActivity.objects
                .select_related('scan_of')
                .filter(scan_of=scan))
                
        return scan, subscan, engine, tasks
        
    except ScanHistory.DoesNotExist:
        return None, None, None, None

def build_notification_message(scan, subscan=None, engine=None, status='RUNNING', tasks=None):
    """Build notification message and options.
    
    Args:
        scan (ScanHistory): Scan history object
        subscan (SubScan, optional): SubScan object
        engine (EngineType, optional): Engine object
        status (str, optional): Status to send. Default: 'RUNNING'
        tasks (QuerySet, optional): Related ScanActivity objects
        
    Returns:
        dict: Message data containing:
            - message (str): Formatted message
            - options (dict): Options for send_notif
    """
    # Build message components with provided objects
    url = get_scan_url(scan.id, subscan.id if subscan else None)
    title = get_scan_title(scan.id, subscan.id if subscan else None)
    fields = get_scan_fields(engine, scan, subscan, status, tasks or [])
    
    # Format message
    msg = f'{title} {status}\n'
    msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
    
    # Build options
    severity = STATUS_TO_SEVERITIES.get(status) if status else None
    options = {
        'title': title,
        'url': url,
        'fields': fields,
        'severity': severity
    }
    
    return {
        'message': msg,
        'options': options
    }

def send_vulnerability_scan_summary(task_instance, scan_id=None):
    """Send vulnerability scan summary notification.
    
    Calculates statistics for all vulnerability types and sends a summary notification.
    
    Args:
        task_instance: The RengineTask instance (self)
        scan_id: Optional scan ID override (defaults to task_instance.scan_id)
    """
    from startScan.models import Vulnerability
    from scanEngine.models import Notification
    
    # Get notification settings
    notif = Notification.objects.first()
    send_status = notif.send_scan_status_notif if notif else False
    
    if not send_status:
        return
    
    # Use provided scan_id or fallback to task instance scan_id
    scan_id = scan_id or task_instance.scan_id
    
    # Count vulnerabilities by severity
    vulns = Vulnerability.objects.filter(scan_history__id=scan_id)
    info_count = vulns.filter(severity=0).count()
    low_count = vulns.filter(severity=1).count()
    medium_count = vulns.filter(severity=2).count()
    high_count = vulns.filter(severity=3).count()
    critical_count = vulns.filter(severity=4).count()
    unknown_count = vulns.filter(severity=-1).count()
    
    # Calculate total
    vulnerability_count = (
        info_count + low_count + medium_count + 
        high_count + critical_count + unknown_count
    )
    
    # Prepare notification fields
    fields = {
        'Total': vulnerability_count,
        'Critical': critical_count,
        'High': high_count,
        'Medium': medium_count,
        'Low': low_count,
        'Info': info_count,
        'Unknown': unknown_count
    }
    
    # Send notification
    task_instance.notify(fields=fields)


def send_vulnerability_notification(task_instance, vuln, http_url, subdomain_name, severity):
    """Send notification for an individual vulnerability.
    
    Args:
        task_instance: The RengineTask instance (self)
        vuln: Vulnerability object
        http_url: URL where vulnerability was found
        subdomain_name: Name of the subdomain
        severity: Severity string (low, medium, high, critical)
    """
    from scanEngine.models import Notification
    
    # Get notification settings
    notif = Notification.objects.first()
    
    if not (
        notif 
        and notif.send_vuln_notif
        and severity in ['low', 'medium', 'high', 'critical']
    ):
        return
    
    # Prepare notification fields
    fields = {
        'Severity': f'**{severity.upper()}**',
        'URL': http_url,
        'Subdomain': subdomain_name,
        'Name': vuln.name,
        'Type': vuln.type,
        'Description': vuln.description,
        'Template': vuln.template_url,
        'Tags': vuln.get_tags_str(),
        'CVEs': vuln.get_cve_str(),
        'CWEs': vuln.get_cwe_str(),
        'References': vuln.get_refs_str()
    }
    
    # Map severity to notification level
    severity_map = {
        'low': 'info',
        'medium': 'warning',
        'high': 'error',
        'critical': 'error'
    }
    
    # Send notification
    task_instance.notify(
        f'vulnerability_scan_#{vuln.id}',
        severity_map[severity],
        fields,
        add_meta_info=False
    )
