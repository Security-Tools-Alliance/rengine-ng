import json
import pickle
from time import sleep

import humanize
import redis
import requests
from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.utils import timezone

from reNgine.definitions import DISCORD_SEVERITY_COLORS
from reNgine.settings import CELERY_BROKER_URL, DOMAIN_NAME
from scanEngine.models import Notification

logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)


#--------------------#
# NOTIFICATION UTILS #
#--------------------#

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
        cached_response = pickle.loads(cached_response)

    # Get existing webhook if found in cache
    cached_webhook = (
        DISCORD_WEBHOOKS_CACHE.get(f'{title}_webhook') if title else None
    )
    if cached_webhook:
        webhook = pickle.loads(cached_webhook)
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
        embed = pickle.loads(cached_embed)
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
        DISCORD_WEBHOOKS_CACHE.set(f'{title}_webhook', pickle.dumps(webhook))
        DISCORD_WEBHOOKS_CACHE.set(f'{title}_embed', pickle.dumps(embed))

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
            DISCORD_WEBHOOKS_CACHE.set(title, pickle.dumps(response))

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


def get_scan_title(scan_id, subscan_id=None, task_name=None):
    return f'Subscan #{subscan_id} summary' if subscan_id else f'Scan #{scan_id} summary'


def get_scan_url(scan_id=None, subscan_id=None):
    return f'https://{DOMAIN_NAME}/scan/detail/{scan_id}' if scan_id else None


def get_scan_fields(engine, scan, subscan=None, status='RUNNING', tasks=None):
    if tasks is None:
        tasks = []
    scan_obj = subscan or scan
    if subscan:
        tasks_h = f'`{subscan.type}`'
        host = subscan.subdomain.name
        scan_obj = subscan
    else:
        tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''
        host = scan.domain.name
        scan_obj = scan

    # Find scan elapsed time
    duration = None
    if scan_obj:
        if status in ['ABORTED', 'FAILED', 'SUCCESS']:
            td = scan_obj.stop_scan_date - scan_obj.start_scan_date
        else:
            td = timezone.now() - scan_obj.start_scan_date
        duration = humanize.naturaldelta(td)
    # Build fields
    url = get_scan_url(scan.id)
    fields = {
        'Status': f'**{status}**',
        'Engine': engine.engine_name,
        'Scan ID': f'[#{scan.id}]({url})'
    }

    if subscan:
        url = get_scan_url(scan.id, subscan.id)
        fields['Subscan ID'] = f'[#{subscan.id}]({url})'

    if duration:
        fields['Duration'] = duration

    fields['Host'] = host
    if tasks:
        fields['Tasks'] = tasks_h

    return fields


def get_task_title(task_name, scan_id=None, subscan_id=None):
    if scan_id:
        prefix = f'#{scan_id}'
        if subscan_id:
            prefix += f'-#{subscan_id}'
        return f'`{prefix}` - `{task_name}`'
    return f'`{task_name}` [unbound]'


def get_task_header_message(name, scan_history_id, subscan_id):
    msg = f'`{name}` [#{scan_history_id}'
    if subscan_id:
        msg += f'_#{subscan_id}]'
    msg += 'status'
    return msg


def get_output_file_name(scan_history_id, subscan_id, filename):
    title = f'{scan_history_id}'
    if subscan_id:
        title += f'-{subscan_id}'
    title += f'_{filename}'
    return title 