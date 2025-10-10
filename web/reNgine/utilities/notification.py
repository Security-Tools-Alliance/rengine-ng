"""
Notification utilities for reNgine-ng.

This module provides utilities for handling notifications, file naming,
and output management across different scan types.

Key features:
- File naming utilities for scan outputs
- Notification formatting helpers
- Output file management
- Scan result organization
"""

from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
from discord_webhook import DiscordEmbed, DiscordWebhook
import redis
import requests

from reNgine.settings import CELERY_BROKER_URL
from reNgine.utilities.core.formatting import format_bytes, format_json
from scanEngine.models import Notification


logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(CELERY_BROKER_URL)


# --------------------#
# NOTIFICATION UTILS #
# --------------------#


def get_output_file_name(scan_history_id: int, subscan_id: Optional[int], filename: str) -> str:
    """
    Generate standardized output file name for scan results.

    Args:
        scan_history_id (int): Scan history ID
        subscan_id (int, optional): Subscan ID if applicable
        filename (str): Base filename

    Returns:
        str: Formatted filename with scan IDs

    Example:
        >>> get_output_file_name(123, 456, "subdomains.txt")
        "123-456_subdomains.txt"
        >>> get_output_file_name(123, None, "ports.txt")
        "123_ports.txt"
    """
    title = f"{scan_history_id}"
    if subscan_id:
        title += f"-{subscan_id}"
    title += f"_{filename}"
    return title


def send_telegram_message(message: str) -> bool:
    """
    Send Telegram message.

    Args:
        message (str): Message to send

    Returns:
        bool: True if message sent successfully, False otherwise
    """
    try:
        notif = Notification.objects.first()
        do_send = notif and notif.send_to_telegram and notif.telegram_bot_token and notif.telegram_bot_chat_id
        if not do_send:
            logger.debug("Telegram notification not configured or disabled")
            return False

        telegram_bot_token = notif.telegram_bot_token
        telegram_bot_chat_id = notif.telegram_bot_chat_id
        send_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_bot_chat_id}&parse_mode=Markdown&text={message}"

        response = requests.get(send_url, timeout=30)
        response.raise_for_status()

        logger.info("Telegram message sent successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")
        return False


def send_slack_message(message: str) -> bool:
    """
    Send Slack message.

    Args:
        message (str): Message to send

    Returns:
        bool: True if message sent successfully, False otherwise
    """
    try:
        headers = {"content-type": "application/json"}
        message_data = {"text": message}
        notif = Notification.objects.first()

        if not (notif and notif.send_to_slack and notif.slack_webhook_url):
            logger.debug("Slack notification not configured or disabled")
            return False

        response = requests.post(notif.slack_webhook_url, headers=headers, data=format_json(message_data), timeout=30)
        response.raise_for_status()

        logger.info("Slack message sent successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")
        return False


def send_discord_message(message: str, webhook_url: str, title: str = "reNgine Notification") -> bool:
    """
    Send Discord message.

    Args:
        message (str): Message to send
        webhook_url (str): Discord webhook URL
        title (str): Message title

    Returns:
        bool: True if message sent successfully, False otherwise
    """
    try:
        webhook = DiscordWebhook(url=webhook_url, content=message)
        embed = DiscordEmbed(title=title, description=message, color="03b2f8")
        webhook.add_embed(embed)
        webhook.execute()

        logger.info("Discord message sent successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to send Discord message: {e}")
        return False


def send_discord_file(file_path: str, webhook_url: str, filename: str = None) -> bool:
    """
    Send file to Discord.

    Args:
        file_path (str): Path to file to send
        webhook_url (str): Discord webhook URL
        filename (str, optional): Custom filename for Discord

    Returns:
        bool: True if file sent successfully, False otherwise
    """
    try:
        webhook = DiscordWebhook(url=webhook_url)
        webhook.add_file(file=open(file_path, "rb"), filename=filename or file_path.split("/")[-1])
        webhook.execute()

        logger.info(f"Discord file sent successfully: {file_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to send Discord file {file_path}: {e}")
        return False


def format_scan_summary(scan_data: Dict[str, Any]) -> str:
    """
    Format scan summary for notifications.

    Args:
        scan_data (dict): Scan data dictionary

    Returns:
        str: Formatted scan summary
    """
    try:
        summary = "🔍 **Scan Summary**\n"
        summary += f"**Target:** {scan_data.get('target', 'N/A')}\n"
        summary += f"**Scan Type:** {scan_data.get('scan_type', 'N/A')}\n"
        summary += f"**Status:** {scan_data.get('status', 'N/A')}\n"

        if scan_data.get("subdomains_found"):
            summary += f"**Subdomains Found:** {scan_data['subdomains_found']}\n"
        if scan_data.get("ports_found"):
            summary += f"**Ports Found:** {scan_data['ports_found']}\n"
        if scan_data.get("endpoints_found"):
            summary += f"**Endpoints Found:** {scan_data['endpoints_found']}\n"
        if scan_data.get("vulnerabilities_found"):
            summary += f"**Vulnerabilities Found:** {scan_data['vulnerabilities_found']}\n"

        summary += f"**Duration:** {scan_data.get('duration', 'N/A')}\n"
        summary += f"**Started:** {scan_data.get('started_at', 'N/A')}\n"

        return summary

    except Exception as e:
        logger.error(f"Failed to format scan summary: {e}")
        return f"Scan completed for {scan_data.get('target', 'unknown target')}"


def get_notification_config() -> Dict[str, Any]:
    """
    Get notification configuration.

    Returns:
        dict: Notification configuration
    """
    try:
        notif = Notification.objects.first()
        if not notif:
            return {}

        return {
            "send_to_telegram": notif.send_to_telegram,
            "send_to_slack": notif.send_to_slack,
            "send_to_discord": notif.send_to_discord,
            "telegram_bot_token": notif.telegram_bot_token,
            "telegram_bot_chat_id": notif.telegram_bot_chat_id,
            "slack_webhook_url": notif.slack_webhook_url,
            "discord_webhook_url": notif.discord_webhook_url,
        }

    except Exception as e:
        logger.error(f"Failed to get notification config: {e}")
        return {}


def send_notification(message: str, notification_type: str = "info") -> bool:
    """
    Send notification through configured channels.

    Args:
        message (str): Message to send
        notification_type (str): Type of notification (info, warning, error)

    Returns:
        bool: True if at least one notification sent successfully
    """
    config = get_notification_config()
    success = False

    try:
        # Send Telegram notification
        if config.get("send_to_telegram") and config.get("telegram_bot_token"):
            if send_telegram_message(message):
                success = True

        # Send Slack notification
        if config.get("send_to_slack") and config.get("slack_webhook_url"):
            if send_slack_message(message):
                success = True

        # Send Discord notification
        if config.get("send_to_discord") and config.get("discord_webhook_url"):
            if send_discord_message(message, config["discord_webhook_url"]):
                success = True

    except Exception as e:
        logger.error(f"Failed to send notifications: {e}")

    return success


def cache_discord_webhook(webhook_url: str, scan_id: int) -> None:
    """
    Cache Discord webhook URL for a scan.

    Args:
        webhook_url (str): Discord webhook URL
        scan_id (int): Scan ID
    """
    try:
        DISCORD_WEBHOOKS_CACHE.set(f"discord_webhook_{scan_id}", webhook_url, ex=3600)  # 1 hour
        logger.debug(f"Cached Discord webhook for scan {scan_id}")
    except Exception as e:
        logger.error(f"Failed to cache Discord webhook: {e}")


def get_cached_discord_webhook(scan_id: int) -> Optional[str]:
    """
    Get cached Discord webhook URL for a scan.

    Args:
        scan_id (int): Scan ID

    Returns:
        str or None: Cached webhook URL or None if not found
    """
    try:
        webhook_url = DISCORD_WEBHOOKS_CACHE.get(f"discord_webhook_{scan_id}")
        return webhook_url.decode("utf-8") if webhook_url else None
    except Exception as e:
        logger.error(f"Failed to get cached Discord webhook: {e}")
        return None


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format.

    Args:
        size_bytes (int): File size in bytes

    Returns:
        str: Human readable file size
    """
    return format_bytes(size_bytes)


def send_lark_message(message: str) -> bool:
    """
    Send Lark message.

    Args:
        message (str): Message to send

    Returns:
        bool: True if message was sent successfully, False otherwise
    """
    try:
        import json

        import requests

        from scanEngine.models import Notification

        notif = Notification.objects.first()
        do_send = notif and notif.send_to_lark and notif.lark_hook_url

        if not do_send:
            logger.warning("Lark notifications not configured or disabled")
            return False

        headers = {"content-type": "application/json"}
        message_data = {
            "msg_type": "interactive",
            "card": {"elements": [{"tag": "div", "text": {"content": message, "tag": "lark_md"}}]},
        }

        hook_url = notif.lark_hook_url
        response = requests.post(url=hook_url, data=json.dumps(message_data), headers=headers)

        if response.status_code == 200:
            logger.info(f"Lark message sent successfully: {message[:100]}...")
            return True
        else:
            logger.error(f"Failed to send Lark message: {response.status_code}")
            return False

    except Exception as e:
        logger.error(f"Failed to send Lark message: {e}")
        return False
