from functools import lru_cache

from django import template

from scanEngine.models import SecatorTask


register = template.Library()


@register.filter
def category_display_label(category):
    """Display label for category; use 'Untagged' for unknown/empty so untagged tasks are clear."""
    if not category or (isinstance(category, str) and category.lower() == "unknown"):
        return "Untagged"
    return category


@register.filter
def category_icon(category):
    """Map category names to FontAwesome icons"""
    if not category:
        return "tag"
    cat_lower = category.lower()
    if cat_lower == "unknown":
        return "tag"

    # Priority mapping for specific categories with more representative icons
    priority_map = {
        "dns/recon": "search-location",  # DNS reconnaissance
        "dns/fuzz": "random",  # DNS fuzzing
        "dns/recon/tls": "certificate",  # TLS certificate analysis
        "url/crawl": "spider",  # Web crawling
        "url/fuzz": "bomb",  # URL fuzzing/bruteforce
        "url/fuzz/params": "cogs",  # Parameter fuzzing
        "url/probe": "crosshairs",  # URL probing
        "url/bypass": "shield-virus",  # WAF bypass
        "user/recon/email": "at",  # Email reconnaissance
        "user/recon/username": "user-secret",  # Username enumeration
        "vuln/scan": "exclamation-triangle",  # Vulnerability scanning
        "vuln/scan/wordpress": "wordpress",  # WordPress specific
        "port/scan": "network-wired",  # Port scanning
        "secret/scan": "key",  # Secret scanning
        "pattern/scan": "search",  # Pattern scanning
        "exploit/attack": "crosshairs",  # Exploitation
        "exploit/recon": "binoculars",  # Exploit reconnaissance
        "ip/recon": "map-marked-alt",  # IP reconnaissance
        "waf/scan": "shield-alt",  # WAF detection
    }

    # Try exact match first
    if cat_lower in priority_map:
        return priority_map[cat_lower]

    # Try partial matches for main categories with better icons
    icon_map = {
        "dns": "search-location",  # DNS operations
        "url": "link",  # URL operations
        "user": "users",  # User operations
        "vuln": "exclamation-triangle",  # Vulnerabilities
        "port": "network-wired",  # Network ports
        "secret": "key",  # Secrets
        "pattern": "search",  # Pattern matching
        "exploit": "crosshairs",  # Exploitation
        "ip": "map-marked-alt",  # IP addresses
        "waf": "shield-alt",  # WAF
        "email": "at",  # Email
        "recon": "binoculars",  # Reconnaissance
        "scan": "search",  # Scanning
        "fuzz": "random",  # Fuzzing
        "crawl": "spider",  # Crawling
        "probe": "crosshairs",  # Probing
        "bypass": "shield-virus",  # Bypassing
        "attack": "crosshairs",  # Attacking
        "tls": "certificate",  # TLS/SSL
        "params": "cogs",  # Parameters
        "wordpress": "wordpress",  # WordPress
        "username": "user-secret",  # Username
    }

    return next((icon for key, icon in icon_map.items() if key in cat_lower), "folder")


@register.filter
def workflow_icon(workflow_name):
    """Map workflow names to FontAwesome icons"""
    if not workflow_name:
        return "project-diagram"

    # Convert to lowercase for matching
    name_lower = workflow_name.lower()

    # Priority mapping for specific workflow names
    priority_map = {
        "cidr recon": "network-wired",  # Network reconnaissance
        "code scan": "code",  # Code scanning
        "host recon": "server",  # Host reconnaissance
        "subdomain recon": "sitemap",  # Subdomain discovery
        "url bypass": "shield-virus",  # WAF bypass
        "url crawl": "spider",  # Web crawling
        "url directory search": "folder-open",  # Directory enumeration
        "url fuzz": "bomb",  # URL fuzzing
        "url parameters fuzz": "cogs",  # Parameter fuzzing
        "url vulnerability": "exclamation-triangle",  # Vulnerability scanning
        "user hunt": "users",  # User hunting
        "wordpress": "wordpress",  # WordPress scanning
        "domain recon": "search-location",  # Domain reconnaissance
        "ip recon": "map-marked-alt",  # IP reconnaissance
        "port scan": "plug",  # Port scanning
        "service scan": "cogs",  # Service scanning
        "vulnerability scan": "exclamation-triangle",  # Vulnerability assessment
        "web scan": "globe",  # Web application scanning
        "api scan": "code",  # API scanning
        "ssl scan": "certificate",  # SSL/TLS scanning
        "dns scan": "search-location",  # DNS scanning
        "email scan": "at",  # Email scanning
        "social scan": "users",  # Social engineering
        "mobile scan": "mobile-alt",  # Mobile scanning
        "cloud scan": "cloud",  # Cloud scanning
        "iot scan": "microchip",  # IoT scanning
        "crypto scan": "coins",  # Cryptocurrency scanning
        "osint scan": "search",  # OSINT scanning
        "forensics scan": "search-plus",  # Digital forensics
        "malware scan": "virus",  # Malware scanning
        "phishing scan": "fish",  # Phishing scanning
        "red team": "crosshairs",  # Red team exercises
        "blue team": "shield",  # Blue team defense
        "purple team": "balance-scale",  # Purple team collaboration
        "compliance scan": "check-circle",  # Compliance scanning
        "penetration test": "target",  # Penetration testing
        "security assessment": "clipboard-check",  # Security assessment
        "security audit": "audit",  # Security audit
        "incident response": "exclamation-circle",  # Incident response
        "threat hunting": "skull-crossbones",  # Threat hunting
        "threat intelligence": "brain",  # Threat intelligence
    }

    # Try exact match first
    if name_lower in priority_map:
        return priority_map[name_lower]

    # Try partial matches for workflow types
    icon_map = {
        "builtin": "star",  # Built-in workflows (fallback)
        "custom": "user-cog",  # Custom workflows
        "subdomain": "sitemap",  # Subdomain enumeration
        "recon": "binoculars",  # Reconnaissance
        "vuln": "exclamation-triangle",  # Vulnerability assessment
        "web": "globe",  # Web applications
        "network": "network-wired",  # Network infrastructure
        "port": "plug",  # Port scanning
        "dns": "search-location",  # DNS operations
        "url": "link",  # URL scanning
        "email": "at",  # Email security
        "social": "users",  # Social engineering
        "api": "code",  # API testing
        "mobile": "mobile-alt",  # Mobile applications
        "cloud": "cloud",  # Cloud infrastructure
        "iot": "microchip",  # IoT devices
        "crypto": "coins",  # Cryptocurrency
        "osint": "search",  # Open source intelligence
        "forensics": "search-plus",  # Digital forensics
        "malware": "virus",  # Malware analysis
        "phishing": "fish",  # Phishing campaigns
        "red_team": "crosshairs",  # Red team exercises
        "blue_team": "shield",  # Blue team defense
        "purple_team": "balance-scale",  # Purple team collaboration
        "compliance": "check-circle",  # Compliance testing
        "penetration": "target",  # Penetration testing
        "assessment": "clipboard-check",  # Security assessment
        "audit": "audit",  # Security audit
        "incident": "exclamation-circle",  # Incident response
        "threat": "skull-crossbones",  # Threat hunting
        "intelligence": "brain",  # Threat intelligence
        "scan": "search",  # General scanning
        "fuzz": "random",  # Fuzzing
        "crawl": "spider",  # Crawling
        "bypass": "shield-virus",  # Bypassing
        "directory": "folder-open",  # Directory enumeration
        "parameters": "cogs",  # Parameter testing
        "code": "code",  # Code analysis
        "host": "server",  # Host operations
        "cidr": "network-wired",  # Network ranges
        "ssl": "certificate",  # SSL/TLS
        "service": "cogs",  # Service operations
    }

    return next(
        (icon for key, icon in icon_map.items() if key in name_lower),
        "project-diagram",
    )


@register.filter
def scan_icon(scan_name):
    """Map scan names to FontAwesome icons (scan-type tiles). Fallback to workflow_icon."""
    if not scan_name:
        return "radar"
    name_str = str(scan_name)
    name_lower = name_str.lower()
    scan_icons = {
        "domain": "globe",
        "host": "server",
        "network": "network-wired",
        "subdomain": "sitemap",
        "url": "link",
    }
    if name_lower in scan_icons:
        return scan_icons[name_lower]
    return workflow_icon(name_str)


@lru_cache(maxsize=128)
def _get_task_info_from_db(task_name):
    """
    Look up SecatorTask by task_type and return metadata dict.
    Memoized so repeated template tag calls for the same task_name reuse the result.
    """
    if not task_name:
        return {"name": task_name or "", "category": "Unknown", "description": "", "icon": "tools"}
    task = SecatorTask.objects.filter(task_type=task_name, is_active=True).only("name", "tags", "description").first()
    if not task:
        return {"name": task_name, "category": "Unknown", "description": f"Secator task: {task_name}", "icon": "tools"}
    cat = tags_parent_category(task.tags) if task.tags else "unknown"
    return {
        "name": task.name,
        "category": cat,
        "description": task.description,
        "icon": tags_icon(task.tags),
    }


@register.simple_tag(takes_context=True)
def get_task_info(context, task_name):
    """Get task information by task name."""
    if tasks_dict := context.get("tasks_dict"):
        if task := tasks_dict.get(task_name):
            cat = tags_parent_category(task.tags) if getattr(task, "tags", None) else "unknown"
            return {
                "name": task.name,
                "category": cat,
                "description": task.description,
                "icon": tags_icon(task.tags) if getattr(task, "tags", None) else "folder",
            }

    return _get_task_info_from_db(task_name or "")


@register.filter
def parent_category(category):
    """Extract parent category (part before the first slash). Kept for backward compatibility."""
    if not category:
        return "unknown"
    parts = category.split("/")
    return parts[0].lower()


@register.filter
def tags_icon(tags):
    """Map first task tag to FontAwesome icon (same logic as category_icon)."""
    primary = tags_parent_category(tags)
    return category_icon(primary)


@register.filter
def tags_parent_category(tags):
    """Return first tag for grouping/filtering; used when tasks use tags instead of category."""
    if not tags:
        return "unknown"
    if isinstance(tags, (list, tuple)):
        first = next((t for t in tags if t), None)
        return (first or "unknown").lower() if isinstance(first, str) else "unknown"
    return "unknown"


@register.filter
def get_structured_tasks(workflow):
    """Get structured tasks from workflow (with group information)"""
    # Use pre-computed value if available (from view optimization)
    if hasattr(workflow, "_precomputed_structured_tasks"):
        return workflow._precomputed_structured_tasks
    # Fallback to method call if not pre-computed
    if not hasattr(workflow, "get_structured_tasks"):
        return []
    return workflow.get_structured_tasks()


@register.filter
def workflow_tags_union(workflows):
    """Return sorted list of unique tags across workflows for filter bar (lowercase for CSS/JS)."""
    if not workflows:
        return []
    seen = set()
    for w in workflows:
        tags = getattr(w, "tags", None) or []
        for t in tags:
            if t and isinstance(t, str):
                seen.add(t.lower())
    return sorted(seen)


@register.filter
def workflow_count_for_tag(workflows, tag):
    """Return count of workflows that have the given tag (case-insensitive)."""
    if not tag or not workflows:
        return 0
    tag_lower = tag.lower() if isinstance(tag, str) else tag
    return sum(
        1
        for w in workflows
        if any((t or "").lower() == tag_lower for t in (getattr(w, "tags", None) or []) if isinstance(t, str))
    )


@register.filter
def workflow_has_tag(workflow, tag):
    """Return True if workflow has the given tag (case-insensitive)."""
    if not tag:
        return False
    tag_lower = tag.lower() if isinstance(tag, str) else tag
    tags = getattr(workflow, "tags", None) or []
    return any((t or "").lower() == tag_lower for t in tags if isinstance(t, str))


@register.filter
def slice_from(value, start_index):
    """Return list[start_index:]; used so limit is respected for remaining items."""
    if value is None:
        return []
    try:
        start = int(start_index)
    except (TypeError, ValueError):
        return list(value)
    return list(value)[start:]


@register.filter
def subtract(value, arg):
    """Return value - arg (for '+N more' count using limit)."""
    try:
        return int(value) - int(arg)
    except (TypeError, ValueError):
        return 0
