from django import template

from scanEngine.models import SecatorTask


register = template.Library()


@register.filter
def category_icon(category):
    """Map category names to FontAwesome icons"""
    if not category:
        return "folder"

    # Convert to lowercase for matching
    cat_lower = category.lower()

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

    # Try partial matches
    for key, icon in icon_map.items():
        if key in cat_lower:
            return icon

    # Default icon
    return "folder"


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

    # Try partial matches
    for key, icon in icon_map.items():
        if key in name_lower:
            return icon

    # Default icon
    return "project-diagram"


@register.simple_tag
def get_task_info(task_name):
    """Get task information by task name"""
    task = SecatorTask.objects.filter(task_type=task_name, is_active=True).first()
    if not task:
        return {"name": task_name, "category": "Unknown", "description": f"Secator task: {task_name}", "icon": "tools"}

    return {
        "name": task.name,
        "category": task.category,
        "description": task.description,
        "icon": category_icon(task.category),
    }


@register.filter
def parent_category(category):
    """Extract parent category (part before the first slash)"""
    if not category:
        return "unknown"

    # Split by '/' and take the first part
    parts = category.split("/")
    return parts[0].lower()


@register.filter
def get_structured_tasks(workflow):
    """Get structured tasks from workflow (with group information)"""
    if not hasattr(workflow, "get_structured_tasks"):
        return []
    return workflow.get_structured_tasks()
