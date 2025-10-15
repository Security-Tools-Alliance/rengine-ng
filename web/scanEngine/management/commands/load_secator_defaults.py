from django.core.management.base import BaseCommand

from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow


class Command(BaseCommand):
    help = "Load default Secator tasks, workflows and scan configurations into the database"

    def handle(self, *args, **options):
        self.stdout.write("Loading default Secator tasks...")
        self.load_default_tasks()

        self.stdout.write("Loading default Secator workflows...")
        self.load_default_workflows()

        self.stdout.write("Loading default Secator scan configurations...")
        self.load_default_scans()

        self.stdout.write(
            self.style.SUCCESS("Successfully loaded default Secator tasks, workflows and scan configurations!")
        )

    def load_default_tasks(self):
        """Load default Secator tasks based on the available commands."""

        default_tasks = [
            # URL/Fuzz/Params
            {
                "name": "Arjun",
                "task_type": "arjun",
                "category": "url/fuzz/params",
                "description": "HTTP Parameter Discovery Suite",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "BUP",
                "task_type": "bup",
                "category": "url/bypass",
                "description": "40X bypasser",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Dalfox",
                "task_type": "dalfox",
                "category": "url/fuzz",
                "description": "Powerful open source XSS scanning tool",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Dirsearch",
                "task_type": "dirsearch",
                "category": "url/fuzz",
                "description": "Advanced web path brute-forcer",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Feroxbuster",
                "task_type": "feroxbuster",
                "category": "url/fuzz",
                "description": "Simple, fast, recursive content discovery tool written in Rust",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "FFuF",
                "task_type": "ffuf",
                "category": "url/fuzz",
                "description": "Fast web fuzzer written in Go",
                "is_builtin": True,
                "is_active": True,
            },
            # Vulnerability Scan
            {
                "name": "BBot",
                "task_type": "bbot",
                "category": "vuln/scan",
                "description": "Multipurpose scanner",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Grype",
                "task_type": "grype",
                "category": "vuln/scan",
                "description": "Vulnerability scanner for container images and filesystems",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Nuclei",
                "task_type": "nuclei",
                "category": "vuln/scan",
                "description": "Fast and customisable vulnerability scanner based on simple YAML based DSL",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Trivy",
                "task_type": "trivy",
                "category": "vuln/scan",
                "description": "Comprehensive and versatile security scanner",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "WPScan",
                "task_type": "wpscan",
                "category": "vuln/scan/wordpress",
                "description": "Wordpress security scanner",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "WPProbe",
                "task_type": "wpprobe",
                "category": "vuln/scan/wordpress",
                "description": "Fast wordpress plugin enumeration tool",
                "is_builtin": True,
                "is_active": True,
            },
            # URL/Crawl
            {
                "name": "Cariddi",
                "task_type": "cariddi",
                "category": "url/crawl",
                "description": "Crawl endpoints, secrets, api keys, extensions, tokens...",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Gospider",
                "task_type": "gospider",
                "category": "url/crawl",
                "description": "Fast web spider written in Go",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Katana",
                "task_type": "katana",
                "category": "url/crawl",
                "description": "Next-generation crawling and spidering framework",
                "is_builtin": True,
                "is_active": True,
            },
            # DNS/Fuzz
            {
                "name": "DNSx",
                "task_type": "dnsx",
                "category": "dns/fuzz",
                "description": "dnsx is a fast and multi-purpose DNS toolkit designed for running various retryabledns library",
                "is_builtin": True,
                "is_active": True,
            },
            # IP/Recon
            {
                "name": "FPing",
                "task_type": "fping",
                "category": "ip/recon",
                "description": "Send ICMP echo probes to network hosts, similar to ping, but much better",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "MapCIDR",
                "task_type": "mapcidr",
                "category": "ip/recon",
                "description": "Utility program to perform multiple operations for a given subnet/cidr ranges",
                "is_builtin": True,
                "is_active": True,
            },
            # Pattern/Scan
            {
                "name": "GAU",
                "task_type": "gau",
                "category": "pattern/scan",
                "description": "Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "GF",
                "task_type": "gf",
                "category": "pattern/scan",
                "description": "Wrapper around grep, to help you grep for things",
                "is_builtin": True,
                "is_active": True,
            },
            # Secret/Scan
            {
                "name": "Gitleaks",
                "task_type": "gitleaks",
                "category": "secret/scan",
                "description": "Tool for detecting secrets like passwords, API keys, and tokens in git repos, files, and stdin",
                "is_builtin": True,
                "is_active": True,
            },
            # User/Recon/Email
            {
                "name": "H8mail",
                "task_type": "h8mail",
                "category": "user/recon/email",
                "description": "Email information and password lookup tool",
                "is_builtin": True,
                "is_active": True,
            },
            # URL/Probe
            {
                "name": "HTTPx",
                "task_type": "httpx",
                "category": "url/probe",
                "description": "Fast and multi-purpose HTTP toolkit",
                "is_builtin": True,
                "is_active": True,
            },
            # User/Recon/Username
            {
                "name": "Maigret",
                "task_type": "maigret",
                "category": "user/recon/username",
                "description": "Collect a dossier on a person by username",
                "is_builtin": True,
                "is_active": True,
            },
            # Exploit/Attack
            {
                "name": "MSFConsole",
                "task_type": "msfconsole",
                "category": "exploit/attack",
                "description": "CLI to access and work with the Metasploit Framework",
                "is_builtin": True,
                "is_active": True,
            },
            # Port/Scan
            {
                "name": "Naabu",
                "task_type": "naabu",
                "category": "port/scan",
                "description": "Port scanning tool written in Go",
                "is_builtin": True,
                "is_active": True,
            },
            {
                "name": "Nmap",
                "task_type": "nmap",
                "category": "port/scan",
                "description": "Network Mapper is a free and open source utility for network discovery and security auditing",
                "is_builtin": True,
                "is_active": True,
            },
            # Exploit/Recon
            {
                "name": "SearchSploit",
                "task_type": "searchsploit",
                "category": "exploit/recon",
                "description": "Exploit searcher based on ExploitDB",
                "is_builtin": True,
                "is_active": True,
            },
            # DNS/Recon
            {
                "name": "Subfinder",
                "task_type": "subfinder",
                "category": "dns/recon",
                "description": "Fast passive subdomain enumeration tool",
                "is_builtin": True,
                "is_active": True,
            },
            # DNS/Recon/TLS
            {
                "name": "TestSSL",
                "task_type": "testssl",
                "category": "dns/recon/tls",
                "description": "SSL/TLS security scanner, including ciphers, protocols and cryptographic flaws",
                "is_builtin": True,
                "is_active": True,
            },
            # WAF/Scan
            {
                "name": "WAFW00F",
                "task_type": "wafw00f",
                "category": "waf/scan",
                "description": "Web Application Firewall Fingerprinting tool",
                "is_builtin": True,
                "is_active": True,
            },
        ]

        for task_data in default_tasks:
            task, created = SecatorTask.objects.get_or_create(name=task_data["name"], defaults=task_data)
            if created:
                self.stdout.write(f"  Created task: {task.name}")
            else:
                self.stdout.write(f"  Task already exists: {task.name}")

    def load_default_workflows(self):
        """Load default Secator workflows based on the available commands."""

        default_workflows = [
            {
                "name": "CIDR Recon",
                "alias": "cidr_recon",
                "description": "Local network recon",
                "workflow_type": "builtin",
                "scan_type": "internal_network",
                "yaml_configuration": "tasks:\n  - fping\n  - nmap\n  - naabu",
                "is_active": True,
            },
            {
                "name": "Code Scan",
                "alias": "code_scan",
                "description": "Code vulnerability scan",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - gitleaks\n  - grype\n  - trivy",
                "is_active": True,
            },
            {
                "name": "Host Recon",
                "alias": "host_recon",
                "description": "Host recon",
                "workflow_type": "builtin",
                "scan_type": "internal_network",
                "yaml_configuration": "tasks:\n  - nmap\n  - nuclei\n  - httpx",
                "is_active": True,
            },
            {
                "name": "Subdomain Recon",
                "alias": "subdomain_recon",
                "description": "Subdomain discovery",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - subfinder\n  - dnsx\n  - httpx",
                "is_active": True,
            },
            {
                "name": "URL Bypass",
                "alias": "url_bypass",
                "description": "Try bypass techniques for 4xx URLs",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - bup\n  - ffuf\n  - dirsearch",
                "is_active": True,
            },
            {
                "name": "URL Crawl",
                "alias": "url_crawl",
                "description": "URL crawl (fast)",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - katana\n  - gospider\n  - cariddi",
                "is_active": True,
            },
            {
                "name": "URL Directory Search",
                "alias": "url_dirsearch",
                "description": "URL directory search",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - dirsearch\n  - feroxbuster\n  - ffuf",
                "is_active": True,
            },
            {
                "name": "URL Fuzz",
                "alias": "url_fuzz",
                "description": "URL fuzz (slow)",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - ffuf\n  - arjun\n  - dalfox",
                "is_active": True,
            },
            {
                "name": "URL Parameters Fuzz",
                "alias": "url_params_fuzz",
                "description": "Extract parameters from an URL and fuzz them",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - arjun\n  - dalfox\n  - ffuf",
                "is_active": True,
            },
            {
                "name": "URL Vulnerability",
                "alias": "url_vuln",
                "description": "URL vulnerability scan (gf, dalfox)",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - gf\n  - dalfox\n  - nuclei",
                "is_active": True,
            },
            {
                "name": "User Hunt",
                "alias": "user_hunt",
                "description": "User account search",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - maigret\n  - h8mail\n  - gau",
                "is_active": True,
            },
            {
                "name": "WordPress",
                "alias": "wordpress",
                "description": "Wordpress vulnerability scan",
                "workflow_type": "builtin",
                "scan_type": "internet",
                "yaml_configuration": "tasks:\n  - wpscan\n  - wpprobe\n  - nuclei",
                "is_active": True,
            },
        ]

        for workflow_data in default_workflows:
            workflow, created = SecatorWorkflow.objects.get_or_create(
                name=workflow_data["name"], defaults=workflow_data
            )
            if created:
                self.stdout.write(f"  Created workflow: {workflow.name}")
            else:
                self.stdout.write(f"  Workflow already exists: {workflow.name}")

    def load_default_scans(self):
        """Load default Secator scan configurations based on the available scan types."""

        default_scans = [
            {
                "name": "Domain Scan",
                "description": "Comprehensive domain reconnaissance scan",
                "scan_type": "internet",
                "secator_scan_type": "domain",
                "execution_mode": "scan",
                "scan_config_type": "builtin",
                "is_default": True,
                "is_active": True,
            },
            {
                "name": "Host Scan",
                "description": "Host-based vulnerability and port scanning",
                "scan_type": "internal_network",
                "secator_scan_type": "host",
                "execution_mode": "scan",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            {
                "name": "Internal Network Scan",
                "description": "Internal network reconnaissance and scanning",
                "scan_type": "internal_network",
                "secator_scan_type": "network",
                "execution_mode": "scan",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            {
                "name": "Subdomain Discovery",
                "description": "Subdomain enumeration and discovery",
                "scan_type": "internet",
                "secator_scan_type": "subdomain",
                "execution_mode": "scan",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            {
                "name": "URL Scan",
                "description": "URL-based vulnerability scanning and enumeration",
                "scan_type": "internet",
                "secator_scan_type": "url",
                "execution_mode": "scan",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            # Workflow-based scan configurations
            {
                "name": "Internet Workflow Scan",
                "description": "Complete Internet reconnaissance using workflows",
                "scan_type": "internet",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            {
                "name": "Internal Network Workflow Scan",
                "description": "Internal network assessment using workflows",
                "scan_type": "internal_network",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            # Task-based scan configurations
            {
                "name": "Vulnerability Assessment",
                "description": "Focused vulnerability scanning using individual tasks",
                "scan_type": "internet",
                "execution_mode": "tasks",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
            {
                "name": "Network Reconnaissance",
                "description": "Network discovery and reconnaissance using individual tasks",
                "scan_type": "internal_network",
                "execution_mode": "tasks",
                "scan_config_type": "builtin",
                "is_default": False,
                "is_active": True,
            },
        ]

        for scan_data in default_scans:
            scan, created = SecatorScan.objects.get_or_create(name=scan_data["name"], defaults=scan_data)
            if created:
                self.stdout.write(f"  Created scan: {scan.name}")
            else:
                self.stdout.write(f"  Scan already exists: {scan.name}")
