"""
Django management command to load Secator profiles into the database.
"""

import os

from django.conf import settings
from secator.loader import get_configs_by_type
import yaml

from scanEngine.models import SecatorProfile

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator profiles into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--builtin-only",
            action="store_true",
            help="Load only built-in profiles",
        )
        parser.add_argument(
            "--custom-only",
            action="store_true",
            help="Load only custom profiles",
        )

    def handle(self, *args, **options):
        builtin_only = options["builtin_only"]
        custom_only = options["custom_only"]

        self.stdout.write("Loading Secator profiles...")

        if not custom_only:
            self.load_builtin_profiles()

        if not builtin_only:
            self.load_custom_profiles()

        self.stdout.write(self.style.SUCCESS("Profile loading completed successfully!"))

    def load_builtin_profiles(self):
        """Load built-in Secator profiles"""
        self.stdout.write("Loading built-in Secator profiles...")

        created_count = 0
        updated_count = 0
        failed_count = 0

        try:
            # Get profiles directly from secator library
            profiles = get_configs_by_type("profile")

            if not profiles:
                self.stdout.write(self.style.WARNING("No profiles found in secator"))
                return

            for profile_loader in profiles:
                try:
                    # Extract profile information from TemplateLoader
                    profile_name = profile_loader.name
                    profile_description = getattr(profile_loader, "description", "") or ""
                    profile_path = getattr(profile_loader, "_path", None)

                    if not profile_path:
                        self.stdout.write(self.style.WARNING(f"Profile {profile_name} has no path, skipping"))
                        failed_count += 1
                        continue

                    # Read YAML configuration from file
                    try:
                        with open(profile_path, "r", encoding="utf-8") as f:
                            yaml_config = f.read()
                    except (OSError, IOError) as e:
                        # I/O-related issues (missing file, permission error, etc.) are expected
                        self.stdout.write(
                            self.style.ERROR(
                                f"Failed to read YAML file for profile {profile_name} at {profile_path}: {e}"
                            )
                        )
                        failed_count += 1
                        continue
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Failed to read YAML file for profile {profile_name}: {e}"))
                        failed_count += 1
                        continue

                    # Parse YAML to extract metadata
                    try:
                        profile_data = yaml.safe_load(yaml_config)
                    except yaml.YAMLError as e:
                        self.stdout.write(self.style.ERROR(f"Invalid YAML for profile {profile_name}: {e}"))
                        failed_count += 1
                        continue

                    if not profile_data:
                        self.stdout.write(self.style.WARNING(f"Empty YAML for profile: {profile_name}"))
                        failed_count += 1
                        continue

                    # Extract profile fields
                    name = profile_data.get("name", profile_name)
                    category = profile_data.get("category", "general")
                    description = profile_data.get("description", profile_description) or f"Built-in {name}"
                    enforce = profile_data.get("enforce", False)
                    opts = profile_data.get("opts", {})

                    # Convert opts dict to YAML string
                    opts_yaml = yaml.dump(opts, default_flow_style=False) if opts else ""

                    # Define default profiles for each category (only set on first creation)
                    default_profiles = {
                        "speed": "polite",
                        "evasion": "stealth",
                        "general": "full",
                        "network": "all_ports",
                    }

                    # Check if this profile should be default (only on first creation)
                    should_be_default = (
                        name == default_profiles.get(category) and not SecatorProfile.objects.filter(name=name).exists()
                    )

                    # Use profile_loader.name directly as name (unique identifier for Secator)
                    profile, created = SecatorProfile.objects.get_or_create(
                        name=name,
                        defaults={
                            "category": category,
                            "description": description,
                            "enforce": enforce,
                            "opts": opts_yaml,
                            "profile_type": "builtin",
                            "is_active": True,
                            "is_default": should_be_default,
                        },
                    )

                    if created:
                        # For built-in profiles, use bypass_builtin_constraints to allow save
                        profile.save(bypass_builtin_constraints=True)
                        created_count += 1
                        default_msg = " (set as default)" if should_be_default else ""
                        self.stdout.write(f"Created built-in profile: {name}{default_msg}")
                    else:
                        # Update existing profile using update() to bypass save() constraints
                        # Do NOT modify is_default field on updates
                        SecatorProfile.objects.filter(pk=profile.pk).update(
                            category=category,
                            description=description,
                            enforce=enforce,
                            opts=opts_yaml,
                        )
                        updated_count += 1
                        self.stdout.write(f"Updated built-in profile: {name}")

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Error processing profile {getattr(profile_loader, 'name', 'unknown')}: {e}")
                    )
                    failed_count += 1

            self.stdout.write(
                f"Loaded {created_count} new built-in profiles, updated {updated_count} existing profiles"
            )
            if failed_count > 0:
                self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} profiles"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get profiles from secator: {e}"))

    def load_custom_profiles(self):
        """Load custom profiles from config/profiles/ directory"""
        self.stdout.write("Loading custom profiles...")

        profiles_dir = os.path.join(settings.BASE_DIR, "config", "profiles")

        if not os.path.exists(profiles_dir):
            self.stdout.write(self.style.WARNING(f"Profiles directory not found: {profiles_dir}"))
            return

        created_count = 0
        updated_count = 0
        for filename in sorted(os.listdir(profiles_dir)):
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue

            filepath = os.path.join(profiles_dir, filename)

            try:
                with open(filepath, "r") as f:
                    profile_data = yaml.safe_load(f)

                if not profile_data or "name" not in profile_data:
                    self.stdout.write(self.style.WARNING(f"Invalid profile file: {filename}"))
                    continue

                profile_name = profile_data["name"]
                category = profile_data.get("category", "general")
                description = profile_data.get("description", "")
                enforce = profile_data.get("enforce", False)
                opts = profile_data.get("opts", {})

                # Convert opts dict to YAML string
                opts_yaml = yaml.dump(opts, default_flow_style=False) if opts else ""

                profile, created = SecatorProfile.objects.get_or_create(
                    name=profile_name,
                    profile_type="custom",
                    defaults={
                        "category": category,
                        "description": description,
                        "enforce": enforce,
                        "opts": opts_yaml,
                        "is_active": True,
                    },
                )

                if created:
                    # Custom profiles don't need bypass_builtin_constraints
                    profile.save()
                    created_count += 1
                    self.stdout.write(f"Created custom profile: {profile_name}")
                else:
                    # Always update existing custom profiles using update()
                    SecatorProfile.objects.filter(pk=profile.pk).update(
                        category=category,
                        description=description,
                        enforce=enforce,
                        opts=opts_yaml,
                    )
                    updated_count += 1
                    self.stdout.write(f"Updated custom profile: {profile_name}")

            except FileNotFoundError:
                self.stdout.write(self.style.ERROR(f"Profile file not found: {filename}"))
            except PermissionError:
                self.stdout.write(self.style.ERROR(f"Permission denied reading profile file: {filename}"))
            except yaml.YAMLError as e:
                self.stdout.write(self.style.ERROR(f"Invalid YAML syntax in profile file {filename}: {e}"))
            except UnicodeDecodeError as e:
                self.stdout.write(self.style.ERROR(f"Encoding error in profile file {filename}: {e}"))
            except KeyError as e:
                self.stdout.write(self.style.ERROR(f"Missing required field in profile file {filename}: {e}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Unexpected error loading profile {filename}: {e}"))

        self.stdout.write(
            f"Loaded {created_count} new custom profiles, updated {updated_count} existing custom profiles"
        )

    def _extract_all_opts(self):
        """
        Extract all unique opts keys from all built-in profiles, grouped by category.
        Returns a YAML-formatted string with options organized by category and comments.
        """
        # Define option descriptions based on documentation
        option_descriptions = {
            # Speed options
            "rate_limit": "Requests per second (higher = faster, lower = more respectful)",
            "delay": "Delay between requests in seconds",
            "timeout": "Request timeout in seconds",
            "retries": "Number of retries on failure",
            # Evasion options
            "fragment": "Enable packet fragmentation (IDS/IPS evasion)",
            "nmap_light_fragment": "Enable light packet fragmentation for nmap",
            "tcp_syn_stealth": "Use TCP SYN stealth scanning",
            "nmap_light_tcp_syn_stealth": "Use TCP SYN stealth for nmap light",
            "scan_type": "Nmap scan type (s = SYN, T = TCP, etc.)",
            "proxy": "Proxy configuration (auto, tor, or custom proxy URL)",
            # General options
            "active": "Enable active scanning only (no passive sources)",
            "passive": "Enable passive scanning only (no requests to targets)",
            "domain_recon_active": "Active mode for domain reconnaissance",
            "domain_recon_passive": "Passive mode for domain reconnaissance",
            "subdomain_recon_active": "Active mode for subdomain reconnaissance",
            "subdomain_recon_passive": "Passive mode for subdomain reconnaissance",
            "host_recon_active": "Active mode for host reconnaissance",
            "host_recon_passive": "Passive mode for host reconnaissance",
            "url_crawl_active": "Active mode for URL crawling",
            "url_crawl_passive": "Passive mode for URL crawling",
            "url_vuln_active": "Active mode for URL vulnerability scanning",
            "url_vuln_passive": "Passive mode for URL vulnerability scanning",
            # Network options
            "ports": 'Port range to scan ("-" = all ports, "80,443" = specific ports)',
            "host_recon_nmap_ports": "Port range for nmap in host recon",
            # Task options
            "headless": "Enable headless browser mode (for JavaScript rendering)",
            "system_chrome": "Use system Chrome instead of bundled version",
            "no_sandbox": "Disable Chrome sandbox (required in some environments)",
            "screenshot": "Take screenshots of web pages",
            "juicy_extensions": "Number of juicy file extensions to check (cariddi)",
            "server_defaults": "Use default server names for SSL testing (testssl)",
            # Workflow options
            "nuclei": "Enable Nuclei vulnerability scanning",
            "brute_dns": "Enable DNS brute forcing",
            "brute_http": "Enable HTTP brute forcing",
            "hunt_secrets": "Enable secret hunting",
            "test_ssl": "Enable SSL/TLS testing",
            # Scan options
            "host_recon_nuclei": "Enable Nuclei in host reconnaissance",
            "domain_recon_testssl_server_defaults": "Server defaults for testssl in domain recon",
            "subdomain_recon_hunt_secrets": "Enable secret hunting in subdomain recon",
            "subdomain_recon_test_ssl": "Enable SSL testing in subdomain recon",
            "subdomain_recon_testssl_server_defaults": "Server defaults for testssl in subdomain recon",
            "url_crawl_hunt_secrets": "Enable secret hunting in URL crawling",
            "url_vuln_nuclei": "Enable Nuclei in URL vulnerability scanning",
            "url_crawl_cariddi_juicy_extensions": "Number of juicy extensions for cariddi in URL crawl",
        }

        # Define category mappings for options
        category_mappings = {
            "speed": ["rate_limit", "delay", "timeout", "retries"],
            "evasion": [
                "fragment",
                "nmap_light_fragment",
                "tcp_syn_stealth",
                "nmap_light_tcp_syn_stealth",
                "scan_type",
                "proxy",
            ],
            "general": [
                "active",
                "passive",
                "domain_recon_active",
                "domain_recon_passive",
                "subdomain_recon_active",
                "subdomain_recon_passive",
                "host_recon_active",
                "host_recon_passive",
                "url_crawl_active",
                "url_crawl_passive",
                "url_vuln_active",
                "url_vuln_passive",
            ],
            "network": [
                "ports",
                "host_recon_nmap_ports",
                "headless",
                "system_chrome",
                "no_sandbox",
                "screenshot",
                "juicy_extensions",
                "server_defaults",
                "nuclei",
                "brute_dns",
                "brute_http",
                "hunt_secrets",
                "test_ssl",
                "host_recon_nuclei",
                "domain_recon_testssl_server_defaults",
                "subdomain_recon_hunt_secrets",
                "subdomain_recon_test_ssl",
                "subdomain_recon_testssl_server_defaults",
                "url_crawl_hunt_secrets",
                "url_vuln_nuclei",
                "url_crawl_cariddi_juicy_extensions",
            ],
        }

        try:
            profiles = get_configs_by_type("profile")
            all_opts_by_category = {
                "speed": {},
                "evasion": {},
                "general": {},
                "network": {},
            }

            for profile_loader in profiles:
                profile_path = getattr(profile_loader, "_path", None)
                if not profile_path:
                    continue

                try:
                    with open(profile_path, "r", encoding="utf-8") as f:
                        profile_data = yaml.safe_load(f)

                    if profile_data and "opts" in profile_data:
                        opts = profile_data["opts"]
                        if isinstance(opts, dict):
                            # Determine which category this profile belongs to
                            profile_category = profile_data.get("category", "general")

                            # Collect all keys and their values
                            for key, value in opts.items():
                                # Find the category for this option
                                option_category = None
                                for cat, keys in category_mappings.items():
                                    if key in keys:
                                        option_category = cat
                                        break

                                # If not found in mappings, use profile category
                                if option_category is None:
                                    option_category = profile_category

                                # Store the first non-None value encountered for each key
                                if key not in all_opts_by_category[option_category] or (
                                    all_opts_by_category[option_category][key] is None and value is not None
                                ):
                                    all_opts_by_category[option_category][key] = value

                except Exception:
                    # Skip profiles that can't be read
                    continue

            # Build YAML string with categories and comments
            yaml_lines = []
            category_order = ["speed", "evasion", "general", "network"]
            category_titles = {
                "speed": "Speed options",
                "evasion": "Evasion options",
                "general": "General options",
                "network": "Network & Feature options",
            }

            for category in category_order:
                opts_dict = all_opts_by_category[category]
                if opts_dict:
                    yaml_lines.append(f"# {category_titles[category]}")
                    for key, value in sorted(opts_dict.items()):
                        # Format value appropriately for YAML
                        if value is None:
                            value_str = "null"
                        elif isinstance(value, bool):
                            # YAML uses lowercase true/false
                            value_str = "true" if value else "false"
                        elif isinstance(value, (int, float)):
                            value_str = str(value)
                        elif isinstance(value, str):
                            # Only quote if it contains special characters or starts with number
                            if value in ["-", "null", "true", "false"] or value.startswith(("-", "+")):
                                value_str = f'"{value}"'
                            else:
                                value_str = value
                        else:
                            value_str = yaml.dump(value, default_flow_style=True).strip()

                        # Add comment if available
                        comment = option_descriptions.get(key, "")
                        if comment:
                            yaml_lines.append(f"{key}: {value_str}  # {comment}")
                        else:
                            yaml_lines.append(f"{key}: {value_str}")
                    yaml_lines.append("")  # Empty line between categories

            return "\n".join(yaml_lines).strip()

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error extracting opts: {e}"))
            return ""
