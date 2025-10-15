# Generated manually for enhanced Secator models

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanEngine", "0011_add_is_legacy_to_enginetype"),
    ]

    operations = [
        # Add alias field to SecatorWorkflow
        migrations.AddField(
            model_name="secatorworkflow",
            name="alias",
            field=models.CharField(
                blank=True,
                choices=[
                    ("cidr_recon", "CIDR Recon"),
                    ("code_scan", "Code Scan"),
                    ("host_recon", "Host Recon"),
                    ("subdomain_recon", "Subdomain Recon"),
                    ("url_bypass", "URL Bypass"),
                    ("url_crawl", "URL Crawl"),
                    ("url_dirsearch", "URL Directory Search"),
                    ("url_fuzz", "URL Fuzz"),
                    ("url_params_fuzz", "URL Parameters Fuzz"),
                    ("url_vuln", "URL Vulnerability"),
                    ("user_hunt", "User Hunt"),
                    ("wordpress", "WordPress"),
                ],
                help_text="Built-in workflow alias from Secator",
                max_length=50,
                null=True,
            ),
        ),
        # Add category field to SecatorTask
        migrations.AddField(
            model_name="secatortask",
            name="category",
            field=models.CharField(
                blank=True,
                choices=[
                    ("url/fuzz/params", "URL/Fuzz/Params"),
                    ("vuln/scan", "Vulnerability Scan"),
                    ("url/bypass", "URL Bypass"),
                    ("url/crawl", "URL Crawl"),
                    ("url/fuzz", "URL Fuzz"),
                    ("dns/fuzz", "DNS Fuzz"),
                    ("ip/recon", "IP Recon"),
                    ("pattern/scan", "Pattern Scan"),
                    ("secret/scan", "Secret Scan"),
                    ("user/recon/email", "User Recon/Email"),
                    ("url/probe", "URL Probe"),
                    ("user/recon/username", "User Recon/Username"),
                    ("exploit/attack", "Exploit/Attack"),
                    ("port/scan", "Port Scan"),
                    ("exploit/recon", "Exploit/Recon"),
                    ("dns/recon", "DNS Recon"),
                    ("dns/recon/tls", "DNS Recon/TLS"),
                    ("waf/scan", "WAF Scan"),
                    ("vuln/scan/wordpress", "Vulnerability Scan/WordPress"),
                ],
                help_text="Category of the task",
                max_length=50,
                null=True,
            ),
        ),
        # Add is_active field to SecatorTask
        migrations.AddField(
            model_name="secatortask",
            name="is_active",
            field=models.BooleanField(
                default=True,
                help_text="Whether this task is available for use",
            ),
        ),
        # Change is_builtin default to True for SecatorTask
        migrations.AlterField(
            model_name="secatortask",
            name="is_builtin",
            field=models.BooleanField(
                default=True,
                help_text="Whether this is a built-in Secator task",
            ),
        ),
        # Make name unique for SecatorTask
        migrations.AlterField(
            model_name="secatortask",
            name="name",
            field=models.CharField(max_length=200, unique=True),
        ),
        # Add secator_scan_type field to SecatorScan
        migrations.AddField(
            model_name="secatorscan",
            name="secator_scan_type",
            field=models.CharField(
                blank=True,
                choices=[
                    ("domain", "Domain Scan"),
                    ("host", "Host Scan"),
                    ("network", "Internal Network Scan"),
                    ("subdomain", "Subdomain Scan"),
                    ("url", "URL Scan"),
                ],
                help_text="Secator scan type (domain, host, network, subdomain, url)",
                max_length=20,
                null=True,
            ),
        ),
        # Add is_active field to SecatorScan
        migrations.AddField(
            model_name="secatorscan",
            name="is_active",
            field=models.BooleanField(
                default=True,
                help_text="Whether this scan configuration is available for use",
            ),
        ),
        # Add scan mode to execution_mode choices
        migrations.AlterField(
            model_name="secatorscan",
            name="execution_mode",
            field=models.CharField(
                choices=[
                    ("workflow", "Workflow"),
                    ("tasks", "Individual Tasks"),
                    ("scan", "Scan Type"),
                ],
                default="workflow",
                help_text="Whether to run a workflow, individual tasks, or a scan type",
                max_length=20,
            ),
        ),
        # Remove unique_together constraint from SecatorTask
        migrations.AlterUniqueTogether(
            name="secatortask",
            unique_together=set(),
        ),
    ]
