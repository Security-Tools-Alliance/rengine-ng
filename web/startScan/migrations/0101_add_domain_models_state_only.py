# Migration order and recovery: see wiki install-migrations.md.
# Dev notes: Domain/WHOIS migration from targetApp to startScan (state only).
# - Before: targetApp 0051 has renamed domain tables to startScan_* and removed domain models from targetApp state.
# - This migration: adds startScan domain/WHOIS models in state only (SeparateDatabaseAndState); no DB changes.
#   Repoints all FKs that pointed to targetApp.domain to startScan.domain. Tables already exist as startScan_*.
# - Upgrade path: run targetApp 0049 -> 0050 -> 0051 first; then this migration (0101). Follow with 0104 -> 0105 -> 0106 -> ... -> 0109.
# - State operations (AlterField) reference the schema as it was at 0101: ScanHistory.domain, Subdomain.target_domain,
#   ScanSchedule.domain, etc. exist at this point; they are removed or renamed in later migrations (0102, 0103).
#   Run migrations in order; do not run 0101 against a DB built from current models only.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("startScan", "0099_add_scan_history_target_fk"),
        ("targetApp", "0051_move_domain_tables_to_startscan"),
        ("dashboard", "0019_user_preference"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name="HistoricalIP",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("ip", models.CharField(max_length=150)),
                        ("location", models.CharField(max_length=500)),
                        ("owner", models.CharField(max_length=500)),
                        ("last_seen", models.CharField(max_length=500)),
                    ],
                    options={"db_table": "startScan_historicalip", "managed": False},
                ),
                migrations.CreateModel(
                    name="RelatedDomain",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(max_length=250)),
                    ],
                    options={"db_table": "startScan_relateddomain", "managed": False},
                ),
                migrations.CreateModel(
                    name="Registrar",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(blank=True, max_length=500, null=True)),
                        ("phone", models.CharField(blank=True, max_length=150, null=True)),
                        ("email", models.CharField(blank=True, max_length=350, null=True)),
                        ("url", models.CharField(blank=True, max_length=1000, null=True)),
                        ("address", models.CharField(blank=True, max_length=1000, null=True)),
                        ("country", models.CharField(blank=True, max_length=100, null=True)),
                        ("fax", models.CharField(blank=True, max_length=150, null=True)),
                    ],
                    options={"db_table": "startScan_registrar", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainRegistration",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(blank=True, max_length=500, null=True)),
                        ("organization", models.CharField(blank=True, max_length=500, null=True)),
                        ("contact", models.CharField(blank=True, max_length=500, null=True)),
                        ("type", models.CharField(blank=True, max_length=100, null=True)),
                        ("address", models.CharField(blank=True, max_length=500, null=True)),
                        ("city", models.CharField(blank=True, max_length=100, null=True)),
                        ("state", models.CharField(blank=True, max_length=100, null=True)),
                        ("zip_code", models.CharField(blank=True, max_length=100, null=True)),
                        ("country", models.CharField(blank=True, max_length=100, null=True)),
                        ("email", models.CharField(blank=True, max_length=500, null=True)),
                        ("phone", models.CharField(blank=True, max_length=150, null=True)),
                        ("fax", models.CharField(blank=True, max_length=150, null=True)),
                        ("id_str", models.CharField(blank=True, max_length=500, null=True)),
                    ],
                    options={"db_table": "startScan_domainregistration", "managed": False},
                ),
                migrations.CreateModel(
                    name="WhoisStatus",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(max_length=500)),
                    ],
                    options={"db_table": "startScan_whoisstatus", "managed": False},
                ),
                migrations.CreateModel(
                    name="NameServer",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(max_length=500)),
                    ],
                    options={"db_table": "startScan_nameserver", "managed": False},
                ),
                migrations.CreateModel(
                    name="DNSRecord",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.TextField()),
                        ("type", models.CharField(max_length=50)),
                        ("extra_data", models.JSONField(blank=True, null=True)),
                    ],
                    options={"db_table": "startScan_dnsrecord", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfo",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("dnssec", models.BooleanField(default=False)),
                        ("created", models.DateTimeField(blank=True, null=True)),
                        ("updated", models.DateTimeField(blank=True, null=True)),
                        ("expires", models.DateTimeField(blank=True, null=True)),
                        ("geolocation_iso", models.CharField(blank=True, max_length=10, null=True)),
                        ("whois_server", models.CharField(blank=True, max_length=150, null=True)),
                        ("extra_data", models.JSONField(blank=True, null=True)),
                        (
                            "registrar",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                to="startScan.registrar",
                            ),
                        ),
                        (
                            "registrant",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="registrant",
                                to="startScan.domainregistration",
                            ),
                        ),
                        (
                            "admin",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="admin",
                                to="startScan.domainregistration",
                            ),
                        ),
                        (
                            "tech",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="tech",
                                to="startScan.domainregistration",
                            ),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoStatusThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "whoisstatus",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.whoisstatus"),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_status", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoNameServersThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "nameserver",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.nameserver"),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_name_servers", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoDnsRecordsThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "dnsrecord",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.dnsrecord"),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_dns_records", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoRelatedDomainsThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "relateddomain",
                            models.ForeignKey(
                                on_delete=django.db.models.deletion.CASCADE, to="startScan.relateddomain"
                            ),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_related_domains", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoRelatedTldsThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "relateddomain",
                            models.ForeignKey(
                                on_delete=django.db.models.deletion.CASCADE, to="startScan.relateddomain"
                            ),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_related_tlds", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoSimilarDomainsThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "relateddomain",
                            models.ForeignKey(
                                on_delete=django.db.models.deletion.CASCADE, to="startScan.relateddomain"
                            ),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_similar_domains", "managed": False},
                ),
                migrations.CreateModel(
                    name="DomainInfoHistoricalIpsThrough",
                    fields=[
                        ("id", models.BigAutoField(primary_key=True, serialize=False)),
                        (
                            "domaininfo",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domaininfo"),
                        ),
                        (
                            "historicalip",
                            models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.historicalip"),
                        ),
                    ],
                    options={"db_table": "startScan_domaininfo_historical_ips", "managed": False},
                ),
                migrations.CreateModel(
                    name="Domain",
                    fields=[
                        ("id", models.AutoField(primary_key=True, serialize=False)),
                        ("name", models.CharField(max_length=300, unique=True)),
                        ("h1_team_handle", models.CharField(blank=True, max_length=100, null=True)),
                        ("ip_address_cidr", models.CharField(blank=True, max_length=100, null=True)),
                        ("description", models.TextField(blank=True, null=True)),
                        ("insert_date", models.DateTimeField(null=True)),
                        ("start_scan_date", models.DateTimeField(null=True)),
                        ("request_headers", models.JSONField(blank=True, null=True)),
                        ("custom_dns_servers", models.CharField(blank=True, max_length=500, null=True)),
                        (
                            "domain_info",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                to="startScan.domaininfo",
                            ),
                        ),
                        (
                            "project",
                            models.ForeignKey(
                                blank=False,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="startscan_domains",
                                to="dashboard.project",
                            ),
                        ),
                        (
                            "target",
                            models.ForeignKey(
                                blank=True,
                                null=True,
                                on_delete=django.db.models.deletion.SET_NULL,
                                related_name="startscan_domain_set",
                                to="targetApp.target",
                            ),
                        ),
                    ],
                    options={"db_table": "startScan_domain", "managed": False},
                ),
                migrations.AlterField(
                    model_name="scanhistory",
                    name="domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scan_histories",
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="subdomain",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="endpoint",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="vulnerability",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="employee",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="exploit",
                    name="target_domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="certificate",
                    name="domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="secatorrunner",
                    name="domain",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="startScan.domain",
                    ),
                ),
                migrations.AlterField(
                    model_name="scanschedule",
                    name="domain",
                    field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="startScan.domain"),
                ),
            ],
            database_operations=[],
        ),
    ]
