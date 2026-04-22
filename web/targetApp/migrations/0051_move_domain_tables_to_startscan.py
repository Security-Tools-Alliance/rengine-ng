# Dev notes: Move domain/WHOIS tables from targetApp to startScan (DB rename only in this step).
# - Before: Tables targetapp_domain, targetapp_domaininfo, etc. Domain models live in targetApp state.
# - This migration: renames tables to startScan_* (AlterModelTable); removes domain/WHOIS models from targetApp state (DeleteModel).
#   Through tables renamed only if they exist. Organization.domains M2M removed.
# - After: startScan 0101 adds the same models to startScan state (state only, no DB create). Order: 0049 -> 0050 -> startScan 0099 -> 0051 -> startScan 0101.
# - targetApp 0051 must run after startScan 0099: older startScan migrations reference targetApp.domain in FK state; 0051 removes Domain from targetApp state.

from django.db import migrations


def _op_rename_and_delete(model_name: str, new_table: str):
    return migrations.SeparateDatabaseAndState(
        database_operations=[
            migrations.AlterModelTable(model_name, new_table),
        ],
        state_operations=[
            migrations.DeleteModel(model_name),
        ],
    )


def _op_rename_table_only(old_table: str, new_table: str):
    """Rename table in DB only if it exists (through tables may be missing in some DBs)."""
    return migrations.RunSQL(
        sql=(
            f"DO $migrate$\n"
            f"BEGIN\n"
            f"  IF EXISTS (\n"
            f"    SELECT 1 FROM information_schema.tables\n"
            f"    WHERE table_schema = current_schema() AND table_name = '{old_table}'\n"
            f"  ) THEN\n"
            f"    EXECUTE format('ALTER TABLE %I RENAME TO %I', '{old_table}', '{new_table}');\n"
            f"  END IF;\n"
            f"END $migrate$;"
        ),
        reverse_sql=(
            f"DO $migrate$\n"
            f"BEGIN\n"
            f"  IF EXISTS (\n"
            f"    SELECT 1 FROM information_schema.tables\n"
            f"    WHERE table_schema = current_schema() AND table_name = '{new_table}'\n"
            f"  ) THEN\n"
            f"    EXECUTE format('ALTER TABLE %I RENAME TO %I', '{new_table}', '{old_table}');\n"
            f"  END IF;\n"
            f"END $migrate$;"
        ),
    )


class Migration(migrations.Migration):
    dependencies = [
        ("targetApp", "0050_backfill_target_from_domain"),
        ("startScan", "0099_add_scan_history_target_fk"),
    ]

    operations = [
        migrations.RemoveField(model_name="organization", name="domains"),
        _op_rename_and_delete("HistoricalIP", "startScan_historicalip"),
        _op_rename_and_delete("RelatedDomain", "startScan_relateddomain"),
        _op_rename_and_delete("Registrar", "startScan_registrar"),
        _op_rename_and_delete("DomainRegistration", "startScan_domainregistration"),
        _op_rename_and_delete("WhoisStatus", "startScan_whoisstatus"),
        _op_rename_and_delete("NameServer", "startScan_nameserver"),
        _op_rename_and_delete("DNSRecord", "startScan_dnsrecord"),
        # Through tables use Django default names (model name lowercased, no extra underscores)
        _op_rename_table_only("targetapp_domaininfostatusthrough", "startScan_domaininfo_status"),
        _op_rename_table_only("targetapp_domaininfonameserversthrough", "startScan_domaininfo_name_servers"),
        _op_rename_table_only("targetapp_domaininfodnsrecordsthrough", "startScan_domaininfo_dns_records"),
        _op_rename_table_only("targetapp_domaininforelateddomainsthrough", "startScan_domaininfo_related_domains"),
        _op_rename_table_only("targetapp_domaininforelatedtldsthrough", "startScan_domaininfo_related_tlds"),
        _op_rename_table_only("targetapp_domaininfosimilardomainsthrough", "startScan_domaininfo_similar_domains"),
        _op_rename_table_only("targetapp_domaininfohistoricalipsthrough", "startScan_domaininfo_historical_ips"),
        _op_rename_and_delete("DomainInfo", "startScan_domaininfo"),
        _op_rename_and_delete("Domain", "startScan_domain"),
    ]
