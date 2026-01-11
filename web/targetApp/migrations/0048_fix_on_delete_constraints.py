# Generated manually to fix on_delete constraints

from django.db import migrations
from psycopg2.extensions import quote_ident


def get_table_name(apps, app_label, model_name):
    """Get the actual database table name for a model."""
    model = apps.get_model(app_label, model_name)
    return model._meta.db_table


def resolve_actual_table_name(schema_editor, table_name):
    """Resolve the actual table name from PostgreSQL, handling case sensitivity."""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
            AND LOWER(tablename) = LOWER(%s)
            LIMIT 1
            """,
            [table_name],
        )
        result = cursor.fetchone()
        return result[0] if result else None


def get_constraint_name(schema_editor, actual_table_name, column_name, actual_ref_table_name):
    """Get the foreign key constraint name for a given table and column.

    Uses the actual table names from the database to find the constraint,
    handling cases where Django truncates constraint names.
    """
    with schema_editor.connection.cursor() as cursor:
        # Find the constraint using the actual table names
        cursor.execute(
            """
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
            JOIN pg_class rt ON rt.oid = c.confrelid
            WHERE t.relname = %s
            AND rt.relname = %s
            AND c.contype = 'f'
            AND a.attname = %s
            LIMIT 1
            """,
            [actual_table_name, actual_ref_table_name, column_name],
        )
        result = cursor.fetchone()
        return result[0] if result else None


def fix_constraint(
    apps, schema_editor, table_name, column_name, referenced_table, referenced_column="id", on_delete="SET NULL"
):
    """Fix a foreign key constraint by changing its on_delete behavior."""
    # Resolve actual table names from PostgreSQL
    actual_table_name = resolve_actual_table_name(schema_editor, table_name)
    if not actual_table_name:
        return

    actual_ref_table_name = resolve_actual_table_name(schema_editor, referenced_table)
    if not actual_ref_table_name:
        return

    # Get the actual constraint name from the database using resolved table names
    constraint_name = get_constraint_name(schema_editor, actual_table_name, column_name, actual_ref_table_name)

    if constraint_name:
        # Safely quote all identifiers
        quoted_table_name = quote_ident(actual_table_name, schema_editor.connection.connection)
        quoted_column_name = quote_ident(column_name, schema_editor.connection.connection)
        quoted_ref_table_name = quote_ident(actual_ref_table_name, schema_editor.connection.connection)
        quoted_ref_column = quote_ident(referenced_column, schema_editor.connection.connection)
        quoted_constraint_name = quote_ident(constraint_name, schema_editor.connection.connection)

        # Drop existing constraint using actual table name
        schema_editor.execute(f"ALTER TABLE {quoted_table_name} DROP CONSTRAINT {quoted_constraint_name};")
        # Add new constraint with specified on_delete using actual table names
        schema_editor.execute(
            f"ALTER TABLE {quoted_table_name} ADD CONSTRAINT {quoted_constraint_name} "
            f"FOREIGN KEY ({quoted_column_name}) REFERENCES {quoted_ref_table_name}({quoted_ref_column}) ON DELETE {on_delete};"
        )


def fix_all_targetapp_constraints(apps, schema_editor):
    """Fix all on_delete constraints in targetApp models."""
    # Get actual table names from Django metadata
    domain_table = get_table_name(apps, "targetApp", "Domain")
    domaininfo_table = get_table_name(apps, "targetApp", "DomainInfo")
    organization_table = get_table_name(apps, "targetApp", "Organization")
    project_table = get_table_name(apps, "dashboard", "Project")
    registrar_table = get_table_name(apps, "targetApp", "Registrar")
    domainregistration_table = get_table_name(apps, "targetApp", "DomainRegistration")

    # Domain.domain_info → DomainInfo : SET_NULL (relation optionnelle)
    fix_constraint(apps, schema_editor, domain_table, "domain_info_id", domaininfo_table, on_delete="SET NULL")

    # Domain.project → Project : CASCADE (relation forte - si Project supprimé, Domain supprimé)
    fix_constraint(apps, schema_editor, domain_table, "project_id", project_table, on_delete="CASCADE")

    # Organization.project → Project : CASCADE (relation forte - si Project supprimé, Organization supprimé)
    fix_constraint(apps, schema_editor, organization_table, "project_id", project_table, on_delete="CASCADE")

    # DomainInfo.registrar → Registrar : SET_NULL (relation optionnelle, null=True)
    fix_constraint(apps, schema_editor, domaininfo_table, "registrar_id", registrar_table, on_delete="SET NULL")

    # DomainInfo.registrant → DomainRegistration : SET_NULL (relation optionnelle, null=True)
    fix_constraint(
        apps, schema_editor, domaininfo_table, "registrant_id", domainregistration_table, on_delete="SET NULL"
    )

    # DomainInfo.admin → DomainRegistration : SET_NULL (relation optionnelle, null=True)
    fix_constraint(apps, schema_editor, domaininfo_table, "admin_id", domainregistration_table, on_delete="SET NULL")

    # DomainInfo.tech → DomainRegistration : SET_NULL (relation optionnelle, null=True)
    fix_constraint(apps, schema_editor, domaininfo_table, "tech_id", domainregistration_table, on_delete="SET NULL")


def reverse_fix_all_targetapp_constraints(apps, schema_editor):
    """Reverse: Change all on_delete constraints back to their original values."""
    # Get actual table names from Django metadata
    domain_table = get_table_name(apps, "targetApp", "Domain")
    domaininfo_table = get_table_name(apps, "targetApp", "DomainInfo")
    organization_table = get_table_name(apps, "targetApp", "Organization")
    project_table = get_table_name(apps, "dashboard", "Project")
    registrar_table = get_table_name(apps, "targetApp", "Registrar")
    domainregistration_table = get_table_name(apps, "targetApp", "DomainRegistration")

    # Domain.domain_info → DomainInfo : CASCADE (reverse)
    fix_constraint(apps, schema_editor, domain_table, "domain_info_id", domaininfo_table, on_delete="CASCADE")

    # Domain.project → Project : CASCADE (reverse - reste CASCADE)
    fix_constraint(apps, schema_editor, domain_table, "project_id", project_table, on_delete="CASCADE")

    # Organization.project → Project : CASCADE (reverse - reste CASCADE)
    fix_constraint(apps, schema_editor, organization_table, "project_id", project_table, on_delete="CASCADE")

    # DomainInfo.registrar → Registrar : CASCADE (reverse)
    fix_constraint(apps, schema_editor, domaininfo_table, "registrar_id", registrar_table, on_delete="CASCADE")

    # DomainInfo.registrant → DomainRegistration : CASCADE (reverse)
    fix_constraint(
        apps, schema_editor, domaininfo_table, "registrant_id", domainregistration_table, on_delete="CASCADE"
    )

    # DomainInfo.admin → DomainRegistration : CASCADE (reverse)
    fix_constraint(apps, schema_editor, domaininfo_table, "admin_id", domainregistration_table, on_delete="CASCADE")

    # DomainInfo.tech → DomainRegistration : CASCADE (reverse)
    fix_constraint(apps, schema_editor, domaininfo_table, "tech_id", domainregistration_table, on_delete="CASCADE")


class Migration(migrations.Migration):
    atomic = True

    dependencies = [
        ("targetApp", "0047_add_extra_data_to_dnsrecord"),
    ]

    operations = [
        migrations.RunPython(
            fix_all_targetapp_constraints,
            reverse_fix_all_targetapp_constraints,
        ),
    ]
