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


def fix_todonote_constraints(apps, schema_editor):
    """Fix on_delete constraints to CASCADE for strong parent-child relationships."""
    # Get actual table names from Django metadata
    todonote_table = get_table_name(apps, "recon_note", "TodoNote")
    scanhistory_table = get_table_name(apps, "startScan", "ScanHistory")
    subdomain_table = get_table_name(apps, "startScan", "Subdomain")

    # TodoNote - CASCADE for strong relationships (if parent deleted, child should be deleted)
    fix_constraint(apps, schema_editor, todonote_table, "scan_history_id", scanhistory_table, on_delete="CASCADE")
    fix_constraint(apps, schema_editor, todonote_table, "subdomain_id", subdomain_table, on_delete="CASCADE")


def reverse_fix_todonote_constraints(apps, schema_editor):
    """Reverse: Change on_delete constraints back to SET NULL."""
    # Get actual table names from Django metadata
    todonote_table = get_table_name(apps, "recon_note", "TodoNote")
    scanhistory_table = get_table_name(apps, "startScan", "ScanHistory")
    subdomain_table = get_table_name(apps, "startScan", "Subdomain")

    # TodoNote
    fix_constraint(apps, schema_editor, todonote_table, "scan_history_id", scanhistory_table, on_delete="SET NULL")
    fix_constraint(apps, schema_editor, todonote_table, "subdomain_id", subdomain_table, on_delete="SET NULL")


class Migration(migrations.Migration):
    atomic = True

    dependencies = [
        ("recon_note", "0002_todonote_project"),
    ]

    operations = [
        migrations.RunPython(
            fix_todonote_constraints,
            reverse_fix_todonote_constraints,
        ),
    ]
