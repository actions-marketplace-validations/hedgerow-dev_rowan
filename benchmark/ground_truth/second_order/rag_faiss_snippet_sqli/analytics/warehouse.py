"""Read-only warehouse access."""

import psycopg2

DSN = "postgresql://reader@warehouse/analytics"
ROW_LIMIT = 100


def run_subquery(sql):
    """Run a saved snippet, capped to a preview-sized result set."""
    with psycopg2.connect(DSN) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM ({sql}) AS preview LIMIT {ROW_LIMIT}")
            return cursor.fetchall()
