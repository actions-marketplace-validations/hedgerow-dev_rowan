"""Raw ticket queries used by the research tools."""

from __future__ import annotations

import sqlite3

db = sqlite3.connect("oracle.db", check_same_thread=False)


def search_impl(term: str) -> list[dict]:
    """Search tickets by a free-text term and return id, title pairs."""
    cursor = db.cursor()
    cursor.execute(f"SELECT id, title FROM tickets WHERE title LIKE '%{term}%' ORDER BY id DESC")
    return [{"id": row[0], "title": row[1]} for row in cursor.fetchall()]


def count_open() -> int:
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE status = 'open'")
    return int(cursor.fetchone()[0])
