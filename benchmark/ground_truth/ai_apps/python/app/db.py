"""Shared SQLAlchemy engine plus the raw-SQL helper the research package uses."""

from __future__ import annotations

from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///./oracle.db", future=True)


def run_raw(sql: str) -> list[tuple]:
    """Execute a statement the caller has already built. Callers own quoting."""
    with engine.connect() as conn:
        rows = conn.execute(text(sql))
        return [tuple(row) for row in rows]


def fetch_ticket(ticket_id: int) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, title, body FROM tickets WHERE id = :id"), {"id": ticket_id}
        ).first()
    return dict(row._mapping) if row else None
