"""Outbound webhook registrations."""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Webhook(db.Model):
    __tablename__ = "webhooks"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False, index=True)
    target_url = db.Column(db.String(2048), nullable=False)
    secret = db.Column(db.String(64), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    failure_count = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<Webhook {self.id} owner={self.owner_id}>"
