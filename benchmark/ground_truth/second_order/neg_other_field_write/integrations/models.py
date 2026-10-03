"""Managed partner integrations.

The delivery endpoint is fixed per partner and set from deployment
configuration; the customer can only rename their integration.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class PartnerHook(db.Model):
    __tablename__ = "partner_hooks"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False, index=True)
    display_label = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    secret = db.Column(db.String(64), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
