from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class NotificationTemplate(db.Model):
    __tablename__ = "notification_templates"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
