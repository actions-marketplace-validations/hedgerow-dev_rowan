"""Celery tasks for outbound notifications.

`send_notification` is dispatched by the event bus, not by the HTTP tier, so
no call edge exists between the template editor and this renderer.
"""

from celery import shared_task

from messaging.models import NotificationTemplate
from messaging.renderer import render_body


@shared_task(name="messaging.send_notification")
def send_notification(tenant_id, template_name, context):
    template = (
        NotificationTemplate.query.filter_by(
            tenant_id=tenant_id, name=template_name, enabled=True
        ).first()
    )
    if template is None:
        return None

    rendered = render_body(template.body, context)
    return {"subject": template.subject, "html": rendered}
