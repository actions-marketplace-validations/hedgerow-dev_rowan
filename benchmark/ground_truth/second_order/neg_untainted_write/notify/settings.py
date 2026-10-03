import os

INTERNAL_CALLBACK_URL = os.environ.get(
    "INTERNAL_CALLBACK_URL", "https://events.internal.acme/ingest"
)
SYSTEM_OWNER_ID = 0
