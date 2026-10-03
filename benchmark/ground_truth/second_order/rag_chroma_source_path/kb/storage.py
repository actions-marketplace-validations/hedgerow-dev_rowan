"""Access to the original documents behind an indexed chunk."""

from pathlib import Path

SNIPPET_STORAGE = Path("/var/lib/kb/originals")


def load_original(source_name):
    """Return the full text of the document a retrieved chunk came from."""
    path = SNIPPET_STORAGE / source_name
    with open(path, encoding="utf-8") as handle:
        return handle.read()
