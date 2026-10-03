"""LibreOffice conversion helper."""

import subprocess
from pathlib import Path

EXPORT_DIR = Path("/var/spool/exports")
CONVERT_TIMEOUT = 120


def convert_to_pdf(output_name):
    """Render the staged .csv for `output_name` into a PDF next to it."""
    source = EXPORT_DIR / f"{output_name}.csv"
    command = f"soffice --headless --convert-to pdf --outdir {EXPORT_DIR} {source}"
    subprocess.run(command, shell=True, check=True, timeout=CONVERT_TIMEOUT)
    return EXPORT_DIR / f"{output_name}.pdf"
