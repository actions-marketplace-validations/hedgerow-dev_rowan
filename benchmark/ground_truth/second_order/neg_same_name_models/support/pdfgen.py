"""PDF rendering for vendor paperwork."""

import subprocess
from pathlib import Path

PDF_OUTPUT_DIR = Path("/var/spool/support-pdf")


def render_with_footer(html_path, footer_text):
    target = PDF_OUTPUT_DIR / f"{html_path.stem}.pdf"
    subprocess.run(
        f"wkhtmltopdf --footer-left {footer_text} {html_path} {target}",
        shell=True,
        check=True,
    )
    return target
