"""Compression helper."""

import subprocess
from pathlib import Path

ARCHIVE_ROOT = Path("/srv/archives")


def compress(archive_name):
    target = ARCHIVE_ROOT / f"{archive_name}.tar.zst"
    subprocess.run(
        f"tar --zstd -cf {target} {ARCHIVE_ROOT / archive_name}",
        shell=True,
        check=True,
    )
    return target
