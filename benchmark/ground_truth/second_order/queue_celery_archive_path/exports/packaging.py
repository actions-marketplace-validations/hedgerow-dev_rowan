"""Tar packaging for export archives."""

import shutil
import tarfile
from pathlib import Path

ARCHIVE_ROOT = Path("/srv/exports")


def package_directory(prefix):
    staged = ARCHIVE_ROOT / prefix
    target = ARCHIVE_ROOT / f"{prefix}.tar.gz"

    with tarfile.open(target, "w:gz") as archive:
        archive.add(staged, arcname=prefix)

    shutil.rmtree(staged)
    return target
